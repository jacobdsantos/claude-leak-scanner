"""Multi-platform scan orchestrator with scoring engine."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

import config
import db
from models import (
    RepoCandidate, ReleaseAsset, ScoredFinding, ScanRecord, ScanProgress,
)
from platforms import PLATFORM_MAP
from platforms.base import PlatformScanner

logger = logging.getLogger("lure-monitor.scanner")


# ── Scoring engine (ported from claude_lure_scanner.py) ──────────────────────

CLAUDE_RELEVANCE_PATTERNS = [
    r"claude",
    r"anthropic",
    r"source\s*map",
    r"leaked?\s*(source|code)",
    r"crack(ed|ing)?.*code",
    r"claudecode",
    r"claw.?code",  # common misspelling/obfuscation
]


def is_claude_relevant(candidate: RepoCandidate, readme: str) -> bool:
    """Check if repo is actually related to Claude Code leaks."""
    # Always relevant if it's a known malicious repo
    if candidate.repo_name in config.KNOWN_MALICIOUS_REPOS:
        return True

    # Check repo name, description, and README for Claude relevance
    text = " ".join([
        candidate.repo_name.lower(),
        candidate.description.lower(),
        readme.lower()[:2000],
    ])

    for pattern in CLAUDE_RELEVANCE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def score_repo(
    candidate: RepoCandidate,
    readme: str,
    files: list[str],
    release_assets: list[ReleaseAsset],
    owner_age_days: Optional[int],
    owner_pub_repos: Optional[int],
) -> tuple[int, list[str]]:
    """Score a repo's suspicion level. Returns (score, reasons)."""
    score = 0
    reasons: list[str] = []

    # ── Known malicious match ──
    if candidate.repo_name in config.KNOWN_MALICIOUS_REPOS:
        score += 50
        reasons.append("KNOWN MALICIOUS REPO (Zscaler IOC)")

    # Known account boost — only if repo is Claude-relevant
    if candidate.owner_login in config.KNOWN_MALICIOUS_ACCOUNTS:
        if is_claude_relevant(candidate, readme):
            score += 40
            reasons.append(f"KNOWN MALICIOUS ACCOUNT: {candidate.owner_login}")
        else:
            score += 10
            reasons.append(f"Known threat actor account (unrelated repo): {candidate.owner_login}")

    # ── Account age ──
    if owner_age_days is not None:
        if owner_age_days < 30:
            score += 30
            reasons.append(f"New account ({owner_age_days}d old)")
        elif owner_age_days < 90:
            score += 15
            reasons.append(f"Young account ({owner_age_days}d old)")

    if owner_pub_repos is not None and owner_pub_repos <= 3:
        score += 10
        reasons.append(f"Low repo count ({owner_pub_repos})")

    # ── Stars ──
    if candidate.stars == 0:
        score += 5
        reasons.append("Zero stars")

    # ── README + description lure patterns ──
    readme_lower = readme.lower()
    combined_text = readme_lower + " " + candidate.description.lower()

    for pattern, weight, label in config.LURE_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            score += weight
            reasons.append(f"Lure keyword: {label}")

    # ── README suspicious elements ──
    if re.search(r"!\[.*\]\(.*download.*\)", readme, re.IGNORECASE):
        score += 15
        reasons.append("Download button image in README")
    if re.search(r"(mega\.nz|mediafire|gofile|anonfiles|catbox\.moe)", readme, re.IGNORECASE):
        score += 25
        reasons.append("External file host link in README")
    if re.search(r"(telegram\.me|t\.me)/", readme, re.IGNORECASE):
        score += 15
        reasons.append("Telegram link in README")
    if re.search(r"steamcommunity\.com/profiles/", readme, re.IGNORECASE):
        score += 20
        reasons.append("Steam profile link (known DDR pattern)")

    # ── README download lure — exact phrases from known malicious README ──
    # These patterns are derived from the leaked-claude-code/leaked-claude-code
    # original README. They require specific combination of phrases to avoid FPs.
    has_claudecode_archive = bool(re.search(r"ClaudeCode_x64\.(7z|exe|zip|rar)", readme, re.IGNORECASE))
    has_precompiled = bool(re.search(r"pre-compiled\s+binar", readme, re.IGNORECASE))
    has_releases_download = bool(re.search(r"navigate\s+to\s+(the\s+)?releases.*page.*download", readme, re.IGNORECASE))
    has_extract_archive = bool(re.search(r"extract\s+(the\s+)?archive\s+to\s+a\s+permanent", readme, re.IGNORECASE))

    if has_claudecode_archive and has_precompiled:
        # HIGH confidence: exact lure combo from the original malicious README
        score += 40
        reasons.append("README matches malicious lure pattern: ClaudeCode_x64 archive + 'pre-compiled binaries'")
    elif has_claudecode_archive and has_releases_download:
        # HIGH confidence: archive name + specific Releases page download instruction
        score += 35
        reasons.append("README matches malicious lure pattern: ClaudeCode_x64 archive + Releases page download")
    elif has_claudecode_archive:
        # LOW confidence: archive name alone — could be news, analysis, or star tracker.
        # Only +10 so it needs other signals (zero stars, new account, etc.) to surface.
        score += 10
        reasons.append("README references ClaudeCode_x64 archive (no lure combo — may be analysis)")
    if has_extract_archive and has_claudecode_archive:
        score += 10
        reasons.append("README has 'extract archive to permanent location' instruction")

    for domain in config.KNOWN_C2_DOMAINS:
        if domain in readme_lower:
            score += 40
            reasons.append(f"KNOWN C2 DOMAIN: {domain}")
    for ip in config.KNOWN_C2_IPS:
        if ip in readme:
            score += 40
            reasons.append(f"KNOWN C2 IP: {ip}")

    # ── Suspicious files in tree ──
    for f in files:
        fname = f.lower().split("/")[-1]
        ext = os.path.splitext(fname)[1]
        if ext in config.SUSPICIOUS_FILE_EXTENSIONS:
            score += 25
            reasons.append(f"Suspicious file: {f}")
        if fname in config.SUSPICIOUS_FILE_NAMES:
            score += 35
            reasons.append(f"KNOWN MALICIOUS FILENAME: {f}")
        if ext in {".7z", ".zip", ".rar"} and "claude" in fname:
            score += 15
            reasons.append(f"Claude-named archive: {f}")

    # ── Release assets ──
    for asset in release_assets:
        aname = asset.name.lower()
        ext = os.path.splitext(aname)[1]
        if ext in {".exe", ".msi", ".scr"}:
            score += 30
            reasons.append(f"Release contains executable: {asset.name} ({asset.size_mb} MB)")
        elif ext in {".zip", ".7z", ".rar"}:
            score += 20
            reasons.append(f"Release contains archive: {asset.name} ({asset.size_mb} MB)")
            if "claude" in aname:
                score += 15
                reasons.append(f"Release archive named after Claude: {asset.name}")
        if asset.size_mb > 50:
            score += 10
            reasons.append(f"Large release asset: {asset.name} ({asset.size_mb} MB)")
        if asset.download_count > 0:
            reasons.append(f"Downloaded {asset.download_count}x: {asset.name}")

    # ── Repo name patterns ──
    name_lower = candidate.repo_name.lower()
    if "leaked" in name_lower and "claude" in name_lower:
        score += 20
        reasons.append("Repo name contains 'leaked' + 'claude'")
    if "crack" in name_lower and "claude" in name_lower:
        score += 20
        reasons.append("Repo name contains 'crack' + 'claude'")

    # ── TradeAI rotating campaign ─────────────────────────────────────────────
    if "tradeai" in name_lower or "tradeai" in candidate.description.lower():
        score += 50
        reasons.append("KNOWN DROPPER CAMPAIGN: TradeAI nofilabs (25+ brand rotating lure, Vidar+GhostSocks)")

    if "openclaw" in name_lower:
        score += 30
        reasons.append("Known precursor campaign: OpenClaw (Feb 2026, same threat actor, same payload)")

    # ── High-star suspicious patterns (fake/bought star signals) ─────────────
    # High stars on a lure repo = social proof attack — score these higher, not lower.
    if candidate.stars >= 100:
        if owner_age_days is not None and owner_age_days < 90:
            score += 20
            reasons.append(
                f"Suspicious star velocity: {candidate.stars} stars on {owner_age_days}d-old account (likely bought)"
            )
        elif owner_pub_repos is not None and owner_pub_repos <= 2:
            score += 15
            reasons.append(
                f"Concentrated credibility: {candidate.stars} stars with only {owner_pub_repos} public repo(s)"
            )

    return min(score, 100), reasons


# ── Scan orchestrator ────────────────────────────────────────────────────────

async def scan_platform(
    scanner: PlatformScanner,
    days_back: int,
    star_threshold: int,
) -> AsyncGenerator[ScanProgress, None]:
    """Scan a single platform. Yields progress updates."""
    platform = scanner.name

    yield ScanProgress(platform=platform, status="searching", message="Searching repositories...")

    try:
        candidates = await scanner.search(config.SEARCH_QUERIES, days_back)
    except Exception as e:
        logger.error(f"[{platform}] Search failed: {e}", exc_info=True)
        yield ScanProgress(platform=platform, status="error", message=f"Search failed: {e}")
        return

    logger.info(f"[{platform}] Search returned {len(candidates)} raw candidates")

    # High-star lures are MORE dangerous — more victims will trust and download them.
    # Include them if they have any Claude/campaign relevance. Fake-star patterns
    # are caught by score_repo() bonuses instead of a hard filter here.
    _LURE_KWS = {"claude", "anthropic", "claw", "tradeai", "openclaw", "claudecode"}
    filtered = []
    for c in candidates:
        if c.stars < star_threshold:
            filtered.append(c)
            continue
        # Always include known malicious regardless of stars
        if c.repo_name in config.KNOWN_MALICIOUS_REPOS or c.owner_login in config.KNOWN_MALICIOUS_ACCOUNTS:
            filtered.append(c)
            continue
        # Include high-star repos only if name/description has lure relevance
        combined = (c.repo_name + " " + c.description).lower()
        if any(kw in combined for kw in _LURE_KWS):
            filtered.append(c)

    logger.info(f"[{platform}] After star filter: {len(filtered)} candidates (threshold: {star_threshold})")

    yield ScanProgress(
        platform=platform, status="inspecting",
        found=len(filtered), message=f"Found {len(filtered)} candidates, inspecting..."
    )

    # ── Two-pass inspection: quick score first, deep inspect high-value only ──
    results: list[ScoredFinding] = []

    for i, candidate in enumerate(filtered):
        # Progress heartbeat every 10 repos
        if i > 0 and i % 10 == 0:
            yield ScanProgress(
                platform=platform, status="inspecting",
                found=len(results),
                message=f"Inspecting {i}/{len(filtered)}... ({len(results)} findings so far)"
            )

        # ── Pass 1: Quick score from metadata only (no API calls) ──
        quick_score = 0
        name_lower = candidate.repo_name.lower()
        desc_lower = candidate.description.lower()

        if candidate.repo_name in config.KNOWN_MALICIOUS_REPOS:
            quick_score += 50
        if candidate.owner_login in config.KNOWN_MALICIOUS_ACCOUNTS:
            quick_score += 20
        if "leaked" in name_lower and "claude" in name_lower:
            quick_score += 20
        if "crack" in name_lower and "claude" in name_lower:
            quick_score += 20
        if candidate.stars == 0:
            quick_score += 5
        if "tradeai" in name_lower or "tradeai" in desc_lower:
            quick_score += 30  # Known dropper campaign label
        if "openclaw" in name_lower or "openclaw" in desc_lower:
            quick_score += 25  # Known precursor campaign, same TA
        if ("unlock" in name_lower or "keygen" in name_lower or "activat" in name_lower) and \
                ("claude" in name_lower or "anthropic" in name_lower):
            quick_score += 15
        if any(kw in desc_lower for kw in ["leaked", "source code", "source map", "anthropic"]):
            quick_score += 10
        if any(kw in name_lower for kw in ["leaked", "leak", "source", "claude", "anthropic", "claw"]):
            quick_score += 5

        # ── Pass 2: Deep inspect only high-value candidates ──
        readme = ""
        releases: list[ReleaseAsset] = []
        files: list[str] = []
        owner_age_days = None
        owner_pub_repos = None

        # Deep inspect if quick score suggests anything interesting
        if quick_score >= 5:
            try:
                readme = await scanner.get_readme(candidate.repo_id)
            except Exception:
                pass

            # Only check releases + files for higher-scoring repos (saves API calls)
            if quick_score >= 15 or candidate.repo_name in config.KNOWN_MALICIOUS_REPOS:
                try:
                    releases = await scanner.get_releases(candidate.repo_id)
                except Exception:
                    pass

                try:
                    files = await scanner.get_file_tree(candidate.repo_id)
                except Exception:
                    pass

            # Only check owner for new/suspicious repos
            if quick_score >= 10 and candidate.owner_login:
                try:
                    owner_info = await scanner.get_owner_info(candidate.owner_login)
                    owner_age_days = owner_info.age_days
                    owner_pub_repos = owner_info.public_repos
                except Exception:
                    pass

        score, reasons = score_repo(
            candidate, readme, files, releases,
            owner_age_days, owner_pub_repos,
        )

        if score < config.MIN_SCORE:
            continue

        suspicious_files = []
        for f in files:
            fname = f.lower().split("/")[-1]
            ext = os.path.splitext(fname)[1]
            if ext in config.SUSPICIOUS_FILE_EXTENSIONS or fname in config.SUSPICIOUS_FILE_NAMES:
                suspicious_files.append(f)

        results.append(ScoredFinding(
            id=candidate.finding_id,
            platform=platform,
            repo_name=candidate.repo_name,
            repo_url=candidate.repo_url,
            description=candidate.description,
            owner_login=candidate.owner_login,
            owner_age_days=owner_age_days,
            owner_pub_repos=owner_pub_repos,
            stars=candidate.stars,
            forks=candidate.forks,
            score=score,
            severity=config.severity_for_score(score),
            reasons=reasons,
            release_assets=releases,
            suspicious_files=suspicious_files,
            repo_created_at=candidate.repo_created_at,
        ))

    yield ScanProgress(
        platform=platform, status="done",
        found=len(results),
        message=f"Done: {len(results)} findings",
    )

    # Store results attribute for collection
    scanner._results = results  # type: ignore[attr-defined]


async def run_scan(
    platforms: Optional[list[str]] = None,
    days_back: int = config.DAYS_BACK,
    star_threshold: int = config.STAR_THRESHOLD,
    progress_callback=None,
) -> tuple[int, int]:
    """Run a full multi-platform scan. Returns (total_found, new_found)."""
    if platforms is None:
        platforms = config.ENABLED_PLATFORMS

    database = await db.get_db()

    # Create scan record
    scan = ScanRecord(
        started_at=datetime.now(timezone.utc),
        platforms=platforms,
        status="running",
    )
    scan_id = await db.insert_scan(database, scan)

    # Initialize scanners
    scanners: list[PlatformScanner] = []
    for p in platforms:
        cls = PLATFORM_MAP.get(p)
        if cls:
            scanners.append(cls())

    total_found = 0
    new_found = 0

    try:
        # Scan platforms SEQUENTIALLY — save to DB after each one
        for scanner in scanners:
            logger.info(f"=== Starting platform: {scanner.name} ===")
            platform_start = datetime.now(timezone.utc)
            try:
                async for progress in scan_platform(scanner, days_back, star_threshold):
                    if progress_callback:
                        await progress_callback(progress)

                # Persist this platform's results immediately
                results = getattr(scanner, "_results", [])
                for finding in results:
                    is_new = await db.upsert_finding(database, finding)
                    total_found += 1
                    if is_new:
                        new_found += 1

                elapsed = (datetime.now(timezone.utc) - platform_start).total_seconds()
                logger.info(f"=== {scanner.name} done: {len(results)} findings in {elapsed:.1f}s ===")

            except Exception as e:
                logger.error(f"=== {scanner.name} FAILED: {e} ===", exc_info=True)
                # Log error but continue to next platform
                if progress_callback:
                    await progress_callback(ScanProgress(
                        platform=scanner.name, status="error",
                        message=f"Platform failed: {e}",
                    ))

            finally:
                # Close this scanner's HTTP client before moving on
                if hasattr(scanner, "close"):
                    await scanner.close()

        # Update scan record
        completed_at = datetime.now(timezone.utc)
        duration = (completed_at - scan.started_at).total_seconds()
        await db.update_scan(
            database, scan_id,
            completed_at=completed_at,
            total_found=total_found,
            new_found=new_found,
            duration_seconds=round(duration, 1),
            status="completed",
        )

    except Exception as e:
        await db.update_scan(database, scan_id, status=f"failed: {e}")
        raise
    finally:
        # Close any scanners not already closed
        for scanner in scanners:
            try:
                await scanner.close()
            except Exception:
                pass
    return total_found, new_found


# ── VT Livehunt scan (separate entrypoint) ────────────────────────────────────

async def run_vt_scan(
    days_back: int = config.DAYS_BACK,
) -> tuple[int, int]:
    """Run a VirusTotal livehunt scan. Returns (total_found, new_found).

    Called from run_vt_hunt.py via a dedicated GitHub Actions workflow.
    Writes findings to the same Supabase table as run_scan(), using
    platform='vt_livehunt'.
    """
    from platforms.virustotal import VirusTotalScanner

    database = await db.get_db()
    scan = ScanRecord(
        started_at=datetime.now(timezone.utc),
        platforms=["vt_livehunt"],
        status="running",
    )
    scan_id = await db.insert_scan(database, scan)

    vt = VirusTotalScanner()
    total_found = new_found = 0

    try:
        logger.info("=== Starting VT Livehunt scan ===")
        await vt.search([], days_back)  # populates vt._scored_findings

        for finding in vt._scored_findings:
            is_new = await db.upsert_finding(database, finding)
            total_found += 1
            if is_new:
                new_found += 1
            logger.info(
                f"[vt_livehunt] {'NEW' if is_new else 'UPD'} "
                f"{finding.repo_name} | score={finding.score} | {finding.severity}"
            )

        completed_at = datetime.now(timezone.utc)
        duration = (completed_at - scan.started_at).total_seconds()
        await db.update_scan(
            database, scan_id,
            completed_at=completed_at,
            total_found=total_found,
            new_found=new_found,
            duration_seconds=round(duration, 1),
            platforms=["vt_livehunt"],
            status="completed",
        )
        logger.info(f"=== VT scan done: {total_found} findings ({new_found} new) in {duration:.1f}s ===")

    except Exception as e:
        logger.error(f"=== VT scan FAILED: {e} ===", exc_info=True)
        await db.update_scan(database, scan_id, status=f"failed: {e}")
        raise
    finally:
        await vt.close()

    return total_found, new_found
