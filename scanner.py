"""Multi-platform scan orchestrator with scoring engine."""

from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

import aiosqlite

import config
import db
from models import (
    RepoCandidate, ReleaseAsset, ScoredFinding, ScanRecord, ScanProgress,
)
from platforms import PLATFORM_MAP
from platforms.base import PlatformScanner


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
        yield ScanProgress(platform=platform, status="error", message=f"Search failed: {e}")
        return

    # Filter high-star repos (keep known IOCs)
    filtered = []
    for c in candidates:
        if c.stars >= star_threshold:
            if c.repo_name not in config.KNOWN_MALICIOUS_REPOS and c.owner_login not in config.KNOWN_MALICIOUS_ACCOUNTS:
                continue
        filtered.append(c)

    yield ScanProgress(
        platform=platform, status="inspecting",
        found=len(filtered), message=f"Found {len(filtered)} candidates, inspecting..."
    )

    # Deep inspection: check releases first, then full inspection on those with releases
    results: list[ScoredFinding] = []

    for candidate in filtered:
        try:
            releases = await scanner.get_releases(candidate.repo_id)
        except Exception:
            releases = []

        # Only deep inspect repos with releases OR known IOCs
        has_releases = len(releases) > 0
        is_known_repo = candidate.repo_name in config.KNOWN_MALICIOUS_REPOS
        is_known_account = candidate.owner_login in config.KNOWN_MALICIOUS_ACCOUNTS

        if not has_releases and not is_known_repo and not is_known_account:
            continue

        # Deep inspect
        try:
            readme = await scanner.get_readme(candidate.repo_id)
        except Exception:
            readme = ""

        # Relevance gate: for known accounts, skip repos not about Claude
        if is_known_account and not is_known_repo:
            if not is_claude_relevant(candidate, readme):
                continue

        try:
            files = await scanner.get_file_tree(candidate.repo_id)
        except Exception:
            files = []

        owner_age_days = None
        owner_pub_repos = None
        if candidate.owner_login:
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
        # Scan all platforms in parallel
        async def scan_one(scanner: PlatformScanner):
            async for progress in scan_platform(scanner, days_back, star_threshold):
                if progress_callback:
                    await progress_callback(progress)

        await asyncio.gather(*(scan_one(s) for s in scanners), return_exceptions=True)

        # Collect and persist results
        for scanner in scanners:
            results = getattr(scanner, "_results", [])
            for finding in results:
                is_new = await db.upsert_finding(database, finding)
                total_found += 1
                if is_new:
                    new_found += 1

        await database.commit()

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
        # Close scanner HTTP clients
        for scanner in scanners:
            await scanner.close()
        await database.close()

    return total_found, new_found
