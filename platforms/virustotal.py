"""VirusTotal Livehunt platform — polls hunting notifications for lure files."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

import config
from models import RepoCandidate, ReleaseAsset, OwnerInfo, ScoredFinding
from .base import PlatformScanner

logger = logging.getLogger("lure-monitor.virustotal")

_VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalScanner(PlatformScanner):
    """Polls VT Intelligence hunting_notifications and enriches each file hit."""

    name = "vt_livehunt"
    base_url = _VT_BASE

    def __init__(self) -> None:
        super().__init__()
        self._api_key: str = config.VT_API_KEY
        # Pre-scored findings built during search() — consumed by run_vt_scan()
        self._scored_findings: list[ScoredFinding] = []

    async def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={
                    "x-apikey": self._api_key,
                    "Accept": "application/json",
                },
            )
        return self._client

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score_file(
        self,
        attrs: dict,
        sha256: str,
        filename: str,
        rule_name: str,
    ) -> tuple[int, list[str]]:
        """Score a VT file hit. Returns (score, reasons)."""
        score = 0
        reasons: list[str] = [f"Matched VT hunt rule: {rule_name}"]

        # ── AV detection counts ───────────────────────────────────────────────
        stats     = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious_av = stats.get("suspicious", 0)
        total     = max(sum(stats.values()), 1)

        if malicious >= 30:
            score += 60
            reasons.append(f"High detections: {malicious}/{total} engines flagged malicious")
        elif malicious >= 10:
            score += 40
            reasons.append(f"Detected: {malicious}/{total} engines flagged malicious")
        elif malicious >= 3:
            score += 25
            reasons.append(f"Low detection: {malicious}/{total} engines")
        elif malicious > 0:
            score += 15
            reasons.append(f"Rare detection: {malicious}/{total} engines")

        if suspicious_av >= 5:
            score += 10
            reasons.append(f"{suspicious_av} engines flagged suspicious")

        # ── File type ─────────────────────────────────────────────────────────
        file_type = (attrs.get("type_description") or attrs.get("magic") or "").lower()
        if any(t in file_type for t in ["pe32", "executable", "pe+"]):
            score += 20
            reasons.append(f"Executable file type: {attrs.get('type_description', file_type)}")
        elif any(t in file_type for t in ["7-zip", "zip archive", "rar"]):
            score += 10
            reasons.append(f"Archive type: {attrs.get('type_description', file_type)}")

        # ── Filename signals ──────────────────────────────────────────────────
        fname_lower = filename.lower()
        if "tradeai" in fname_lower:
            score += 50
            reasons.append(f"KNOWN DROPPER FILENAME: {filename} (TradeAI rotating campaign)")
        if fname_lower in {"claudecode_x64.exe", "claudecode.exe", "claude_code.exe",
                           "openclaudecode.exe", "tradeai.exe"}:
            score += 35
            reasons.append(f"KNOWN MALICIOUS FILENAME: {filename}")
        elif "claudecode" in fname_lower or "claude_code" in fname_lower:
            score += 25
            reasons.append(f"Claude Code lure filename: {filename}")

        # ── Known hashes ──────────────────────────────────────────────────────
        md5 = attrs.get("md5", "")
        if md5 and md5 in config.KNOWN_MD5S:
            score += 60
            reasons.append(f"KNOWN MALICIOUS HASH — MD5: {md5}")

        # ── Size signal ───────────────────────────────────────────────────────
        size_bytes = attrs.get("size", 0) or 0
        size_mb    = round(size_bytes / (1024 * 1024), 1)
        if size_mb > 50:
            score += 10
            reasons.append(f"Large file: {size_mb} MB (typical for lure archives)")

        return min(score, 100), reasons

    # ── Main search: polls notifications + enriches files ────────────────────

    async def search(self, queries: list[str], days_back: int) -> list[RepoCandidate]:
        """Poll VT hunting notifications. queries/days_back drive the date window;
        actual hunt rule matching is configured on the VT dashboard side.

        Populates self._scored_findings — caller (run_vt_scan) processes these.
        Returns empty list (VT findings bypass the repo scoring pipeline).
        """
        self._scored_findings = []

        if not self._api_key:
            logger.warning("[vt_livehunt] VT_API_KEY not set — skipping")
            return []

        http        = await self.client()
        since_ts    = int((datetime.now(timezone.utc) - timedelta(days=days_back)).timestamp())
        ruleset     = config.VT_HUNT_RULESET_NAME
        seen_sha256 : set[str] = set()
        cursor      : Optional[str] = None
        page        = 0
        max_pages   = 20        # safety cap: 20 × 40 = 800 notifications max

        logger.info(f"[vt_livehunt] Polling notifications (ruleset={ruleset or 'ALL'}, days_back={days_back})")

        while page < max_pages:
            params: dict = {"limit": 40}
            if cursor:
                params["cursor"] = cursor
            if ruleset:
                params["filter"] = f"ruleset_name:{ruleset}"

            try:
                resp = await http.get(f"{_VT_BASE}/intelligence/hunting_notifications", params=params)
            except Exception as e:
                logger.error(f"[vt_livehunt] Network error fetching notifications: {e}")
                break

            if resp.status_code == 401:
                logger.error("[vt_livehunt] 401 Unauthorized — check VT_API_KEY")
                break
            if resp.status_code == 403:
                logger.error(
                    "[vt_livehunt] 403 Forbidden — Livehunt requires a VT Intelligence subscription"
                )
                break
            if resp.status_code == 429:
                logger.warning("[vt_livehunt] Rate limited (429) — stopping pagination")
                break
            if not resp.is_success:
                logger.error(f"[vt_livehunt] Unexpected status {resp.status_code}")
                break

            data          = resp.json()
            notifications = data.get("data", [])

            if not notifications:
                logger.info("[vt_livehunt] No more notifications")
                break

            stop_paginating = False
            for notif in notifications:
                attrs        = notif.get("attributes", {})
                notif_date   = attrs.get("date", 0)
                rule_name    = attrs.get("rule_name") or attrs.get("ruleset_name") or "unknown_rule"
                sha256       = attrs.get("sha256", "")

                # Stop when we've gone past the lookback window
                if notif_date and notif_date < since_ts:
                    stop_paginating = True
                    break

                if not sha256 or sha256 in seen_sha256:
                    continue
                seen_sha256.add(sha256)

                # Enrich: fetch full file details from VT
                try:
                    file_resp = await http.get(f"{_VT_BASE}/files/{sha256}")
                    if file_resp.status_code == 404:
                        continue
                    if not file_resp.is_success:
                        logger.warning(f"[vt_livehunt] File fetch {sha256[:12]}… → {file_resp.status_code}")
                        continue
                    file_attrs = file_resp.json().get("data", {}).get("attributes", {})
                except Exception as e:
                    logger.warning(f"[vt_livehunt] File fetch failed for {sha256[:12]}…: {e}")
                    continue

                # Best available filename
                filename = (
                    file_attrs.get("meaningful_name")
                    or file_attrs.get("name")
                    or f"{sha256[:16]}…"
                )

                score, reasons = self._score_file(file_attrs, sha256, filename, rule_name)
                if score < config.MIN_SCORE:
                    continue

                # Metadata for display
                stats     = file_attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total     = max(sum(stats.values()), 1)
                size_mb   = round((file_attrs.get("size") or 0) / (1024 * 1024), 1)
                first_sub = file_attrs.get("first_submission_date")
                first_seen_dt = (
                    datetime.fromtimestamp(first_sub, tz=timezone.utc)
                    if first_sub else datetime.now(timezone.utc)
                )

                finding = ScoredFinding(
                    id=f"vt_livehunt:{sha256}",
                    platform="vt_livehunt",
                    repo_name=filename,
                    repo_url=f"https://www.virustotal.com/gui/file/{sha256}",
                    description=(
                        f"{file_attrs.get('type_description', 'Unknown type')} · "
                        f"{malicious}/{total} detections · {size_mb} MB"
                    ),
                    # Repurpose owner_login to store hunt rule name for display
                    owner_login=rule_name,
                    score=score,
                    severity=config.severity_for_score(score),
                    reasons=reasons,
                    # Store full SHA256 here — never truncated
                    suspicious_files=[sha256],
                    repo_created_at=first_seen_dt.isoformat(),
                )
                self._scored_findings.append(finding)
                logger.info(
                    f"[vt_livehunt] {filename} | score={score} | {malicious}/{total} dets"
                )

            if stop_paginating:
                break

            meta   = data.get("meta", {})
            cursor = meta.get("cursor")
            if not cursor:
                break
            page += 1

        logger.info(f"[vt_livehunt] Total findings: {len(self._scored_findings)}")
        return []   # VT findings bypass the repo scoring pipeline

    # ── Retrohunt ─────────────────────────────────────────────────────────────

    async def retrohunt(
        self,
        rule_source: str,
        days_back: int = 90,
        poll_interval_seconds: int = 30,
        max_wait_hours: int = 6,
    ) -> list[ScoredFinding]:
        """Submit a YARA retrohunt job, poll until complete, return scored findings.

        Args:
            rule_source:          Full YARA rule text to submit.
            days_back:            How many days back to search (1–90).
            poll_interval_seconds: How often to poll the job status.
            max_wait_hours:        Bail out after this many hours even if not done.

        Retrohunt jobs can take 1–6 hours depending on corpus size.
        This method blocks the event loop during polling via asyncio.sleep.
        Run it from a dedicated GH Actions job with a long timeout.
        """
        import asyncio

        findings: list[ScoredFinding] = []

        if not self._api_key:
            logger.warning("[vt_retrohunt] VT_API_KEY not set — skipping")
            return findings

        http = await self.client()

        # ── Submit job ────────────────────────────────────────────────────────
        end_dt   = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=min(days_back, 90))
        payload  = {
            "data": {
                "type": "retrohunt_job",
                "attributes": {
                    "rules":    rule_source,
                    "corpus":   "goodware+malware",   # full VT corpus
                    "time_range": {
                        "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "end":   end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                },
            }
        }

        try:
            submit = await http.post(
                f"{_VT_BASE}/intelligence/retrohunt_jobs",
                json=payload,
            )
        except Exception as e:
            logger.error(f"[vt_retrohunt] Failed to submit job: {e}")
            return findings

        if submit.status_code == 401:
            logger.error("[vt_retrohunt] 401 Unauthorized — check VT_API_KEY")
            return findings
        if submit.status_code == 403:
            logger.error("[vt_retrohunt] 403 Forbidden — Retrohunt requires VT Intelligence")
            return findings
        if not submit.is_success:
            logger.error(f"[vt_retrohunt] Submit failed {submit.status_code}: {submit.text[:200]}")
            return findings

        job_id = submit.json().get("data", {}).get("id", "")
        if not job_id:
            logger.error("[vt_retrohunt] No job ID returned from submit")
            return findings

        logger.info(
            f"[vt_retrohunt] Job {job_id} submitted — searching {days_back} days back"
            f" ({start_dt.strftime('%Y-%m-%d')} → {end_dt.strftime('%Y-%m-%d')})"
        )

        # ── Poll until complete ───────────────────────────────────────────────
        max_polls = int(max_wait_hours * 3600 / poll_interval_seconds)
        for poll in range(max_polls):
            await asyncio.sleep(poll_interval_seconds)
            try:
                status_resp = await http.get(
                    f"{_VT_BASE}/intelligence/retrohunt_jobs/{job_id}"
                )
                if not status_resp.is_success:
                    logger.warning(f"[vt_retrohunt] Poll {poll+1}: status {status_resp.status_code}")
                    continue
                job_attrs = status_resp.json().get("data", {}).get("attributes", {})
            except Exception as e:
                logger.warning(f"[vt_retrohunt] Poll {poll+1} failed: {e}")
                continue

            status   = job_attrs.get("status", "unknown")
            progress = job_attrs.get("progress", 0)

            # Log every 5 polls or on status change
            if poll % 5 == 0 or status != getattr(self, "_last_rh_status", None):
                logger.info(
                    f"[vt_retrohunt] Job {job_id}: {status} ({progress:.0f}%) "
                    f"— poll {poll+1}/{max_polls}"
                )
            self._last_rh_status = status  # type: ignore[attr-defined]

            if status == "completed":
                num_matches = job_attrs.get("num_matches", "?")
                logger.info(f"[vt_retrohunt] Job {job_id} COMPLETE — {num_matches} matches")
                break
            if status in ("aborted", "aborting", "failed"):
                logger.error(f"[vt_retrohunt] Job {job_id} ended with status: {status}")
                return findings
        else:
            logger.error(f"[vt_retrohunt] Job {job_id} timed out after {max_wait_hours}h")
            return findings

        # ── Fetch matching files (paginated) ──────────────────────────────────
        cursor: Optional[str] = None
        page      = 0
        max_pages = 50   # cap at 50 × 40 = 2000 matches
        seen_sha256: set[str] = set()

        while page < max_pages:
            params: dict = {"limit": 40}
            if cursor:
                params["cursor"] = cursor

            try:
                matches_resp = await http.get(
                    f"{_VT_BASE}/intelligence/retrohunt_jobs/{job_id}/matching_files",
                    params=params,
                )
                if not matches_resp.is_success:
                    logger.error(f"[vt_retrohunt] Matches fetch {matches_resp.status_code}")
                    break
                matches_data = matches_resp.json()
            except Exception as e:
                logger.error(f"[vt_retrohunt] Matches fetch failed: {e}")
                break

            files = matches_data.get("data", [])
            if not files:
                break

            for file_obj in files:
                file_attrs = file_obj.get("attributes", {})
                sha256     = file_obj.get("id") or file_attrs.get("sha256", "")
                if not sha256 or sha256 in seen_sha256:
                    continue
                seen_sha256.add(sha256)

                filename = (
                    file_attrs.get("meaningful_name")
                    or file_attrs.get("name")
                    or f"{sha256[:16]}…"
                )

                score, reasons = self._score_file(
                    file_attrs, sha256, filename, rule_name="retrohunt"
                )
                if score < config.MIN_SCORE:
                    continue

                stats     = file_attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total     = max(sum(stats.values()), 1)
                size_mb   = round((file_attrs.get("size") or 0) / (1024 * 1024), 1)
                first_sub = file_attrs.get("first_submission_date")
                first_seen_dt = (
                    datetime.fromtimestamp(first_sub, tz=timezone.utc)
                    if first_sub else datetime.now(timezone.utc)
                )

                finding = ScoredFinding(
                    id=f"vt_retrohunt:{sha256}",
                    platform="vt_retrohunt",
                    repo_name=filename,
                    repo_url=f"https://www.virustotal.com/gui/file/{sha256}",
                    description=(
                        f"{file_attrs.get('type_description', 'Unknown type')} · "
                        f"{malicious}/{total} detections · {size_mb} MB"
                    ),
                    owner_login=f"retrohunt:{job_id[:8]}",
                    score=score,
                    severity=config.severity_for_score(score),
                    reasons=reasons,
                    suspicious_files=[sha256],   # full SHA256 — never truncated
                    repo_created_at=first_seen_dt.isoformat(),
                )
                findings.append(finding)
                logger.info(
                    f"[vt_retrohunt] {filename} | score={score} | "
                    f"{malicious}/{total} dets | {size_mb} MB"
                )

            meta   = matches_data.get("meta", {})
            cursor = meta.get("cursor")
            if not cursor:
                break
            page += 1

        logger.info(
            f"[vt_retrohunt] Ingested {len(findings)} findings from job {job_id}"
        )
        return findings

    # ── Stubs: not used for VT (all data fetched in search()) ────────────────

    async def get_readme(self, repo_id: str) -> str:
        return ""

    async def get_releases(self, repo_id: str) -> list[ReleaseAsset]:
        return []

    async def get_file_tree(self, repo_id: str) -> list[str]:
        return []
