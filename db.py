"""SQLite database layer for the lure monitor."""

from __future__ import annotations

import json
import aiosqlite
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from config import DB_PATH
from models import ScoredFinding, ScanRecord, DashboardStats, ReleaseAsset

_DB_FILE = Path(__file__).parent / DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    description TEXT,
    owner_login TEXT,
    owner_age_days INTEGER,
    owner_pub_repos INTEGER,
    stars INTEGER DEFAULT 0,
    forks INTEGER DEFAULT 0,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    reasons TEXT,
    release_assets TEXT,
    suspicious_files TEXT,
    repo_created_at TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_count INTEGER DEFAULT 1,
    dismissed INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    platforms TEXT,
    total_found INTEGER DEFAULT 0,
    new_found INTEGER DEFAULT 0,
    duration_seconds REAL,
    status TEXT DEFAULT 'running'
);

CREATE INDEX IF NOT EXISTS idx_findings_platform ON findings(platform);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_first_seen ON findings(first_seen);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
"""


async def get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(str(_DB_FILE))
    db.row_factory = aiosqlite.Row
    await db.executescript(SCHEMA)
    return db


async def upsert_finding(db: aiosqlite.Connection, f: ScoredFinding) -> bool:
    """Insert or update a finding. Returns True if this is a new finding."""
    now = datetime.now(timezone.utc).isoformat()
    row = await db.execute("SELECT id, scan_count FROM findings WHERE id = ?", (f.id,))
    existing = await row.fetchone()

    if existing:
        await db.execute(
            """UPDATE findings SET
                score=?, severity=?, reasons=?, release_assets=?, suspicious_files=?,
                stars=?, forks=?, description=?, owner_login=?, owner_age_days=?,
                owner_pub_repos=?, last_seen=?, scan_count=scan_count+1
            WHERE id=?""",
            (
                f.score, f.severity,
                json.dumps(f.reasons), json.dumps([a.model_dump() for a in f.release_assets]),
                json.dumps(f.suspicious_files),
                f.stars, f.forks, f.description, f.owner_login,
                f.owner_age_days, f.owner_pub_repos, now, f.id,
            ),
        )
        return False
    else:
        await db.execute(
            """INSERT INTO findings
                (id, platform, repo_name, repo_url, description, owner_login,
                 owner_age_days, owner_pub_repos, stars, forks, score, severity,
                 reasons, release_assets, suspicious_files, repo_created_at,
                 first_seen, last_seen, scan_count, dismissed)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0)""",
            (
                f.id, f.platform, f.repo_name, f.repo_url, f.description,
                f.owner_login, f.owner_age_days, f.owner_pub_repos,
                f.stars, f.forks, f.score, f.severity,
                json.dumps(f.reasons),
                json.dumps([a.model_dump() for a in f.release_assets]),
                json.dumps(f.suspicious_files),
                f.repo_created_at, now, now,
            ),
        )
        return True


async def get_findings(
    db: aiosqlite.Connection,
    platform: Optional[str] = None,
    severity: Optional[str] = None,
    new_only: bool = False,
    include_dismissed: bool = False,
) -> list[ScoredFinding]:
    query = "SELECT * FROM findings WHERE 1=1"
    params: list = []

    if not include_dismissed:
        query += " AND dismissed = 0"
    if platform:
        query += " AND platform = ?"
        params.append(platform)
    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY score DESC, last_seen DESC"

    rows = await db.execute(query, params)
    findings = []
    now = datetime.now(timezone.utc)
    for row in await rows.fetchall():
        r = dict(row)
        # "NEW" = first seen within the last 24 hours
        is_new = False
        if r["first_seen"]:
            try:
                first = datetime.fromisoformat(r["first_seen"])
                if first.tzinfo is None:
                    first = first.replace(tzinfo=timezone.utc)
                is_new = (now - first).total_seconds() < 86400
            except ValueError:
                pass
        if new_only and not is_new:
            continue
        findings.append(ScoredFinding(
            id=r["id"],
            platform=r["platform"],
            repo_name=r["repo_name"],
            repo_url=r["repo_url"],
            description=r["description"] or "",
            owner_login=r["owner_login"] or "",
            owner_age_days=r["owner_age_days"],
            owner_pub_repos=r["owner_pub_repos"],
            stars=r["stars"] or 0,
            forks=r["forks"] or 0,
            score=r["score"],
            severity=r["severity"],
            reasons=json.loads(r["reasons"]) if r["reasons"] else [],
            release_assets=[ReleaseAsset(**a) for a in json.loads(r["release_assets"])] if r["release_assets"] else [],
            suspicious_files=json.loads(r["suspicious_files"]) if r["suspicious_files"] else [],
            repo_created_at=r["repo_created_at"],
            first_seen=datetime.fromisoformat(r["first_seen"]) if r["first_seen"] else None,
            last_seen=datetime.fromisoformat(r["last_seen"]) if r["last_seen"] else None,
            scan_count=r["scan_count"],
            dismissed=bool(r["dismissed"]),
            is_new=is_new,
        ))
    return findings


async def dismiss_finding(db: aiosqlite.Connection, finding_id: str) -> None:
    await db.execute("UPDATE findings SET dismissed = 1 WHERE id = ?", (finding_id,))
    await db.commit()


async def insert_scan(db: aiosqlite.Connection, scan: ScanRecord) -> int:
    cursor = await db.execute(
        "INSERT INTO scans (started_at, platforms, status) VALUES (?, ?, ?)",
        (scan.started_at.isoformat(), json.dumps(scan.platforms), scan.status),
    )
    await db.commit()
    return cursor.lastrowid


async def update_scan(db: aiosqlite.Connection, scan_id: int, **kwargs) -> None:
    sets = []
    params = []
    for k, v in kwargs.items():
        sets.append(f"{k} = ?")
        if k == "platforms":
            params.append(json.dumps(v))
        elif k == "completed_at" and isinstance(v, datetime):
            params.append(v.isoformat())
        else:
            params.append(v)
    params.append(scan_id)
    await db.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()


async def get_scans(db: aiosqlite.Connection, limit: int = 20) -> list[ScanRecord]:
    rows = await db.execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
    )
    scans = []
    for row in await rows.fetchall():
        r = dict(row)
        scans.append(ScanRecord(
            id=r["id"],
            started_at=datetime.fromisoformat(r["started_at"]),
            completed_at=datetime.fromisoformat(r["completed_at"]) if r["completed_at"] else None,
            platforms=json.loads(r["platforms"]) if r["platforms"] else [],
            total_found=r["total_found"] or 0,
            new_found=r["new_found"] or 0,
            duration_seconds=r["duration_seconds"] or 0.0,
            status=r["status"] or "unknown",
        ))
    return scans


async def get_stats(db: aiosqlite.Connection) -> DashboardStats:
    # Counts by severity (excluding dismissed)
    cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    row = await db.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN first_seen >= ? THEN 1 ELSE 0 END) as new,
            SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
        FROM findings WHERE dismissed = 0
    """, (cutoff_24h,))
    r = dict(await row.fetchone())

    # Platforms with findings
    prow = await db.execute(
        "SELECT COUNT(DISTINCT platform) as cnt FROM findings WHERE dismissed = 0"
    )
    pr = dict(await prow.fetchone())

    # Last scan
    srow = await db.execute(
        "SELECT started_at FROM scans ORDER BY started_at DESC LIMIT 1"
    )
    sr = await srow.fetchone()

    return DashboardStats(
        total=r["total"] or 0,
        new=r["new"] or 0,
        critical=r["critical"] or 0,
        high=r["high"] or 0,
        medium=r["medium"] or 0,
        low=r["low"] or 0,
        platforms_scanned=pr["cnt"] or 0,
        last_scan=dict(sr)["started_at"] if sr else None,
    )
