"""Supabase database layer for the lure monitor."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from supabase import acreate_client, AsyncClient

from models import ScoredFinding, ScanRecord


async def get_db() -> AsyncClient:
    """Create and return a Supabase AsyncClient using service_role key."""
    url = os.environ["SUPABASE_URL"]
    key = os.environ["SUPABASE_SERVICE_KEY"]
    return await acreate_client(url, key)


async def insert_scan(client: AsyncClient, scan: ScanRecord) -> int:
    """Insert a new scan record. Returns the generated id."""
    record = {
        "started_at": scan.started_at.isoformat(),
        "platforms":  scan.platforms,   # list → JSONB directly (no json.dumps)
        "status":     scan.status,
    }
    result = await client.table("scans").insert(record).execute()
    return result.data[0]["id"]


async def upsert_finding(client: AsyncClient, f: ScoredFinding) -> bool:
    """Insert or update a finding. Returns True if this is a new finding."""
    now = datetime.now(timezone.utc).isoformat()

    # Check if finding already exists (for scan_count + first_seen preservation)
    existing = await client.table("findings").select("id,scan_count,first_seen,dismissed").eq("id", f.id).execute()
    is_new = len(existing.data) == 0

    # ALWAYS send ALL required fields — Supabase upsert ON CONFLICT needs the
    # full row for both INSERT and UPDATE paths. Previously the UPDATE path
    # omitted platform/repo_name/repo_url, causing null constraint errors.
    record = {
        "id":               f.id,
        "platform":         f.platform,
        "repo_name":        f.repo_name,
        "repo_url":         f.repo_url,
        "description":      f.description,
        "owner_login":      f.owner_login,
        "owner_age_days":   f.owner_age_days,
        "owner_pub_repos":  f.owner_pub_repos,
        "stars":            f.stars,
        "forks":            f.forks,
        "score":            f.score,
        "severity":         f.severity,
        "reasons":          f.reasons,                                   # list → JSONB
        "release_assets":   [a.model_dump() for a in f.release_assets],  # list → JSONB
        "suspicious_files": f.suspicious_files,                          # list → JSONB
        "repo_created_at":  f.repo_created_at,
        "last_seen":        now,
    }

    if is_new:
        record["first_seen"]  = now
        record["scan_count"]  = 1
        record["dismissed"]   = False
    else:
        record["first_seen"]  = existing.data[0].get("first_seen") or now
        record["scan_count"]  = (existing.data[0].get("scan_count") or 1) + 1
        # PRESERVE dismissed status — don't un-dismiss on rescan
        record["dismissed"]   = existing.data[0].get("dismissed", False)

    await client.table("findings").upsert(record, on_conflict="id").execute()
    return is_new


async def update_scan(client: AsyncClient, scan_id: int, **kwargs) -> None:
    """Update fields on a scan record. Coerces completed_at datetime to ISO string."""
    updates: dict = {}
    for k, v in kwargs.items():
        if k == "completed_at" and isinstance(v, datetime):
            updates[k] = v.isoformat()
        elif k == "platforms" and isinstance(v, list):
            updates[k] = v  # list → JSONB, no json.dumps
        else:
            updates[k] = v
    await client.table("scans").update(updates).eq("id", scan_id).execute()
