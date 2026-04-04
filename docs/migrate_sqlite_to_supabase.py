#!/usr/bin/env python3
"""
One-shot migration: SQLite lure_monitor.db → Supabase.

Run ONCE locally after 001_initial.sql has been executed in the Supabase SQL Editor.
Archive this file to docs/ after a successful migration.

Usage:
    pip install supabase
    SUPABASE_URL=https://nsjkrclfmetmjzpnqjjm.supabase.co \\
    SUPABASE_SERVICE_KEY=eyJ... \\
    python migrate_sqlite_to_supabase.py
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

from supabase import create_client

# ── Config ────────────────────────────────────────────────────────────────────

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lure_monitor.db")


# ── Helpers ───────────────────────────────────────────────────────────────────

def coerce_ts(val) -> str | None:
    """Ensure timestamp is timezone-aware ISO 8601. SQLite stores naive strings."""
    if not val:
        return None
    try:
        dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        return None


def parse_json(val, default=None):
    """Parse JSON TEXT field from SQLite into a Python object for JSONB columns.

    NEVER pass raw JSON strings to Supabase JSONB — causes double-encoding.
    """
    if default is None:
        default = []
    if not val:
        return default
    if isinstance(val, (list, dict)):
        return val  # already parsed
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return default


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not os.path.exists(DB_FILE):
        print(f"ERROR: SQLite file not found at {DB_FILE}")
        print("Make sure lure_monitor.db is in the same directory as this script.")
        return

    print(f"Connecting to Supabase: {SUPABASE_URL}")
    sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

    print(f"Reading SQLite: {DB_FILE}")
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # ── Migrate findings ──────────────────────────────────────────────────────

    cur.execute("SELECT * FROM findings ORDER BY first_seen ASC")
    findings_rows = cur.fetchall()
    print(f"\nFound {len(findings_rows)} findings in SQLite\n")

    migrated_findings = 0
    failed_findings = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for row in findings_rows:
        r = dict(row)

        first_seen = coerce_ts(r.get("first_seen")) or now_iso
        last_seen  = coerce_ts(r.get("last_seen"))  or first_seen

        record = {
            "id":               r["id"],
            "platform":         r["platform"],
            "repo_name":        r["repo_name"],
            "repo_url":         r["repo_url"],
            "description":      r.get("description") or "",
            "owner_login":      r.get("owner_login") or "",
            "owner_age_days":   r.get("owner_age_days"),
            "owner_pub_repos":  r.get("owner_pub_repos"),
            "stars":            r.get("stars") or 0,
            "forks":            r.get("forks") or 0,
            "score":            r["score"],
            "severity":         r["severity"],
            "reasons":          parse_json(r.get("reasons"),          []),
            "release_assets":   parse_json(r.get("release_assets"),   []),
            "suspicious_files": parse_json(r.get("suspicious_files"), []),
            "repo_created_at":  r.get("repo_created_at"),
            "first_seen":       first_seen,
            "last_seen":        last_seen,
            "scan_count":       r.get("scan_count") or 1,
            "dismissed":        bool(r.get("dismissed")),
        }

        try:
            sb.table("findings").upsert(record, on_conflict="id").execute()
            status = "DISMISSED" if record["dismissed"] else "active"
            print(f"  ✓ [{status:8s}] score={record['score']:3d}  {record['id']}")
            migrated_findings += 1
        except Exception as e:
            print(f"  ✗ FAILED  {record['id']}: {e}")
            failed_findings += 1

    # ── Migrate scans ─────────────────────────────────────────────────────────

    cur.execute("SELECT * FROM scans ORDER BY started_at ASC")
    scans_rows = cur.fetchall()
    print(f"\nFound {len(scans_rows)} scans in SQLite\n")

    migrated_scans = 0
    failed_scans = 0

    for row in scans_rows:
        r = dict(row)

        started_at = coerce_ts(r.get("started_at")) or now_iso
        record = {
            "started_at":       started_at,
            "completed_at":     coerce_ts(r.get("completed_at")),
            "platforms":        parse_json(r.get("platforms"), []),
            "total_found":      r.get("total_found") or 0,
            "new_found":        r.get("new_found") or 0,
            "duration_seconds": r.get("duration_seconds") or 0.0,
            "status":           r.get("status") or "completed",
        }

        try:
            sb.table("scans").insert(record).execute()
            print(f"  ✓ scan {r['id']}  {started_at[:16]}  {record['status']}")
            migrated_scans += 1
        except Exception as e:
            print(f"  ✗ scan {r['id']} FAILED: {e}")
            failed_scans += 1

    conn.close()

    # ── Summary ───────────────────────────────────────────────────────────────

    print(f"\n{'═' * 55}")
    print("Migration complete:")
    print(f"  Findings : {migrated_findings}/{len(findings_rows)} migrated, {failed_findings} failed")
    print(f"  Scans    : {migrated_scans}/{len(scans_rows)} migrated, {failed_scans} failed")
    print(f"\nRun this in Supabase SQL Editor to verify:")
    print("""
  SELECT
      COUNT(*) AS total_findings,
      COUNT(*) FILTER (WHERE dismissed = true)  AS dismissed,
      COUNT(*) FILTER (WHERE reasons IS NULL)   AS null_reasons,
      MIN(first_seen) AS earliest,
      MAX(last_seen)  AS latest
  FROM findings;

  SELECT COUNT(*) AS total_scans FROM scans;
""")


if __name__ == "__main__":
    main()
