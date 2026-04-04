"""Entry point for VT Retrohunt GitHub Actions job.

Submits a YARA rule to VirusTotal Intelligence retrohunt, polls until
the job completes (can take 1–6 hours), then ingests all matching files
into the Supabase findings table as platform='vt_retrohunt'.

Required env vars:
    VT_API_KEY            — VirusTotal Intelligence API key
    SUPABASE_URL          — Supabase project URL
    SUPABASE_SERVICE_KEY  — Supabase service_role key

Optional:
    VT_RULE_FILE    — Path to YARA file to submit (default: yara/retrohunt_dropper.yar)
    DAYS_BACK       — Days to search back in VT corpus, max 90 (default: 30)
    MIN_SCORE       — Minimum score to persist a finding (default: 5)

Usage (local):
    VT_API_KEY=... SUPABASE_URL=... SUPABASE_SERVICE_KEY=... python run_vt_retrohunt.py

Usage (GitHub Actions):
    Trigger the 'VT Retrohunt' workflow_dispatch from the Actions tab.
    Select the number of days to search back (1–90, default 30).
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)

logger = logging.getLogger("vt-retrohunt")

import db
import config
from models import ScanRecord
from platforms.virustotal import VirusTotalScanner


async def run_retrohunt() -> tuple[int, int]:
    """Submit retrohunt job, wait for completion, ingest findings.

    Returns (total_found, new_found).
    """
    # ── Locate YARA rule file ─────────────────────────────────────────────────
    rule_file = Path(
        os.environ.get("VT_RULE_FILE", "yara/retrohunt_dropper.yar")
    )
    if not rule_file.exists():
        raise FileNotFoundError(
            f"YARA rule file not found: {rule_file}\n"
            f"Set VT_RULE_FILE env var or ensure yara/retrohunt_dropper.yar exists."
        )

    rule_source = rule_file.read_text(encoding="utf-8")
    days_back   = int(os.environ.get("DAYS_BACK", 30))

    logger.info(f"Rule file : {rule_file}")
    logger.info(f"Days back : {days_back}")
    logger.info(f"Rule size : {len(rule_source)} chars")

    # ── Init DB + scan record ─────────────────────────────────────────────────
    database = await db.get_db()
    scan = ScanRecord(
        started_at=datetime.now(timezone.utc),
        platforms=["vt_retrohunt"],
        status="running",
    )
    scan_id = await db.insert_scan(database, scan)
    logger.info(f"Scan record: id={scan_id}")

    vt = VirusTotalScanner()
    total_found = new_found = 0

    try:
        findings = await vt.retrohunt(rule_source=rule_source, days_back=days_back)

        for finding in findings:
            is_new = await db.upsert_finding(database, finding)
            total_found += 1
            if is_new:
                new_found += 1

        completed_at = datetime.now(timezone.utc)
        duration     = (completed_at - scan.started_at).total_seconds()

        await db.update_scan(
            database, scan_id,
            completed_at=completed_at,
            total_found=total_found,
            new_found=new_found,
            duration_seconds=round(duration, 1),
            platforms=["vt_retrohunt"],
            status="completed",
        )

        logger.info(
            f"Retrohunt complete: {total_found} findings "
            f"({new_found} new) in {duration / 60:.1f} min"
        )

    except Exception as e:
        logger.error(f"Retrohunt failed: {e}", exc_info=True)
        await db.update_scan(database, scan_id, status=f"failed: {e}")
        raise
    finally:
        await vt.close()

    return total_found, new_found


async def main() -> None:
    total, new = await run_retrohunt()
    print(f"\nRetroHunt complete: {total} findings ({new} new)")


if __name__ == "__main__":
    asyncio.run(main())
