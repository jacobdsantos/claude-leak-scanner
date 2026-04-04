"""Entry point for the VT Livehunt GitHub Actions job.

Polls VirusTotal Intelligence hunting_notifications for files matching
configured YARA rules, scores them, and persists to Supabase findings table.

Required env vars:
    VT_API_KEY            — VirusTotal Intelligence API key
    SUPABASE_URL          — Supabase project URL
    SUPABASE_SERVICE_KEY  — Supabase service_role key

Optional:
    VT_HUNT_RULESET_NAME  — Ruleset name to filter (default: claude_code_lures)
    DAYS_BACK             — How far back to look for notifications (default: 7)
    MIN_SCORE             — Minimum score to persist a finding (default: 5)
"""

import asyncio
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)

from scanner import run_vt_scan


async def main() -> None:
    total, new = await run_vt_scan()
    print(f"\nVT scan complete: {total} findings ({new} new)")


if __name__ == "__main__":
    asyncio.run(main())
