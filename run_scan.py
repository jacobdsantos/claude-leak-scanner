"""Entry point for GitHub Actions scanner job."""

import asyncio
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)

from scanner import run_scan


async def main():
    total, new = await run_scan()
    print(f"\nScan complete: {total} findings ({new} new)")


if __name__ == "__main__":
    asyncio.run(main())
