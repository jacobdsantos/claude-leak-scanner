#!/usr/bin/env python3
"""
Intel 471 Lure Campaign Intelligence — Standalone Script
=========================================================
Full sweep: malware intel, underground forums, adversary profiles, credential leaks.
Local use only — NOT integrated into the dashboard.

Usage:
    python3 intel471.py --api-key YOUR_KEY [--query "vidar claude code"] [--output output/]

Requires: INTEL471_API_KEY env var or --api-key flag.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import httpx
except ImportError:
    print("Error: httpx required. Install with: pip install httpx")
    sys.exit(1)


API_BASE = "https://api.intel471.com/v1"

DEFAULT_QUERIES = [
    "vidar claude code",
    "claude code leaked",
    "ghostsocks vidar",
    "claudecode malware",
    "vidar stealer ai tool",
]

MALWARE_FAMILIES = ["vidar", "ghostsocks"]


def api_get(client: httpx.Client, endpoint: str, params: dict = None) -> dict:
    """Make authenticated GET request to Intel 471 API."""
    try:
        resp = client.get(f"{API_BASE}{endpoint}", params=params or {})
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            print(f"  [!] Auth failed for {endpoint} — check API key")
        elif resp.status_code == 403:
            print(f"  [!] Forbidden: {endpoint} — may need higher API tier")
        else:
            print(f"  [!] {resp.status_code} for {endpoint}")
    except Exception as e:
        print(f"  [!] Error calling {endpoint}: {e}")
    return {}


def search_malware_intel(client: httpx.Client, queries: list[str]) -> list[dict]:
    """Search malware intelligence reports."""
    results = []
    for query in queries:
        print(f"  Malware search: {query!r}")
        data = api_get(client, "/malwareIndicators", {
            "malware": query,
            "count": 50,
            "sort": "latest",
        })
        for indicator in data.get("malwareIndicators", []):
            results.append({
                "type": "malware_indicator",
                "query": query,
                "data": indicator,
            })

    # Also search by malware family name
    for family in MALWARE_FAMILIES:
        print(f"  Malware family: {family!r}")
        data = api_get(client, "/malwareIndicators", {
            "malwareFamily": family,
            "count": 50,
            "sort": "latest",
        })
        for indicator in data.get("malwareIndicators", []):
            results.append({
                "type": "malware_family",
                "query": family,
                "data": indicator,
            })

    return results


def search_underground_forums(client: httpx.Client, queries: list[str]) -> list[dict]:
    """Search underground forum posts."""
    results = []
    for query in queries:
        print(f"  Forum search: {query!r}")
        data = api_get(client, "/posts", {
            "text": query,
            "count": 50,
            "sort": "latest",
        })
        for post in data.get("posts", []):
            results.append({
                "type": "forum_post",
                "query": query,
                "data": post,
            })
    return results


def search_adversary_profiles(client: httpx.Client, queries: list[str]) -> list[dict]:
    """Search adversary/threat actor profiles."""
    results = []
    for query in queries:
        print(f"  Adversary search: {query!r}")
        data = api_get(client, "/actors", {
            "actor": query,
            "count": 20,
        })
        for actor in data.get("actors", []):
            results.append({
                "type": "adversary",
                "query": query,
                "data": actor,
            })
    return results


def search_credential_leaks(client: httpx.Client, queries: list[str]) -> list[dict]:
    """Search credential leak data."""
    results = []
    for query in queries:
        print(f"  Credential search: {query!r}")
        data = api_get(client, "/credentials", {
            "text": query,
            "count": 50,
            "sort": "latest",
        })
        for cred in data.get("credentials", []):
            results.append({
                "type": "credential_leak",
                "query": query,
                "data": cred,
            })
    return results


def generate_report(all_results: dict, queries: list[str]) -> str:
    """Generate markdown report from all results."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Intel 471 — Claude Code Lure Campaign Intelligence",
        "",
        f"**Generated**: {now}",
        f"**Queries**: {', '.join(queries)}",
        "",
    ]

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|----------|-------|")
    for cat, results in all_results.items():
        lines.append(f"| {cat.replace('_', ' ').title()} | {len(results)} |")
    lines.append("")

    # Malware Intelligence
    if all_results.get("malware"):
        lines.append("## Malware Intelligence")
        lines.append("")
        for r in all_results["malware"][:20]:
            d = r["data"]
            lines.append(f"### {d.get('malwareFamily', 'Unknown')} — {d.get('type', 'indicator')}")
            lines.append(f"- **Query**: {r['query']}")
            if d.get("value"):
                lines.append(f"- **IOC**: `{d['value']}`")
            if d.get("confidence"):
                lines.append(f"- **Confidence**: {d['confidence']}")
            if d.get("firstSeen"):
                lines.append(f"- **First Seen**: {d['firstSeen']}")
            if d.get("lastSeen"):
                lines.append(f"- **Last Seen**: {d['lastSeen']}")
            lines.append("")

    # Underground Forums
    if all_results.get("forums"):
        lines.append("## Underground Forum Posts")
        lines.append("")
        for r in all_results["forums"][:20]:
            d = r["data"]
            lines.append(f"### {d.get('subject', 'No subject')}")
            lines.append(f"- **Forum**: {d.get('forum', {}).get('name', 'Unknown')}")
            lines.append(f"- **Author**: {d.get('actor', {}).get('handle', 'Unknown')}")
            if d.get("date"):
                lines.append(f"- **Date**: {d['date']}")
            if d.get("text"):
                snippet = d["text"][:300].replace("\n", " ")
                lines.append(f"- **Snippet**: {snippet}...")
            lines.append("")

    # Adversary Profiles
    if all_results.get("adversaries"):
        lines.append("## Adversary Profiles")
        lines.append("")
        for r in all_results["adversaries"][:10]:
            d = r["data"]
            lines.append(f"### {d.get('handle', 'Unknown')}")
            if d.get("forums"):
                forums = ", ".join(f.get("name", "") for f in d["forums"][:5])
                lines.append(f"- **Forums**: {forums}")
            if d.get("lastActivity"):
                lines.append(f"- **Last Activity**: {d['lastActivity']}")
            lines.append("")

    # Credential Leaks
    if all_results.get("credentials"):
        lines.append("## Credential Leak Mentions")
        lines.append("")
        lines.append(f"Found {len(all_results['credentials'])} credential entries mentioning campaign terms.")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Intel 471 campaign intelligence sweep")
    parser.add_argument("--api-key", type=str, default=os.environ.get("INTEL471_API_KEY", ""),
                        help="Intel 471 API key (or set INTEL471_API_KEY env var)")
    parser.add_argument("--query", type=str, nargs="*", default=None,
                        help="Custom search queries (default: built-in campaign terms)")
    parser.add_argument("--output", type=str, default="output",
                        help="Output directory (default: output/)")
    args = parser.parse_args()

    api_key = args.api_key
    if not api_key:
        print("Error: Intel 471 API key required.")
        print("  Set INTEL471_API_KEY env var or pass --api-key")
        sys.exit(1)

    queries = args.query if args.query else DEFAULT_QUERIES

    print("=" * 60)
    print("  Intel 471 — Claude Code Lure Campaign Sweep")
    print("  PH Threat Hunting Team (LOCAL USE ONLY)")
    print("=" * 60)
    print()

    client = httpx.Client(
        headers={
            "Authorization": f"Basic {api_key}",
            "Accept": "application/json",
        },
        timeout=30.0,
    )

    all_results = {}

    print("[1/4] Searching malware intelligence...")
    all_results["malware"] = search_malware_intel(client, queries)

    print(f"\n[2/4] Searching underground forums...")
    all_results["forums"] = search_underground_forums(client, queries)

    print(f"\n[3/4] Searching adversary profiles...")
    all_results["adversaries"] = search_adversary_profiles(client, queries)

    print(f"\n[4/4] Searching credential leaks...")
    all_results["credentials"] = search_credential_leaks(client, queries)

    client.close()

    # Generate outputs
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")

    # Markdown report
    report = generate_report(all_results, queries)
    md_file = output_dir / f"intel471-{timestamp}.md"
    md_file.write_text(report, encoding="utf-8")

    # Raw JSON
    json_file = output_dir / f"intel471-{timestamp}.json"
    json_file.write_text(json.dumps(all_results, indent=2, default=str), encoding="utf-8")

    total = sum(len(v) for v in all_results.values())
    print(f"\n  Total results: {total}")
    print(f"  Report: {md_file}")
    print(f"  Raw JSON: {json_file}")
    print()


if __name__ == "__main__":
    main()
