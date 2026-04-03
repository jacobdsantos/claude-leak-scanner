"""SourceForge platform scanner (REST API + allura)."""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone

from models import RepoCandidate, ReleaseAsset, OwnerInfo
from config import RELEASE_ARCHIVE_EXTENSIONS
from .base import PlatformScanner


class SourceForgeScanner(PlatformScanner):
    name = "sourceforge"
    base_url = "https://sourceforge.net"

    async def search(self, queries: list[str], days_back: int) -> list[RepoCandidate]:
        all_repos: dict[str, RepoCandidate] = {}
        http = await self.client()

        for query in queries:
            try:
                # SourceForge Allura search API
                resp = await http.get(
                    f"{self.base_url}/rest/search",
                    params={"q": query, "type": "project", "limit": 50},
                )
                if resp.status_code != 200:
                    # Fallback: scrape search page
                    resp = await http.get(
                        f"{self.base_url}/directory/",
                        params={"q": query},
                    )
                    if resp.status_code == 200:
                        # Extract project slugs from search HTML
                        slugs = re.findall(r'href="/projects/([^/"]+)/"', resp.text)
                        for slug in slugs[:20]:
                            if slug not in all_repos:
                                all_repos[slug] = RepoCandidate(
                                    platform="sourceforge",
                                    repo_id=slug,
                                    repo_name=slug,
                                    repo_url=f"https://sourceforge.net/projects/{slug}/",
                                    description="",
                                    owner_login="",
                                )
                    continue

                data = resp.json()
                results = data.get("result", [])
            except Exception:
                continue

            cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)

            for project in results:
                slug = project.get("shortname", "")
                if not slug or slug in all_repos:
                    continue

                # SourceForge doesn't always provide creation date in search
                created_str = project.get("creation_date", "")
                if created_str:
                    try:
                        created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                        if created_dt < cutoff:
                            continue
                    except ValueError:
                        pass

                all_repos[slug] = RepoCandidate(
                    platform="sourceforge",
                    repo_id=slug,
                    repo_name=slug,
                    repo_url=project.get("url", f"https://sourceforge.net/projects/{slug}/"),
                    description=project.get("summary", "") or project.get("short_description", "") or "",
                    owner_login="",
                    stars=0,
                    forks=0,
                    repo_created_at=created_str,
                )

        return list(all_repos.values())

    async def get_readme(self, repo_id: str) -> str:
        """Scrape project description page."""
        http = await self.client()
        try:
            resp = await http.get(f"{self.base_url}/projects/{repo_id}/")
            if resp.status_code != 200:
                return ""
            # Extract description text from page
            text = resp.text
            # Look for project description in the HTML
            match = re.search(
                r'<div[^>]*id="description"[^>]*>(.*?)</div>',
                text, re.DOTALL
            )
            if match:
                desc = re.sub(r'<[^>]+>', ' ', match.group(1)).strip()
                return desc
            # Fallback: try REST API
            resp = await http.get(f"{self.base_url}/rest/p/{repo_id}")
            if resp.status_code == 200:
                data = resp.json()
                return data.get("description", "") or data.get("short_description", "") or ""
        except Exception:
            pass
        return ""

    async def get_releases(self, repo_id: str) -> list[ReleaseAsset]:
        http = await self.client()
        assets = []
        try:
            # Try REST API for file list
            resp = await http.get(f"{self.base_url}/projects/{repo_id}/files/")
            if resp.status_code != 200:
                return []

            # Parse file links from the files page
            text = resp.text
            file_links = re.findall(
                r'href="(/projects/[^/]+/files/[^"]+/download)"[^>]*>\s*<span[^>]*>([^<]+)',
                text
            )
            for link, name in file_links:
                name = name.strip()
                ext = os.path.splitext(name.lower())[1]
                if name.lower().endswith(".tar.gz"):
                    ext = ".tar.gz"
                if ext in RELEASE_ARCHIVE_EXTENSIONS:
                    # Try to get size from page
                    size_match = re.search(
                        re.escape(name) + r'.*?(\d+(?:\.\d+)?)\s*(?:MB|GB|KB)',
                        text, re.DOTALL
                    )
                    size_mb = 0.0
                    if size_match:
                        size_val = float(size_match.group(1))
                        if "GB" in text[size_match.end()-3:size_match.end()]:
                            size_mb = size_val * 1024
                        elif "KB" in text[size_match.end()-3:size_match.end()]:
                            size_mb = size_val / 1024
                        else:
                            size_mb = size_val

                    assets.append(ReleaseAsset(
                        name=name,
                        size_mb=round(size_mb, 2),
                        download_url=f"https://sourceforge.net{link}",
                    ))
        except Exception:
            pass
        return assets

    async def get_file_tree(self, repo_id: str) -> list[str]:
        """SourceForge doesn't have a clean file tree API; return files from files page."""
        http = await self.client()
        try:
            resp = await http.get(f"{self.base_url}/projects/{repo_id}/files/")
            if resp.status_code != 200:
                return []
            # Extract filenames
            names = re.findall(r'<span class="name">([^<]+)</span>', resp.text)
            return names
        except Exception:
            return []
