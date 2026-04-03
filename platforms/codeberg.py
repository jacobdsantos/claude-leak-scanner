"""Codeberg platform scanner (Gitea API)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from models import RepoCandidate, ReleaseAsset, OwnerInfo
from config import RELEASE_ARCHIVE_EXTENSIONS
from .base import PlatformScanner


class CodebergScanner(PlatformScanner):
    name = "codeberg"
    base_url = "https://codeberg.org/api/v1"

    async def search(self, queries: list[str], days_back: int) -> list[RepoCandidate]:
        all_repos: dict[str, RepoCandidate] = {}
        http = await self.client()

        for query in queries:
            try:
                resp = await http.get(
                    f"{self.base_url}/repos/search",
                    params={"q": query, "sort": "newest", "limit": 50},
                )
                if resp.status_code != 200:
                    continue
                data = resp.json().get("data", []) if isinstance(resp.json(), dict) else resp.json()
            except Exception:
                continue

            cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)

            for repo in data:
                full_name = repo.get("full_name", "")
                if not full_name or full_name in all_repos:
                    continue

                created_str = repo.get("created_at", "")
                if created_str:
                    try:
                        created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                        if created_dt < cutoff:
                            continue
                    except ValueError:
                        pass

                all_repos[full_name] = RepoCandidate(
                    platform="codeberg",
                    repo_id=full_name,
                    repo_name=full_name,
                    repo_url=repo.get("html_url", f"https://codeberg.org/{full_name}"),
                    description=repo.get("description", "") or "",
                    owner_login=repo.get("owner", {}).get("login", ""),
                    stars=repo.get("stars_count", 0),
                    forks=repo.get("forks_count", 0),
                    repo_created_at=created_str,
                )

        return list(all_repos.values())

    async def get_readme(self, repo_id: str) -> str:
        http = await self.client()
        # repo_id is "owner/repo"
        for filename in ["README.md", "readme.md", "README"]:
            try:
                resp = await http.get(f"{self.base_url}/repos/{repo_id}/raw/{filename}")
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                continue
        return ""

    async def get_releases(self, repo_id: str) -> list[ReleaseAsset]:
        http = await self.client()
        assets = []
        try:
            resp = await http.get(f"{self.base_url}/repos/{repo_id}/releases")
            if resp.status_code != 200:
                return []
            releases = resp.json()
        except Exception:
            return []

        for release in releases:
            tag = release.get("tag_name", "")
            published = release.get("published_at", "")[:10]
            for asset in release.get("assets", []):
                name = asset.get("name", "")
                ext = os.path.splitext(name.lower())[1]
                if ext in RELEASE_ARCHIVE_EXTENSIONS:
                    assets.append(ReleaseAsset(
                        name=name,
                        size_mb=round(asset.get("size", 0) / (1024 * 1024), 2),
                        download_count=asset.get("download_count", 0),
                        download_url=asset.get("browser_download_url", ""),
                        tag=tag,
                        published=published,
                    ))
        return assets

    async def get_file_tree(self, repo_id: str) -> list[str]:
        http = await self.client()
        try:
            resp = await http.get(
                f"{self.base_url}/repos/{repo_id}/git/trees/HEAD",
                params={"recursive": "true"},
            )
            if resp.status_code != 200:
                return []
            tree = resp.json().get("tree", [])
            return [item.get("path", "") for item in tree]
        except Exception:
            return []

    async def get_owner_info(self, owner_login: str) -> OwnerInfo:
        http = await self.client()
        try:
            resp = await http.get(f"{self.base_url}/users/{owner_login}")
            if resp.status_code != 200:
                return OwnerInfo(login=owner_login)
            u = resp.json()
            age_days = None
            created = u.get("created", "")
            if created:
                try:
                    delta = datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))
                    age_days = delta.days
                except ValueError:
                    pass
            return OwnerInfo(
                login=owner_login,
                created_at=created,
                public_repos=0,
                age_days=age_days,
            )
        except Exception:
            return OwnerInfo(login=owner_login)
