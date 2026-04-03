"""Bitbucket platform scanner (public REST API v2)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from models import RepoCandidate, ReleaseAsset, OwnerInfo
from config import RELEASE_ARCHIVE_EXTENSIONS
from .base import PlatformScanner


class BitbucketScanner(PlatformScanner):
    name = "bitbucket"
    base_url = "https://api.bitbucket.org/2.0"

    async def search(self, queries: list[str], days_back: int) -> list[RepoCandidate]:
        all_repos: dict[str, RepoCandidate] = {}
        http = await self.client()

        for query in queries:
            try:
                resp = await http.get(
                    f"{self.base_url}/repositories",
                    params={
                        "q": f'name ~ "{query}"',
                        "sort": "-created_on",
                        "pagelen": 50,
                    },
                )
                if resp.status_code != 200:
                    continue
                data = resp.json()
            except Exception:
                continue

            cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)

            for repo in data.get("values", []):
                full_name = repo.get("full_name", "")
                if not full_name or full_name in all_repos:
                    continue

                created_str = repo.get("created_on", "")
                if created_str:
                    try:
                        created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                        if created_dt < cutoff:
                            continue
                    except ValueError:
                        pass

                owner = repo.get("owner", {})
                all_repos[full_name] = RepoCandidate(
                    platform="bitbucket",
                    repo_id=full_name,
                    repo_name=full_name,
                    repo_url=repo.get("links", {}).get("html", {}).get("href", f"https://bitbucket.org/{full_name}"),
                    description=repo.get("description", "") or "",
                    owner_login=owner.get("username", "") or owner.get("nickname", ""),
                    stars=0,  # Bitbucket doesn't expose star count in search
                    forks=0,
                    repo_created_at=created_str,
                )

        return list(all_repos.values())

    async def get_readme(self, repo_id: str) -> str:
        http = await self.client()
        for filename in ["README.md", "readme.md", "README.rst", "README"]:
            try:
                resp = await http.get(
                    f"{self.base_url}/repositories/{repo_id}/src/HEAD/{filename}",
                )
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                continue
        return ""

    async def get_releases(self, repo_id: str) -> list[ReleaseAsset]:
        """Bitbucket uses 'downloads' instead of releases."""
        http = await self.client()
        assets = []
        try:
            resp = await http.get(f"{self.base_url}/repositories/{repo_id}/downloads")
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception:
            return []

        for dl in data.get("values", []):
            name = dl.get("name", "")
            ext = os.path.splitext(name.lower())[1]
            if ext in RELEASE_ARCHIVE_EXTENSIONS:
                assets.append(ReleaseAsset(
                    name=name,
                    size_mb=round(dl.get("size", 0) / (1024 * 1024), 2),
                    download_count=dl.get("downloads", 0),
                    download_url=dl.get("links", {}).get("self", {}).get("href", ""),
                ))
        return assets

    async def get_file_tree(self, repo_id: str) -> list[str]:
        http = await self.client()
        try:
            resp = await http.get(
                f"{self.base_url}/repositories/{repo_id}/src/HEAD/",
                params={"pagelen": 100},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            return [item.get("path", "") for item in data.get("values", [])]
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
            created = u.get("created_on", "")
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
