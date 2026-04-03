"""GitLab platform scanner (gitlab.com public API)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from models import RepoCandidate, ReleaseAsset, OwnerInfo
from config import RELEASE_ARCHIVE_EXTENSIONS
from .base import PlatformScanner


class GitLabScanner(PlatformScanner):
    name = "gitlab"
    base_url = "https://gitlab.com/api/v4"

    async def search(self, queries: list[str], days_back: int) -> list[RepoCandidate]:
        since = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00Z")
        all_repos: dict[int, RepoCandidate] = {}
        http = await self.client()

        for query in queries:
            try:
                resp = await http.get(
                    f"{self.base_url}/projects",
                    params={
                        "search": query,
                        "order_by": "created_at",
                        "sort": "desc",
                        "per_page": 50,
                        "created_after": since,
                    },
                )
                if resp.status_code != 200:
                    continue
                projects = resp.json()
            except Exception:
                continue

            for p in projects:
                pid = p.get("id")
                if pid and pid not in all_repos:
                    path = p.get("path_with_namespace", "")
                    all_repos[pid] = RepoCandidate(
                        platform="gitlab",
                        repo_id=str(pid),
                        repo_name=path,
                        repo_url=p.get("web_url", f"https://gitlab.com/{path}"),
                        description=p.get("description", "") or "",
                        owner_login=path.split("/")[0] if "/" in path else "",
                        stars=p.get("star_count", 0),
                        forks=p.get("forks_count", 0),
                        repo_created_at=p.get("created_at", ""),
                    )

        return list(all_repos.values())

    async def get_readme(self, repo_id: str) -> str:
        http = await self.client()
        for filename in ["README.md", "readme.md", "README.rst", "README"]:
            try:
                resp = await http.get(
                    f"{self.base_url}/projects/{repo_id}/repository/files/{quote(filename, safe='')}/raw",
                    params={"ref": "main"},
                )
                if resp.status_code == 200:
                    return resp.text
                # Try default branch
                resp = await http.get(
                    f"{self.base_url}/projects/{repo_id}/repository/files/{quote(filename, safe='')}/raw",
                    params={"ref": "master"},
                )
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                continue
        return ""

    async def get_releases(self, repo_id: str) -> list[ReleaseAsset]:
        http = await self.client()
        assets = []
        try:
            resp = await http.get(f"{self.base_url}/projects/{repo_id}/releases")
            if resp.status_code != 200:
                return []
            releases = resp.json()
        except Exception:
            return []

        for release in releases:
            tag = release.get("tag_name", "")
            published = release.get("released_at", "")[:10]
            for source in release.get("assets", {}).get("sources", []):
                fmt = source.get("format", "")
                url = source.get("url", "")
                if fmt in ("zip", "tar.gz"):
                    assets.append(ReleaseAsset(
                        name=f"source.{fmt}",
                        download_url=url,
                        tag=tag,
                        published=published,
                    ))
            for link in release.get("assets", {}).get("links", []):
                name = link.get("name", "")
                url = link.get("direct_asset_url", "") or link.get("url", "")
                ext = os.path.splitext(name.lower())[1]
                if ext in RELEASE_ARCHIVE_EXTENSIONS:
                    assets.append(ReleaseAsset(
                        name=name,
                        download_url=url,
                        tag=tag,
                        published=published,
                    ))
        return assets

    async def get_file_tree(self, repo_id: str) -> list[str]:
        http = await self.client()
        try:
            resp = await http.get(
                f"{self.base_url}/projects/{repo_id}/repository/tree",
                params={"recursive": "true", "per_page": 100},
            )
            if resp.status_code != 200:
                return []
            return [item.get("path", "") for item in resp.json()]
        except Exception:
            return []

    async def get_owner_info(self, owner_login: str) -> OwnerInfo:
        http = await self.client()
        try:
            resp = await http.get(
                f"{self.base_url}/users",
                params={"username": owner_login},
            )
            if resp.status_code != 200 or not resp.json():
                return OwnerInfo(login=owner_login)
            u = resp.json()[0]
            age_days = None
            created = u.get("created_at", "")
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
