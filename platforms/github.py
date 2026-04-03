"""GitHub platform scanner using gh CLI."""

from __future__ import annotations

import asyncio
import base64
import json
import os
from datetime import datetime, timedelta, timezone

from models import RepoCandidate, ReleaseAsset, OwnerInfo
from config import KNOWN_MALICIOUS_REPOS, KNOWN_MALICIOUS_ACCOUNTS, RELEASE_ARCHIVE_EXTENSIONS
from .base import PlatformScanner


class GitHubScanner(PlatformScanner):
    name = "github"
    base_url = "https://api.github.com"

    async def _gh(self, args: list[str]) -> str:
        """Run gh CLI command async."""
        proc = await asyncio.create_subprocess_exec(
            "gh", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode == 0:
            return stdout.decode().strip()
        return ""

    async def search(self, queries: list[str], days_back: int) -> list[RepoCandidate]:
        since_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%d")
        all_repos: dict[str, RepoCandidate] = {}

        for query in queries:
            raw = await self._gh([
                "search", "repos", query,
                "--created", f">={since_date}",
                "--json", "fullName,description,createdAt,updatedAt,stargazersCount,forksCount,url,owner",
                "--limit", "50",
            ])
            if not raw:
                continue
            try:
                repos = json.loads(raw)
            except json.JSONDecodeError:
                continue

            for repo in repos:
                name = repo.get("fullName", "")
                if name and name not in all_repos:
                    all_repos[name] = RepoCandidate(
                        platform="github",
                        repo_id=name,
                        repo_name=name,
                        repo_url=repo.get("url", f"https://github.com/{name}"),
                        description=repo.get("description", "") or "",
                        owner_login=repo.get("owner", {}).get("login", ""),
                        stars=repo.get("stargazersCount", 0),
                        forks=repo.get("forksCount", 0),
                        repo_created_at=repo.get("createdAt", ""),
                    )

        # Check known malicious repos directly
        for known_repo in KNOWN_MALICIOUS_REPOS:
            if known_repo not in all_repos:
                raw = await self._gh(["api", f"/repos/{known_repo}", "--jq", "."])
                if raw:
                    try:
                        d = json.loads(raw)
                        all_repos[known_repo] = RepoCandidate(
                            platform="github",
                            repo_id=known_repo,
                            repo_name=known_repo,
                            repo_url=d.get("html_url", f"https://github.com/{known_repo}"),
                            description=d.get("description", "") or "",
                            owner_login=d.get("owner", {}).get("login", ""),
                            stars=d.get("stargazers_count", 0),
                            forks=d.get("forks_count", 0),
                            repo_created_at=d.get("created_at", ""),
                        )
                    except json.JSONDecodeError:
                        pass

        # Check repos from known malicious accounts
        for acct in KNOWN_MALICIOUS_ACCOUNTS:
            raw = await self._gh(["api", f"/users/{acct}/repos", "--jq", ".[].full_name"])
            if raw:
                for repo_name in raw.strip().split("\n"):
                    if repo_name and repo_name not in all_repos:
                        repo_raw = await self._gh(["api", f"/repos/{repo_name}", "--jq", "."])
                        if repo_raw:
                            try:
                                d = json.loads(repo_raw)
                                all_repos[repo_name] = RepoCandidate(
                                    platform="github",
                                    repo_id=repo_name,
                                    repo_name=repo_name,
                                    repo_url=d.get("html_url", ""),
                                    description=d.get("description", "") or "",
                                    owner_login=d.get("owner", {}).get("login", ""),
                                    stars=d.get("stargazers_count", 0),
                                    forks=d.get("forks_count", 0),
                                    repo_created_at=d.get("created_at", ""),
                                )
                            except json.JSONDecodeError:
                                pass

        return list(all_repos.values())

    async def get_readme(self, repo_id: str) -> str:
        raw = await self._gh(["api", f"/repos/{repo_id}/readme", "--jq", ".content"])
        if not raw:
            return ""
        try:
            return base64.b64decode(raw.replace("\n", "")).decode("utf-8", errors="replace")
        except Exception:
            return ""

    async def get_releases(self, repo_id: str) -> list[ReleaseAsset]:
        raw = await self._gh(["api", f"/repos/{repo_id}/releases", "--jq", "."])
        if not raw:
            return []
        try:
            releases = json.loads(raw)
        except json.JSONDecodeError:
            return []

        assets = []
        for release in releases:
            tag = release.get("tag_name", "")
            published = release.get("published_at", "")[:10]
            for asset in release.get("assets", []):
                name = asset.get("name", "")
                name_lower = name.lower()
                ext = os.path.splitext(name_lower)[1]
                if name_lower.endswith(".tar.gz"):
                    ext = ".tar.gz"
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
        raw = await self._gh([
            "api", f"/repos/{repo_id}/git/trees/HEAD?recursive=1",
            "--jq", ".tree[].path",
        ])
        if not raw:
            return []
        return raw.strip().split("\n")

    async def get_owner_info(self, owner_login: str) -> OwnerInfo:
        raw = await self._gh(["api", f"/users/{owner_login}"])
        if not raw:
            return OwnerInfo(login=owner_login)
        try:
            d = json.loads(raw)
            age_days = None
            created = d.get("created_at", "")
            if created:
                try:
                    delta = datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))
                    age_days = delta.days
                except ValueError:
                    pass
            return OwnerInfo(
                login=owner_login,
                created_at=created,
                public_repos=d.get("public_repos", 0),
                age_days=age_days,
            )
        except json.JSONDecodeError:
            return OwnerInfo(login=owner_login)
