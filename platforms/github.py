"""GitHub platform scanner using REST API (httpx)."""

from __future__ import annotations

import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

from models import RepoCandidate, ReleaseAsset, OwnerInfo
from config import (
    KNOWN_MALICIOUS_REPOS, KNOWN_MALICIOUS_ACCOUNTS, RELEASE_ARCHIVE_EXTENSIONS,
)
from .base import PlatformScanner

logger = logging.getLogger("lure-monitor.github")

# GitHub REST API base
_API = "https://api.github.com"

# Token from env — dramatically improves rate limits (10 → 30 search req/min)
_TOKEN = os.environ.get("GITHUB_TOKEN", "")


class GitHubScanner(PlatformScanner):
    name = "github"
    base_url = _API

    async def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if _TOKEN:
            h["Authorization"] = f"Bearer {_TOKEN}"
        return h

    async def client(self):
        """Override to inject GitHub auth headers."""
        if self._client is None or self._client.is_closed:
            import httpx
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers=await self._headers(),
            )
        return self._client

    async def search(self, queries: list[str], days_back: int) -> list[RepoCandidate]:
        since_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%d")
        all_repos: dict[str, RepoCandidate] = {}
        http = await self.client()

        for query in queries:
            # GitHub search API: q=<query>+created:>=<date>
            search_q = f"{query} created:>={since_date}"
            page = 1
            max_pages = 20  # GitHub caps at 1,000 results (20 × 50)

            while page <= max_pages:
                try:
                    resp = await http.get(
                        f"{_API}/search/repositories",
                        params={
                            "q": search_q,
                            "sort": "updated",
                            "order": "desc",
                            "per_page": 50,
                            "page": page,
                        },
                    )

                    if resp.status_code == 403:
                        logger.warning(f"GitHub rate limited on query: {query} (page {page})")
                        break
                    if resp.status_code == 422:
                        # GitHub returns 422 when page exceeds available results
                        break
                    if resp.status_code != 200:
                        logger.warning(f"GitHub search returned {resp.status_code} for: {query}")
                        break

                    data = resp.json()
                    items = data.get("items", [])
                    total_count = data.get("total_count", 0)

                    if page == 1:
                        logger.info(f"GitHub search '{query}': {len(items)} results (total: {total_count})")
                    else:
                        logger.info(f"  Page {page}: +{len(items)} results for '{query}'")

                except Exception as e:
                    logger.error(f"GitHub search failed for '{query}' page {page}: {e}")
                    break

                # Process this page's items
                for repo in items:
                    name = repo.get("full_name", "")
                    if name and name not in all_repos:
                        owner = repo.get("owner", {})
                        all_repos[name] = RepoCandidate(
                            platform="github",
                            repo_id=name,
                            repo_name=name,
                            repo_url=repo.get("html_url", f"https://github.com/{name}"),
                            description=repo.get("description", "") or "",
                            owner_login=owner.get("login", ""),
                            stars=repo.get("stargazers_count", 0),
                            forks=repo.get("forks_count", 0),
                            repo_created_at=repo.get("created_at", ""),
                        )

                # Stop paginating if no more results or hit GitHub's 1,000 cap
                if not items or len(items) < 50 or page * 50 >= min(total_count, 1000):
                    break
                page += 1

        # Check known malicious repos directly
        for known_repo in KNOWN_MALICIOUS_REPOS:
            if known_repo not in all_repos:
                try:
                    resp = await http.get(f"{_API}/repos/{known_repo}")
                    if resp.status_code == 200:
                        d = resp.json()
                        owner = d.get("owner", {})
                        all_repos[known_repo] = RepoCandidate(
                            platform="github",
                            repo_id=known_repo,
                            repo_name=known_repo,
                            repo_url=d.get("html_url", f"https://github.com/{known_repo}"),
                            description=d.get("description", "") or "",
                            owner_login=owner.get("login", ""),
                            stars=d.get("stargazers_count", 0),
                            forks=d.get("forks_count", 0),
                            repo_created_at=d.get("created_at", ""),
                        )
                    elif resp.status_code == 404:
                        logger.info(f"Known repo {known_repo} is gone (404)")
                    else:
                        logger.warning(f"Known repo {known_repo} returned {resp.status_code}")
                except Exception as e:
                    logger.error(f"Failed to check known repo {known_repo}: {e}")

        # Check repos from known malicious accounts
        for acct in KNOWN_MALICIOUS_ACCOUNTS:
            try:
                resp = await http.get(
                    f"{_API}/users/{acct}/repos",
                    params={"per_page": 30, "sort": "created"},
                )
                if resp.status_code == 200:
                    for repo in resp.json():
                        repo_name = repo.get("full_name", "")
                        if repo_name and repo_name not in all_repos:
                            owner = repo.get("owner", {})
                            all_repos[repo_name] = RepoCandidate(
                                platform="github",
                                repo_id=repo_name,
                                repo_name=repo_name,
                                repo_url=repo.get("html_url", ""),
                                description=repo.get("description", "") or "",
                                owner_login=owner.get("login", ""),
                                stars=repo.get("stargazers_count", 0),
                                forks=repo.get("forks_count", 0),
                                repo_created_at=repo.get("created_at", ""),
                            )
                elif resp.status_code == 404:
                    logger.info(f"Known account {acct} is gone (404)")
                else:
                    logger.warning(f"Known account {acct} returned {resp.status_code}")
            except Exception as e:
                logger.error(f"Failed to check account {acct}: {e}")

        logger.info(f"GitHub total unique repos: {len(all_repos)}")
        return list(all_repos.values())

    async def get_readme(self, repo_id: str) -> str:
        http = await self.client()
        try:
            resp = await http.get(
                f"{_API}/repos/{repo_id}/readme",
                headers={"Accept": "application/vnd.github.raw+json"},
            )
            if resp.status_code == 200:
                return resp.text[:10000]  # Cap at 10KB to save memory
        except Exception:
            pass
        return ""

    async def get_releases(self, repo_id: str) -> list[ReleaseAsset]:
        http = await self.client()
        try:
            resp = await http.get(
                f"{_API}/repos/{repo_id}/releases",
                params={"per_page": 5},
            )
            if resp.status_code != 200:
                return []
            releases = resp.json()
        except Exception:
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
        http = await self.client()
        try:
            resp = await http.get(
                f"{_API}/repos/{repo_id}/git/trees/HEAD",
                params={"recursive": "1"},
            )
            if resp.status_code != 200:
                return []
            tree = resp.json().get("tree", [])
            return [item.get("path", "") for item in tree]
        except Exception:
            return []

    async def get_star_history(self, repo_id: str, max_pages: int = 10) -> list[dict]:
        """Fetch star history as cumulative daily snapshots.

        Uses the star+json media type to get timestamped stargazer events.
        Returns [{date: "YYYY-MM-DD", total: int}, ...] one entry per day.

        Rate cost: up to max_pages requests. Only call for repos with
        meaningful star counts (gate at caller side to save API budget).
        """
        http = await self.client()
        starred_dates: list[str] = []

        for page in range(1, max_pages + 1):
            try:
                resp = await http.get(
                    f"{_API}/repos/{repo_id}/stargazers",
                    headers={"Accept": "application/vnd.github.v3.star+json"},
                    params={"per_page": 100, "page": page},
                )
                if resp.status_code == 403:
                    logger.warning(f"GitHub rate limited fetching star history for {repo_id}")
                    break
                if resp.status_code != 200:
                    break
                data = resp.json()
                if not data:
                    break
                for item in data:
                    starred_at = item.get("starred_at", "")
                    if starred_at:
                        starred_dates.append(starred_at[:10])  # YYYY-MM-DD
                if len(data) < 100:
                    break  # last page
            except Exception as exc:
                logger.debug(f"Star history fetch failed for {repo_id} page {page}: {exc}")
                break

        if not starred_dates:
            return []

        counts = Counter(starred_dates)
        cumulative = 0
        history: list[dict] = []
        for date in sorted(counts):
            cumulative += counts[date]
            history.append({"date": date, "total": cumulative})
        return history

    async def get_owner_info(self, owner_login: str) -> OwnerInfo:
        http = await self.client()
        try:
            resp = await http.get(f"{_API}/users/{owner_login}")
            if resp.status_code != 200:
                return OwnerInfo(login=owner_login)
            d = resp.json()
            age_days = None
            created = d.get("created_at", "")
            if created:
                try:
                    delta = datetime.now(timezone.utc) - datetime.fromisoformat(
                        created.replace("Z", "+00:00")
                    )
                    age_days = delta.days
                except ValueError:
                    pass
            return OwnerInfo(
                login=owner_login,
                created_at=created,
                public_repos=d.get("public_repos", 0),
                age_days=age_days,
            )
        except Exception:
            return OwnerInfo(login=owner_login)
