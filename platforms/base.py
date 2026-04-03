"""Abstract base class for platform scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

import httpx

from models import RepoCandidate, ReleaseAsset, OwnerInfo


class PlatformScanner(ABC):
    name: str = ""
    base_url: str = ""

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None

    async def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={"User-Agent": "LureMonitor/1.0"},
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @abstractmethod
    async def search(self, queries: list[str], days_back: int) -> list[RepoCandidate]:
        """Search platform for repos matching lure queries."""

    @abstractmethod
    async def get_readme(self, repo_id: str) -> str:
        """Fetch README content for a repo."""

    @abstractmethod
    async def get_releases(self, repo_id: str) -> list[ReleaseAsset]:
        """Fetch release/download assets."""

    @abstractmethod
    async def get_file_tree(self, repo_id: str) -> list[str]:
        """Fetch repository file tree."""

    async def get_owner_info(self, owner_login: str) -> OwnerInfo:
        """Fetch owner profile info. Override per platform."""
        return OwnerInfo(login=owner_login)
