"""Pydantic models for the multi-platform lure scanner."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ReleaseAsset(BaseModel):
    name: str
    size_mb: float = 0.0
    download_count: int = 0
    download_url: str = ""
    tag: str = ""
    published: str = ""


class RepoCandidate(BaseModel):
    platform: str  # "github", "gitlab", "codeberg", "bitbucket", "sourceforge"
    repo_id: str  # platform-specific unique ID
    repo_name: str  # "owner/repo" or project slug
    repo_url: str
    description: str = ""
    owner_login: str = ""
    stars: int = 0
    forks: int = 0
    repo_created_at: Optional[str] = None

    @property
    def finding_id(self) -> str:
        return f"{self.platform}:{self.repo_name}"


class OwnerInfo(BaseModel):
    login: str = ""
    created_at: Optional[str] = None
    public_repos: int = 0
    age_days: Optional[int] = None


class ScoredFinding(BaseModel):
    id: str  # "platform:owner/repo"
    platform: str
    repo_name: str
    repo_url: str
    description: str = ""
    owner_login: str = ""
    owner_age_days: Optional[int] = None
    owner_pub_repos: Optional[int] = None
    stars: int = 0
    forks: int = 0
    score: int = 0
    severity: str = "LOW"
    reasons: list[str] = Field(default_factory=list)
    release_assets: list[ReleaseAsset] = Field(default_factory=list)
    suspicious_files: list[str] = Field(default_factory=list)
    repo_created_at: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    scan_count: int = 1
    dismissed: bool = False
    is_new: bool = False


class ScanRecord(BaseModel):
    id: Optional[int] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    platforms: list[str] = Field(default_factory=list)
    total_found: int = 0
    new_found: int = 0
    duration_seconds: float = 0.0
    status: str = "running"


class ScanProgress(BaseModel):
    platform: str
    status: str  # "searching", "inspecting", "done", "error"
    found: int = 0
    message: str = ""


class DashboardStats(BaseModel):
    total: int = 0
    new: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    platforms_scanned: int = 0
    platforms_total: int = 5
    last_scan: Optional[str] = None
