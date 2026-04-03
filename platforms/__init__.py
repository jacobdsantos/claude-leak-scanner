from .github import GitHubScanner
from .gitlab import GitLabScanner
from .codeberg import CodebergScanner
from .bitbucket import BitbucketScanner
from .sourceforge import SourceForgeScanner

PLATFORM_MAP = {
    "github": GitHubScanner,
    "gitlab": GitLabScanner,
    "codeberg": CodebergScanner,
    "bitbucket": BitbucketScanner,
    "sourceforge": SourceForgeScanner,
}

__all__ = [
    "GitHubScanner", "GitLabScanner", "CodebergScanner",
    "BitbucketScanner", "SourceForgeScanner", "PLATFORM_MAP",
]
