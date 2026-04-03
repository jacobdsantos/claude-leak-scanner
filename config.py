"""Shared configuration for the multi-platform lure scanner."""

import os

# ── Platform toggles ─────────────────────────────────────────────────────────

ENABLED_PLATFORMS = os.environ.get(
    "ENABLED_PLATFORMS", "github,gitlab,codeberg,bitbucket,sourceforge"
).split(",")

# ── Dashboard ─────────────────────────────────────────────────────────────────

DASHBOARD_PORT = int(os.environ.get("PORT", 8422))
AUTO_SCAN_INTERVAL_MINUTES = 0  # 0 = disabled
DAYS_BACK = int(os.environ.get("DAYS_BACK", 7))
STAR_THRESHOLD = int(os.environ.get("STAR_THRESHOLD", 50))
MIN_SCORE = int(os.environ.get("MIN_SCORE", 10))
DB_PATH = os.environ.get("DB_PATH", "lure_monitor.db")

# ── Search queries (shared across all platforms) ─────────────────────────────

SEARCH_QUERIES = [
    "claude code leaked",
    "claude code source leaked",
    "claude source code leak",
    "claude code cracked",
    "claude enterprise unlock",
    "claude no limits source",
    "anthropic leaked source",
    "claude code full source",
    "leaked-claude-code",
    "claude code download zip",
]

# ── Known IOCs (Zscaler ThreatLabz) ─────────────────────────────────────────

KNOWN_MALICIOUS_ACCOUNTS = {"idbzoomh", "idbzoomh1", "my3jie"}

KNOWN_MALICIOUS_REPOS = {
    "leaked-claude-code/leaked-claude-code",
    "my3jie/leaked-claude-code",
}

KNOWN_MD5S = {
    "d8256fbc62e85dae85eb8d4b49613774",
    "8660646bbc6bb7dc8f59a764e25fe1fd",
    "77c73bd5e7625b7f691bc00a1b561a0f",
    "81fb210ba148fd39e999ee9cdc085dfc",
    "9a6ea91491ccb1068b0592402029527f",
    "3388b415610f4ae018d124ea4dc99189",
}

KNOWN_C2_IPS = {"147.45.197.92", "94.228.161.88"}
KNOWN_C2_DOMAINS = {"rti.cargomanbd.com"}

# ── Lure keyword patterns (regex, weight, label) ────────────────────────────

LURE_PATTERNS = [
    (r"leaked?\s*(source\s*)?code", 25, "leaked source code"),
    (r"enterprise\s*(features?\s*)?(unlock|enabl|activat)", 20, "enterprise unlock"),
    (r"no\s*(message\s*)?limit", 20, "no limits claim"),
    (r"full\s*source\s*(map|code)", 15, "full source reference"),
    (r"download\s*(zip|7z|archive)", 15, "download archive CTA"),
    (r"crack(ed|ing)?", 15, "cracked claim"),
    (r"free\s*(premium|enterprise|pro)", 15, "free premium claim"),
    (r"source\s*map\s*(leak|expos|extract)", 15, "source map leak"),
    (r"anthropic.*internal", 10, "anthropic internal claim"),
    (r"bypass\s*(rate|limit|auth)", 10, "bypass claim"),
]

# ── Suspicious file patterns ─────────────────────────────────────────────────

SUSPICIOUS_FILE_EXTENSIONS = {
    ".7z", ".exe", ".rar", ".msi", ".bat", ".cmd", ".ps1", ".scr", ".com", ".pif",
}

SUSPICIOUS_FILE_NAMES = {
    "claudecode_x64.exe", "claudecode.exe", "claude_code.exe",
    "setup.exe", "install.exe", "openclaudecode.exe",
}

RELEASE_ARCHIVE_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".exe", ".msi", ".tar.gz", ".tgz",
}

# ── Severity bands ───────────────────────────────────────────────────────────

def severity_for_score(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"
