"""Shared configuration for the multi-platform lure scanner."""

import os

# ── Platform toggles ─────────────────────────────────────────────────────────

ENABLED_PLATFORMS = os.environ.get(
    "ENABLED_PLATFORMS", "github,gitlab,codeberg,bitbucket,sourceforge"
).split(",")

# ── Supabase ──────────────────────────────────────────────────────────────────

SUPABASE_URL         = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

# ── VirusTotal ────────────────────────────────────────────────────────────────

VT_API_KEY = os.environ.get("VT_API_KEY", "")

# Comma-separated list of VT Livehunt ruleset names to poll.
# These must match the ruleset names created in the VT Intelligence dashboard.
# Default maps to the 3 split rulesets (dropper, packer, payload).
# Set VT_HUNT_RULESET_NAMES env var to override (or leave empty to poll ALL).
_rulesets_raw    = os.environ.get("VT_HUNT_RULESET_NAMES", "claude_lure_droppers,claude_lure_packer,claude_lure_payload")
VT_HUNT_RULESET_NAMES: list[str] = [r.strip() for r in _rulesets_raw.split(",") if r.strip()]

# Legacy single-name support (if set, takes precedence)
_legacy = os.environ.get("VT_HUNT_RULESET_NAME", "")
if _legacy and _legacy not in VT_HUNT_RULESET_NAMES:
    VT_HUNT_RULESET_NAMES.insert(0, _legacy)

# ── Scanner settings ──────────────────────────────────────────────────────────

GITHUB_TOKEN    = os.environ.get("GITHUB_TOKEN", "")
DAYS_BACK       = int(os.environ.get("DAYS_BACK", 7))
STAR_THRESHOLD  = int(os.environ.get("STAR_THRESHOLD", 100))
MIN_SCORE       = int(os.environ.get("MIN_SCORE", 5))

# ── Search queries ────────────────────────────────────────────────────────────
# Expanded from 12 → 22 based on campaign research.
# Platform search APIs treat spaces as AND, so "claude leaked" covers
# "claude code leaked", "claude source leaked", etc.
#
# Research sources:
#   - Trend Micro: TradeAI rotating-lure campaign (25+ brands, same Rust dropper)
#   - Huntress: OpenClaw precursor campaign (Feb 2026, same threat actor)
#   - Zscaler: Known IOC repos idbzoomh/my3jie

SEARCH_QUERIES = [
    # Core leak variants
    "claude leaked",
    "claude code source",
    "claude sourcemap",
    "claude-code-leaked",

    # Anthropic-branded lures
    "anthropic leaked",
    "anthropic source code",

    # Obfuscated / evasion variants
    "claw code",
    "claude harness decoded",

    # Cracked / unlock / bypass claims (common lure copy)
    "claude cracked",
    "claude enterprise unlock",
    "claude unlock",
    "claude activator",
    "claude keygen",
    "claude bypass",

    # Free access claims
    "claude code free",
    "claude pro free",

    # Install / setup executable lures
    "ClaudeCode_x64",           # exact known malware binary name
    "claude code setup",
    "claude code installer",

    # Known campaign identifiers
    "TradeAI nofilabs",         # dropper label across all 25+ brand variants
    "openclaw",                 # Feb 2026 precursor campaign, same TA + payload

    # Research / RE repos
    "claude code reverse engineer",
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

KNOWN_C2_IPS    = {"147.45.197.92", "94.228.161.88", "45.55.35.48"}
KNOWN_C2_DOMAINS = {
    "rti.cargomanbd.com",
    "steamhostserver.cc",   # NEW — identified from sample c3eede99, not yet in public reports
}

# Dead-drop resolver domains used by Rust dropper group to fetch payload URLs
# These are NOT C2 — they host obfuscated download links at runtime
# snippet.host is the high-confidence signal (not used by legit software)
# pastebin.com alone has too many FPs; only flag when combined with other signals
KNOWN_DEAD_DROP_RESOLVERS = {"snippet.host", "pastebin.com"}

# ── Lure keyword patterns (regex, weight, label) ────────────────────────────

LURE_PATTERNS = [
    (r"leaked?\s*(source\s*)?code",                  25, "leaked source code"),
    (r"enterprise\s*(features?\s*)?(unlock|enabl|activat)", 20, "enterprise unlock"),
    (r"no\s*(message\s*)?limit",                     20, "no limits claim"),
    (r"full\s*source\s*(map|code)",                  15, "full source reference"),
    (r"download\s*(zip|7z|archive)",                 15, "download archive CTA"),
    (r"crack(ed|ing)?",                              15, "cracked claim"),
    (r"free\s*(premium|enterprise|pro)",             15, "free premium claim"),
    (r"source\s*map\s*(leak|expos|extract)",         15, "source map leak"),
    (r"anthropic.*internal",                         10, "anthropic internal claim"),
    (r"bypass\s*(rate|limit|auth)",                  10, "bypass claim"),
    (r"TradeAI",                                     50, "KNOWN DROPPER: TradeAI nofilabs campaign"),
]

# ── Suspicious file patterns ─────────────────────────────────────────────────

SUSPICIOUS_FILE_EXTENSIONS = {
    ".7z", ".exe", ".rar", ".msi", ".bat", ".cmd", ".ps1", ".scr", ".com", ".pif",
}

SUSPICIOUS_FILE_NAMES = {
    "claudecode_x64.exe", "claudecode.exe", "claude_code.exe",
    "setup.exe", "install.exe", "openclaudecode.exe",
    "tradeai.exe",      # rotating campaign dropper
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
