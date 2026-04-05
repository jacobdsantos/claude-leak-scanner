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
# claude_lure_packer excluded — too many FPs (Stealth Packer / .fptable heuristic
# matches many unrelated packed files). Only dropper + payload rulesets are used.
_rulesets_raw    = os.environ.get("VT_HUNT_RULESET_NAMES", "claude_lure_droppers,claude_lure_payload")
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
# Trimmed to 11 high-signal queries (was 23). Noisy queries removed:
#   claw code (720 FPs), claude code source (1147 FPs), anthropic source code (280 FPs),
#   claude code free (130 FPs), claude code setup (240 FPs), claude code installer (156 FPs),
#   claude activator/bypass/unlock/keygen/cracked/pro free (0-19, all FPs or dead)
#
# Research sources:
#   - Trend Micro: TradeAI rotating-lure campaign (25+ brands, same Rust dropper)
#   - Zscaler: Known IOC repos idbzoomh/my3jie

SEARCH_QUERIES = [
    # Goal: find MALICIOUS repos distributing malware, NOT source mirrors or analysis.
    # 4 precise queries — zero noise from discussion/mirror/analysis repos.

    # 1. Non-fork clones with "leaked-claude-code" in repo name
    "leaked-claude-code",

    # 2. Repos mentioning the malware binary name (exact)
    "ClaudeCode_x64",

    # 3. README download lure — repos with the exact archive name in their README
    "ClaudeCode_x64.7z in:readme",

    # 4. GitHub forks of the original malicious repo (exact phrase match, forks only)
    #    1,092+ forks as of 2026-04-05.
    '"leaked-claude-code" in:name fork:only',
]

# ── Known IOCs (Zscaler ThreatLabz) ─────────────────────────────────────────

KNOWN_MALICIOUS_ACCOUNTS = {"idbzoomh", "idbzoomh1", "my3jie"}

KNOWN_MALICIOUS_REPOS = {
    # Original malicious repos (Zscaler IOC)
    "leaked-claude-code/leaked-claude-code",
    "my3jie/leaked-claude-code",

    # ── Known forks of leaked-claude-code (all carry same malicious README + downloads)
    "ikandali/leaked-claude-code",
    "not-agent/leaked-claude-code",
    "KhaosLee/leaked-claude-code",
    "thivankasarathchandra/leaked-claude-code",
    "bcefghj/Claude-Code-Source",
    "aweyonhub/leaked-claude-code",
    "RicardoPoleo/supposed-cc",
    "Moskimla/leaked-claude-code",
    "makeouthillx32/leaked-claude-code",
    "shun-fukuchi-homula/leaked-claude-code",
    "MikeDevBeddo/leaked-claude-code-vv",
    "princearoraaws/leaked-claude-code",
    "VoicuTomut/leaked-claude-code",
    "GNSubrahmanyam/leaked-claude-code",
    "chinna-naidu/leaked-claude-code",
    "yasinldev/leaked-claude-code",
    "lalitaditya04/leaked-claude-code",
    "dazong9275-prog/leaked-claude-code",
    "paulmarinos/leaked-claude-code",
    "brokerdelhan-beep/leaked-claude-code",
    "Mazen-wedaa/leaked-claude-code",
    "xianzong1981/leaked-claude-code",
    "fabioeducacross/leaked-claude-code",
    "ShoupingShan/leaked-claude-code",
    "CHRITH3/leaked-claude-code",

    # ── Non-fork clones with same malicious content (README download lure)
    "5tarlight/lcc",
    "NguyenThucTrongNhan/clone-claudlev2",
    "nvd11/xinmi-ide-code",
}

KNOWN_MD5S = {
    "d8256fbc62e85dae85eb8d4b49613774",
    "8660646bbc6bb7dc8f59a764e25fe1fd",
    "77c73bd5e7625b7f691bc00a1b561a0f",
    "81fb210ba148fd39e999ee9cdc085dfc",
    "9a6ea91491ccb1068b0592402029527f",
    "3388b415610f4ae018d124ea4dc99189",
}

KNOWN_C2_IPS = {
    # Zscaler ThreatLabz IOCs
    "147.45.197.92", "94.228.161.88",
    # Identified from sample c3eede99 (steamhostserver.cc resolver)
    "45.55.35.48",
    # Trend Micro research — GhostSocks helper C&C (port 443)
    "185.196.9.98",   "121.127.33.212",
    "144.31.123.157", "144.31.139.201", "144.31.139.203",
    "144.31.204.136", "144.31.204.145", "172.245.112.202",
}

KNOWN_C2_DOMAINS = {
    # Vidar C&C (Zscaler)
    "rti.cargomanbd.com",
    # GhostSocks (sample c3eede99, first documented in this project)
    "steamhostserver.cc",
    # Data exfiltration server (Trend Micro research)
    "socifiapp.com",
    # PureLogs Stealer C&C (Trend Micro research)
    "serverconect.cc",
}

# Vidar dead-drop Steam profiles and Telegram channels
KNOWN_DEAD_DROP_RESOLVERS = {
    "snippet.host", "pastebin.com",
    # Steam profiles used by Vidar to resolve C&C address (Trend Micro research)
    "76561198721263282", "76561198742377525",
}

# Known SHA256 hashes from Trend Micro published research
# (weaponizing-trust-signals-claude-code.txt — 2026-04-03)
KNOWN_SHA256S = {
    # Dropper payloads — ClaudeCode_x64.exe variants
    "17145a933525ca8a6f29a818cf0fd94c37f20836090791bec349ae6e705670d4",
    "52e83c718ca96a12b98c5b31af177204145837f4208b0ee0c8e9c2b454795a64",
    "7d5e84dd59165422f31a5a0e53aabba657a6fbccc304e8649f72d49e468ae91a",
    "80920e8843ead75c58d56f55d351dbff01ccf9f28090e401479f21d651190b41",
    # TradeAI.exe dropper variants (25 hashes)
    "0b6ed577b993fd81e14f9abbef710e881629b8521580f3a127b2184685af7e05",
    "0f69513905b9aeca9ad2659ae16f4363ac03a359abeac9ac05cab70a50f17b65",
    "18467faa4fa10ea30fef2012fbd2c36f31407d0466b4e880dd1b6e1e37c9aff6",
    "249058ce8dc6e74cff9fb84d4d32c82e371265b40d02bb70b7955dceea008139",
    "2a4a8f58ad259bde54e9d37cc4a86563797c99a5dc31a0ae39a92f7807b846b9",
    "30be8190db0627a363927be8b8c8f38f31891fb8958b3691944b69533f6770b3",
    "36c4bb55b7e4c072e0cbc344d85b3530aca8f0237cc4669aecdd4dd8f67ab43a",
    "385d00d5dcefa918858e1d2d6623e7d1155f972b694f48944f98fcceb2624211",
    "44d40a9e59f08252a22939f76c92362c15a1ffab0dd3a4e3414bf4a5adc5d7c4",
    "518ff5fbfa4296abf38dfc342107f70e1491a7460978da6315a75175fb70e2b3",
    "537243230e14fb0f82bee8f51cac2e1d7ae955bb497c78b109972df51690edcf",
    "789835888a76eca8cc9e8625004607be99a90ec9f7a4db06c568a69ccb76bd60",
    "8090c3ecad7e4559ead21be02c564d20329e21fe3f449bcd9dbd8734f041aebd",
    "87133e737b2892cebee006068b341012e2c07db1526c08d0a13d0e0cf11d25d1",
    "96db6133e7ca04264ffdf18928c394376323c283a82e8106feec2ac28ee21eeb",
    "b73bd2e4cb16e9036aa7125587c5b3289e17e62f8831de1f9709896797435b82",
    "cce96b39831ce36b9fd1262a7cf4024218dbb3e2c7f1829c261cf79e5c9b50a8",
    "f96d80f7702cb1d5a340ab774e759e3357790c131cfac14a018716813dbc54dd",
    # Other payloads
    "40fc240febf2441d58a7e2554e4590e172bfefd289a5d9fa6781de38e266b378",  # PureLogs
    "a22ddb3083b62dae7f2c8e1e86548fc71b63b7652b556e50704b5c8908740ed5",  # GhostSocks
    "b4554c85f50c56d550d6c572a864deb0442404ddefe05ff27facb3cbfb90b4d6",  # Vidar v18.7
    "d5dffba463beae207aee339f88a18cfcd2ea2cd3e36e98d27297d819a1809846",  # Infostealer
    "e13d9304f7ebdab13f6cb6fae3dff3a007c87fed59b0e06ebad3ecfebf18b9fd",  # AMOS
    "f03e38e1c39ac52179e43107cf7511b9407edf83c008562250f5f340523b4b51",  # Vidar
}

# Already-tracked repos — used for dashboard "LISTED" column indicator.
# This does NOT affect scoring — it is purely for visual triage.
# 115 repos as of 2026-04-05.
ALREADY_LISTED_REPOS = {
    "0PeterAdel/ClaudeCode-Leak",
    "182slash/Claude",
    "3kh0/claude-code",
    "5tarlight/lcc",
    "760704887/claude-code-sourcemap",
    "AnukarOP/claude-code-leaked",
    "Bo1202/claude-code-source",
    "CHRITH3/leaked-claude-code",
    "CnOxx1/claude-code",
    "CodingWorld-007/claw-agent-guide",
    "Corleanus/claude-code-leaked",
    "Cshaoguang/claude-code-sourcemap",
    "GNSubrahmanyam/leaked-claude-code",
    "Gorav22/Claude-code-leaked",
    "Heipiao/leaked-claude-code",
    "HildaM/claude-code-leaked",
    "InlitX/claude-code-source",
    "JamesFireStarter13/claude-code",
    "Kawaii-GPT-ai/KawaiiGPT",
    "KhaosLee/leaked-claude-code",
    "LTX-desktop/LTX-2.3",
    "Manick94/claude_source_leaked_code",
    "Matloob11/Claude-code-leaked",
    "Mazen-wedaa/leaked-claude-code",
    "MikeDevBeddo/leaked-claude-code-vv",
    "Misterbra/claude-code-exposed",
    "MonsterKey/claude-code-leaked",
    "Moskimla/leaked-claude-code",
    "NguyenThucTrongNhan/clone-claudlev2",
    "OpenPayhub/claude-pay",
    "OtisChin/open-claude-code",
    "PhanTranHung/claude-code",
    "Pro-Fazendas/PROFAZENDAS---OpenClaude",
    "Ramabhadram/Claude-Code-Leaked",
    "Ramabhadram/Claude-Code-Leaked_2",
    "Ramabhadram/Claude-Code-Leaked_3",
    "Ramabhadram/Claude-Code-Leaked_4",
    "RicardoPoleo/supposed-cc",
    "SSPIV/anthropic-leaked-source-code",
    "Shahfaisal0835/claude-source-code-leaks",
    "ShoupingShan/leaked-claude-code",
    "Shreyan1/claude-code-src-leaked",
    "Shubhamdas27/Claude-Code-Leaked",
    "SwiftSteed/Awesome-Claude-Code-Source-Code",
    "Usamaliaquat123/Claude-Code-Source",
    "VoicuTomut/leaked-claude-code",
    "WenKai8688/claude-code-ha",
    "ai-wormGPT/wormGPT",
    "anilkeshwani/claude-code-leaked",
    "aweyonhub/leaked-claude-code",
    "bcefghj/Claude-Code-Source",
    "brokerdelhan-beep/leaked-claude-code",
    "chinna-naidu/leaked-claude-code",
    "claude-ai-opus-4-6/claude-opus-4.6",
    "codeaashu/claude-code-info",
    "davccavalcante/claude-code-leaked",
    "davidpuziol/claude-code",
    "dazong9275-prog/leaked-claude-code",
    "ddshub1/Claude-Code-Source-Code",
    "ecosys2026/claude-source-code",
    "enoola/claude-code_leaked-20260401",
    "fabioeducacross/leaked-claude-code",
    "fattail4477/claw-decode",
    "future-labs-narviz/claude-code-leaked",
    "hlwht/claude-code",
    "hmkne36/claude-code-leaked-source",
    "i24hour/Claude-code-leaked",
    "ikandali/leaked-claude-code",
    "imrancoder786/Leaked-claude-code",
    "ishanvaidya01/claude-leaked",
    "itopensourceafrica/leaked-claude-code",
    "jeffy0729/leaked-claude-code",
    "jiahuangzheng8-tech/claude-code-haha",
    "jimtracy1007/claude-code-leaked",
    "kodaneflash/leaked-original-claude-code",
    "lalitaditya04/leaked-claude-code",
    "lanjingling/claude-code-leaked",
    "leaked-claude-code/leaked-claude-code",
    "loveychen/claude-code-leaked",
    "makeouthillx32/leaked-claude-code",
    "minhlucvan/claude-code-wiki",
    "my3jie/ai-edu",
    "my3jie/civil-engineering-cloud-claude-code-source-v2.1.88",
    "my3jie/claude-code",
    "my3jie/claude-code2",
    "my3jie/claw-code",
    "my3jie/leaked-claude-code",
    "not-agent/leaked-claude-code",
    "nvd11/xinmi-ide-code",
    "nvidia-nemoclaw/NemoClaw",
    "omtripathi52/clawc",
    "openlang-cn/claude-code-run",
    "opensourceclaude/communityclaude",
    "paulmarinos/leaked-claude-code",
    "princearoraaws/leaked-claude-code",
    "randy0120/anthropic-leaked-source-code-backup",
    "rayzhux/claude-code-source-leak",
    "realtime-voice-changer-app/realtime-voice-changer",
    "saurav-shakya/Claude_Code-_Source_Code",
    "scmishra-cse/claude-code",
    "seanyoungw/harness-decoded",
    "senthils007/Claude-Leaked-Code",
    "sheiddy/claude-code-leaked",
    "shun-fukuchi-homula/leaked-claude-code",
    "thivankasarathchandra/leaked-claude-code",
    "varun-ahlawat/claude-code-src-code",
    "visheshsanghvi112/claude-code-leaked",
    "xianzong1981/leaked-claude-code",
    "xiaoping4220/claude-code-2188",
    "xyhStruggler/claude-code",
    "yanisvdc/why-claude-code-leaked",
    "yasinldev/leaked-claude-code",
    "yezhe18/claude-code-sourcemap",
    "yu441374-oss/claw-code",
    "zhouying-1218/claude-code001",
}

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
