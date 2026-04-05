// ═══════════════════════════════════════════════════════════════════════════
// RULESET  : claude_lure_payload
// Author   : Trend Micro PH THT — Jacob Santos
// TLP      : GREEN
// Purpose  : VT Livehunt — catch actual malware payloads as standalone files:
//            (a) GhostSocks SOCKS5 proxy DLL/EXE — DEFINITIVE indicators only
//            (b) Vidar v18.7 infostealer — Telegram+Steam dead-drop combo
//
// REMOVED: TradeAI_Campaign_IOC_Any (Rule 7) — produced 77 FPs in 1 day.
//          snippet.host/C2 IPs appear in anti-malware tools' IOC databases.
//
// TIGHTENED: GhostSocks rule — removed go-socks5/yamux/relay/cfg_* conditions.
//            These generic Go library strings matched Jackett and other legitimate
//            Go programs. Only definitive indicators remain (mutex, byte sigs, API string).
//
// Create this ruleset in VT as: claude_lure_payload
// ═══════════════════════════════════════════════════════════════════════════

import "vt"
import "pe"


// ── RULE 5: GhostSocks SOCKS5 proxy — DEFINITIVE indicators only ─────────────
//
// TIGHTENED from original: removed 4 conditions that caused 63 FPs:
//   - go-socks5 + yamux → matched Jackett and other legitimate Go programs
//   - relay_server → too generic
//   - cfg_affiliate/build_version/proxy_user/proxy_pass → common JSON field names
//
// Remaining conditions are DEFINITIVE:
//   - "start to run" mutex — unique to GhostSocks, not used by any legitimate software
//   - SpyCloud byte signatures — extracted from actual GhostSocks binary analysis
//   - "Forbidden: Invalid API Key" — GhostSocks-specific C2 rejection string

rule GhostSocks_GoLang_SOCKS5_Proxy {
    meta:
        description = "GhostSocks SOCKS5 proxy — definitive indicators only (mutex + byte sigs)"
        author      = "Trend Micro PH THT (SpyCloud Labs + Synthient sigs adapted)"
        family      = "GhostSocks"
        reference   = "https://spycloud.com/blog/on-the-hunt-for-ghostsocks/"
        reference2  = "https://synthient.com/blog/ghostsocks-from-initial-access-to-residential-proxy"
        tlp         = "GREEN"
        date        = "2026-04-05"
        severity    = "CRITICAL"

    strings:
        // DEFINITIVE — mutex prevents duplicate instances; unique to GhostSocks
        $mutex       = "start to run" ascii wide

        // SpyCloud Labs binary signatures — GhostSocks core byte routine
        $gs_core     = { 89 EE C1 E5 02 39 EB 77 }

        // SpyCloud Labs — GhostSocks byte manipulation pattern
        $gs_manip    = { 0F B6 ?? ?? ?? 0F B6 ?? ?? ?? 31 CA 88 ?? ?? ?? 40 }

        // GhostSocks-specific API rejection string (Infrawatch network detection)
        $api_reject  = "Forbidden: Invalid API Key" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and (
            $mutex or                        // definitive alone
            ($gs_core and $gs_manip) or      // SpyCloud binary sigs (both required)
            $api_reject                      // specific API rejection string
        )
        and vt.metadata.analysis_stats.malicious > 3   // raised from >1 to reduce noise
}


// ── RULE 6: Vidar v18.7 infostealer payload ──────────────────────────────────
//
// UNCHANGED — 17 findings, all actual Vidar samples. No FPs observed.
// Vidar v18.7 uses BOTH Telegram AND Steam Community as dead-drop C2 resolvers.

rule Vidar_v18_Infostealer_Payload {
    meta:
        description = "Vidar v18.7 infostealer — Telegram+Steam dead-drop C2, credential/wallet theft"
        author      = "Trend Micro PH THT"
        family      = "Vidar"
        version     = "v18.7"
        reference   = "https://www.zscaler.com/blogs/security-research/vidar-github-lure"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"

    strings:
        // Dead-drop C2 resolvers — BOTH present in Vidar v18.7
        $c2_tg       = "https://t.me/"                    ascii wide
        $c2_steam    = "steamcommunity.com/profiles/"     ascii wide

        // Chromium localStorage credential theft
        $ldb         = "\\Local Storage\\leveldb"         ascii wide

        // Browser exfil path templates
        $cc          = "\\CC\\%s_%s.txt"                  ascii wide
        $autofill    = "\\Autofill\\%s_%s.txt"            ascii wide
        $dl          = "\\Downloads\\%s_%s.txt"           ascii wide

        // Crypto wallet targets
        $exodus      = "Exodus\\exodus.wallet"            ascii wide
        $electrum    = "Electrum\\wallets"                ascii wide

        // Vidar version/debug artifact (optional — sometimes stripped)
        $vidar_str   = "Vidar" ascii wide nocase

        // Known C2 IPs (Zscaler ThreatLabz)
        $c2_ip1      = "147.45.197.92" ascii wide
        $c2_ip2      = "94.228.161.88" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and (
            ($c2_tg and $c2_steam) or                      // v18.7 signature C2 pattern
            2 of ($ldb, $cc, $autofill, $dl) or            // browser exfil templates
            (
                any of ($exodus, $electrum)
                and any of ($c2_tg, $c2_steam, $c2_ip1, $c2_ip2)
            ) or
            (
                $vidar_str                                 // "Vidar" version/debug string
                and any of ($c2_tg, $c2_steam, $c2_ip1, $c2_ip2)
            )
        )
        and vt.metadata.analysis_stats.malicious > 2
}

// ── Rule 7 (TradeAI_Campaign_IOC_Any) REMOVED ───────────────────────────────
// Produced 77 FPs in 1 day — snippet.host and C2 IPs appear in legitimate
// anti-malware tools' IOC databases (e.g., Adaware Privacy).
// Keep in retrohunt_dropper.yar for retrohunt-only use, not livehunt.
