// ═══════════════════════════════════════════════════════════════════════════
// RULESET  : claude_lure_payload
// Author   : Trend Micro PH THT — Jacob Santos
// TLP      : GREEN
// Purpose  : VT Livehunt — catch the actual malware payloads as standalone files:
//            (a) GhostSocks SOCKS5 proxy DLL/EXE (Golang, garble-obfuscated)
//            (b) Vidar v18.7 infostealer (extracted/dropped form)
//            (c) Broad IOC net for any file containing campaign infrastructure
//
// Create this ruleset in VT as: claude_lure_payload
// ═══════════════════════════════════════════════════════════════════════════

import "vt"
import "pe"


// ── RULE 5: GhostSocks SOCKS5 proxy — standalone Golang binary ───────────────
// Catches the GhostSocks DLL/EXE when submitted to VT separately from the dropper.
// GhostSocks is 32-bit or standalone EXE, written in Go, obfuscated with garble.
// Mutex "start to run" is definitive and can be used alone.
// SpyCloud Labs byte signatures ($gs_core, $gs_manip) are extracted from binary analysis.
// C2 check-in uses port 30001; API rejects unauthorized connections with specific string.

rule GhostSocks_GoLang_SOCKS5_Proxy {
    meta:
        description = "GhostSocks SOCKS5 backconnect proxy — Golang/garble, 'start to run' mutex"
        author      = "Trend Micro PH THT (SpyCloud Labs + Synthient sigs adapted)"
        family      = "GhostSocks"
        reference   = "https://spycloud.com/blog/on-the-hunt-for-ghostsocks/"
        reference2  = "https://synthient.com/blog/ghostsocks-from-initial-access-to-residential-proxy"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"

    strings:
        // DEFINITIVE — mutex prevents duplicate instances; unique string
        $mutex         = "start to run" ascii wide

        // SpyCloud Labs binary signatures (core GhostSocks routine)
        $gs_core       = { 89 EE C1 E5 02 39 EB 77 }
        $gs_manip      = { 0F B6 ?? ?? ?? 0F B6 ?? ?? ?? 31 CA 88 ?? ?? ?? 40 }

        // Golang SOCKS5 library artifacts (sometimes survive garble)
        $go_socks5     = "go-socks5" ascii
        $go_yamux      = "yamux"     ascii

        // C2 check-in JSON payload field names
        $cfg_affiliate = "affiliate"     ascii
        $cfg_version   = "build_version" ascii
        $cfg_proxy_u   = "proxy_user"    ascii
        $cfg_proxy_p   = "proxy_pass"    ascii

        // API rejection string — Infrawatch network detection reference
        $api_reject    = "Forbidden: Invalid API Key" ascii

        // Dynamic C2 switching response field
        $relay         = "relay_server" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and (
            $mutex or                                          // definitive alone
            ($gs_core and $gs_manip) or                       // SpyCloud binary sigs
            $api_reject or                                     // network detection sig
            ($go_socks5 and $go_yamux) or                     // Golang SOCKS5 libs
            $relay or                                          // dynamic C2 response field
            2 of ($cfg_affiliate, $cfg_version, $cfg_proxy_u, $cfg_proxy_p)
        )
        and vt.metadata.analysis_stats.malicious > 1
}


// ── RULE 6: Vidar v18.7 infostealer payload ──────────────────────────────────
// Catches Vidar when submitted to VT as a standalone file (e.g., extracted
// from a memory dump, or the dropped %TEMP%\System\svchost.exe).
// Vidar v18.7 uses BOTH Telegram AND Steam Community as dead-drop C2 resolvers —
// this combination is definitive for this version.

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


// ── RULE 7: Broad IOC net — any PE with known campaign infrastructure ─────────
// High recall, lower precision. Catches any PE referencing known C2, dropper
// filenames, or the campaign-unique log file. Use as a supplement; review all hits.

rule TradeAI_Campaign_IOC_Any {
    meta:
        description = "Broad catch — any PE with TradeAI/ClaudeCode/OpenClaw campaign IOCs"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI rotating lure"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "HIGH"

    strings:
        // Known C2 IPs (Zscaler IOCs + new discovery)
        $c2_ip1   = "147.45.197.92"  ascii wide
        $c2_ip2   = "94.228.161.88"  ascii wide
        $c2_ip3   = "45.55.35.48"    ascii wide   // steamhostserver.cc

        // Known C2 + dead-drop domains
        $c2_dom1  = "rti.cargomanbd.com"  ascii wide
        $c2_dom2  = "steamhostserver.cc"  ascii wide   // new IOC, first documented here
        $ddr      = "snippet.host"        ascii wide   // dead-drop resolver

        // Known malware filenames
        $fn1      = "ClaudeCode_x64.exe"  ascii wide nocase
        $fn2      = "TradeAI.exe"         ascii wide nocase
        $fn3      = "openclaudecode.exe"  ascii wide nocase

        // Campaign-unique log filename (high specificity, not a common name)
        $log      = "upd152b_log.txt"  ascii wide

        // Stealth Packer definitive mutex
        $packer   = "StealthPackerMutex"  ascii wide

    condition:
        uint16(0) == 0x5A4D
        and (
            any of ($c2_ip*) or
            any of ($c2_dom*) or
            $ddr or
            $log or
            $packer or
            any of ($fn*)
        )
}
