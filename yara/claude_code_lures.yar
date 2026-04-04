// ═══════════════════════════════════════════════════════════════════════════
// RULESET  : claude_code_lures
// Author   : Trend Micro PH THT — Jacob Santos
// TLP      : GREEN
// Purpose  : VT Livehunt — catch Vidar v18.7 + GhostSocks SOCKS5 payloads
//            delivered via TradeAI / ClaudeCode / OpenClaw rotating lure
//
// Campaign brief:
//   Threat actor distributes 100MB+ archives (GitHub Releases) containing
//   Rust-compiled droppers renamed to brand lures (ClaudeCode_x64.exe,
//   NeuralUpdater.exe, VersionPulse.exe, etc.).  The dropper calls a dead-drop
//   resolver (pastebin.com / snippet.host) to fetch the payload URL, then
//   downloads and executes either:
//     (a) Vidar v18.7 infostealer — steals creds, wallets, cookies
//     (b) GhostSocks SOCKS5 proxy — turns victim into residential proxy node
//   A second loader chain uses "Stealth Packer" (VS2019/VS2022 builder) that
//   packs the payload into a huge .rsrc section and uses a .fptable PE section.
//
// Sample analysis basis:
//   3d85ed30ec30155a8812ddf0fa9a57fc8e239215c6f30c989a28018548827e41  Rust dropper
//   5a4033aa864e8c6e3cf8c973b426aff8128a3397feb65fc5de4e3a9fb41ebb6e  Rust dropper
//   fd67063ffb0bcde44dca5fea09cc0913150161d7cb13cffc2a001a0894f12690  Rust dropper
//   d5dffba463beae207aee339f88a18cfcd2ea2cd3e36e98d27297d819a1809846  Rust dropper
//   c3eede99459a16ca90f7cc62cdae861967413dc1cb5d6393e86f146beaef734f  Stealth Packer/GhostSocks
//   623c2e578d3323a07268dafa6d2da21abb1356fa6e28acb6bbeca28420ffd392  Packed loader/Vidar
//   984e415b8002eab2bc3a75f8f5fa6c1107f547a6644ead3703cecf7426a19c70  Packed loader/Vidar
//
// References:
//   Trend Micro (2026-04-03): Weaponizing Trust Signals
//   Zscaler ThreatLabz: IOCs idbzoomh/my3jie
//   Huntress: OpenClaw/GhostSocks campaign (Feb 2026)
//   SpyCloud Labs: GhostSocks binary analysis
// ═══════════════════════════════════════════════════════════════════════════

import "vt"
import "pe"


// ── RULE 1: Rust dropper — dead-drop resolver + masquerade persistence ───────
//
// These are the executables extracted from the large dropper archives.
// Key behaviour: contacts snippet.host (and sometimes pastebin.com) to
// retrieve a download URL for Vidar/GhostSocks payload. Uses consistent
// masquerade filenames and scheduled task names across all variants.
//
// Detection strength: HIGH
//   - snippet.host is not used by legitimate software
//   - upd152b_log.txt is campaign-unique
//   - _RDATA confirms Rust binary
//   - File size range is tight (1–8 MB)

rule TradeAI_Rust_Dropper_DeadDrop {
    meta:
        description = "TradeAI rotating lure — Rust dropper with dead-drop C2 resolver (snippet.host / pastebin)"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI rotating lure (ClaudeCode / NeuralUpdater / VersionPulse / AetherSync)"
        family      = "Rust dropper"
        samples     = "3d85ed30, 5a4033aa, fd67063f, d5dffba4"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"

    strings:
        // Dead-drop resolvers — used to fetch payload URL at runtime
        // snippet.host is the stronger unique signal; pastebin alone has FPs
        $ddr_snippet  = "snippet.host"  ascii wide
        $ddr_pastebin = "pastebin.com"  ascii wide

        // Campaign-unique log filenames written to %TEMP% during execution
        $log_upd  = "upd152b_log.txt"  ascii wide   // seen in 4/4 Rust dropper samples
        $log_sys  = "system_log.txt"   ascii wide   // seen in 3/4 samples

        // Masquerade dropped executable names — written to %ProgramData%
        $mask_adobe  = "AdobeCloudSync.exe"   ascii wide
        $mask_chrome = "ChromeSyncHost.exe"   ascii wide
        $mask_edge   = "EdgeUpdateSvc.exe"    ascii wide
        $mask_intel  = "IntelGraphicsHost.exe" ascii wide
        $mask_od     = "OneDriveSync.exe"     ascii wide

        // Scheduled task names used for SYSTEM-level persistence
        $task_telem  = "TelemetrySyncSvc"   ascii wide
        $task_nvidia = "NvidiaDisplaySys"   ascii wide
        $task_chrome = "ChromeUpdateSvc"    ascii wide
        $task_edge   = "EdgeUpdateHelper"   ascii wide
        $task_od     = "OneDriveSyncHost"   ascii wide

        // Registry run key name used across all samples
        $reg_persist = "WindowsSystemUpdate" ascii wide

        // Mutex naming pattern — "Global\App_XXXXXXXX" (8 lowercase hex)
        // Not a fixed string but the prefix is consistent
        $mutex_pfx = "Global\\App_" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 1MB and filesize < 8MB
        // Must have the dead-drop snippet.host reference
        and $ddr_snippet
        // Plus at least one additional campaign-specific indicator
        and (
            $log_upd or
            $log_sys or
            2 of ($mask_*) or
            1 of ($task_*) or
            $reg_persist
        )
        and vt.metadata.analysis_stats.malicious > 3
}


// ── RULE 2: Rust dropper — broad dead-drop variant (lower confidence) ────────
//
// Catches samples where only pastebin is present (no snippet.host yet)
// and campaign log files. Lower threshold but useful for emerging variants.

rule TradeAI_Rust_Dropper_Broad {
    meta:
        description = "TradeAI Rust dropper variant — pastebin dead-drop + campaign persistence TTP"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI rotating lure"
        family      = "Rust dropper (variant)"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "HIGH"

    strings:
        $ddr_pastebin = "pastebin.com" ascii wide
        $log_upd      = "upd152b_log.txt" ascii wide
        $log_sys      = "system_log.txt"  ascii wide
        $mask_adobe   = "AdobeCloudSync.exe"  ascii wide
        $mask_chrome  = "ChromeSyncHost.exe"  ascii wide
        $mask_edge    = "EdgeUpdateSvc.exe"   ascii wide
        $task_telem   = "TelemetrySyncSvc"   ascii wide
        $task_nvidia  = "NvidiaDisplaySys"   ascii wide
        $reg_persist  = "WindowsSystemUpdate" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 1MB and filesize < 8MB
        and pe.section_index("_RDATA") >= 0   // Rust binary marker — unique PE section
        and $ddr_pastebin
        and (
            $log_upd or
            2 of ($mask_*) or
            1 of ($task_*) or
            $reg_persist
        )
        and vt.metadata.analysis_stats.malicious > 2
}


// ── RULE 3: Stealth Packer — GhostSocks SOCKS5 proxy loader ─────────────────
//
// Detected in sample c3eede99 (~update.tmp.exe).
// The packer injects GhostSocks into memory, creates hidden scheduled tasks,
// opens firewall ports 57001/57002 for the SOCKS5 tunnel, and achieves
// persistence via WinLogon Userinit abuse.
//
// New C2 domain discovered: steamhostserver.cc (45.55.35.48)
// — NOT yet in any public TI report as of 2026-04-04
//
// Detection strength: CRITICAL
//   - StealthPackerMutex_9A8B7C is unique to this packer family
//   - Firewall rule names with exact port numbers are campaign-specific

rule TradeAI_StealthPacker_GhostSocks {
    meta:
        description = "Stealth Packer loading GhostSocks SOCKS5 proxy — ports 57001/57002 + WinLogon persistence"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI / OpenClaw rotating lure"
        family      = "Stealth Packer → GhostSocks"
        sample      = "c3eede99459a16ca90f7cc62cdae861967413dc1cb5d6393e86f146beaef734f"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"
        new_ioc     = "steamhostserver.cc resolves to 45.55.35.48 — not yet public"

    strings:
        // DEFINITIVE: packer mutex string — unique to Stealth Packer family
        $mutex_packer  = "StealthPackerMutex" ascii wide

        // Hex mutex observed in sandbox (short format variant)
        $mutex_hex     = "c10f845f3942" ascii

        // Firewall rules created to allow SOCKS5 proxy ports outbound/inbound
        // Exact names observed in sandbox command executions
        $fw_out_57001  = "Telemetry_Out_57001" ascii wide
        $fw_in_57002   = "Telemetry_In_57002"  ascii wide
        $fw_out_57002  = "Telemetry_Out_57002" ascii wide
        $fw_in_57001   = "Telemetry_In_57001"  ascii wide

        // Firewall rule name prefix (catches port number variants)
        $fw_prefix     = "Telemetry_Out_57" ascii wide

        // NEW C2 domain — only seen in this sample, not in public reports
        $c2_new_domain = "steamhostserver.cc" ascii wide

        // Known Zscaler-documented C2 infrastructure
        $c2_known_dom  = "rti.cargomanbd.com" ascii wide
        $c2_known_ip1  = "147.45.197.92" ascii wide
        $c2_known_ip2  = "94.228.161.88" ascii wide

        // Scheduled task used for persistence (SoftwareProtectionPlatform path abuse)
        $task_svcrestart = "SvcRestartTask" ascii wide

        // Dropped proxy component filename
        $drop_svchost  = "svc_host.exe" ascii wide

        // WinLogon Userinit persistence string (appended path)
        $userinit      = "userinit.exe,," ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and (
            $mutex_packer or                          // Definitive — use alone
            (2 of ($fw_out_57001, $fw_in_57002, $fw_out_57002, $fw_in_57001)) or
            ($fw_prefix and (any of ($c2_*))) or
            ($c2_new_domain) or                       // New C2 — high confidence
            ($userinit and $drop_svchost)
        )
        and vt.metadata.analysis_stats.malicious > 1
}


// ── RULE 4: Packed loader — Vidar stealer container (.fptable + large .rsrc) ─
//
// Detected in QuantumEdge (623c2e57) and SentinelAI (984e415b).
// Both built with identical compiler ID profile → same Stealth Packer builder.
// The large .rsrc section (1.4–5.5 MB) contains the encrypted Vidar payload.
// The .fptable section is an unusual PE section not seen in legitimate software.
// After execution: drops svchost.exe to %AppData%\Local\Temp\System\,
// persists via Run key {AudioService}, mutex {WinService9376}.
//
// Detection strength: HIGH
//   - .fptable section is non-standard; very rare in benign PE
//   - .rsrc > 1MB combined with malicious detections is strong signal

rule TradeAI_PackedLoader_Vidar_Container {
    meta:
        description = "Stealth Packer container for Vidar v18.7 — .fptable section + oversized .rsrc"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI rotating lure"
        family      = "Stealth Packer → Vidar v18.7"
        samples     = "623c2e578d33, 984e415b8002"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"

    strings:
        // Vidar-specific mutex observed in sandbox — {WinService9376}_XXXXXXXXX
        $vidar_mutex    = "{WinService9376}" ascii wide

        // Vidar persistence registry run key name
        $vidar_reg      = "{AudioService}" ascii wide

        // Dropped Vidar payload path patterns
        $vidar_drop1    = "Local\\Temp\\System\\svchost.exe" ascii wide
        $vidar_drop2    = "Roaming\\Local\\Temp\\System" ascii wide

        // Vidar C2 dead-drop resolver strings (Telegram + Steam)
        $vidar_tg       = "https://t.me/" ascii wide
        $vidar_steam    = "steamcommunity.com/profiles/" ascii wide

        // Vidar exfiltration path templates (from ThreatLabz research)
        $vidar_cc       = "\\CC\\%s_%s.txt"       ascii wide
        $vidar_autofill = "\\Autofill\\%s_%s.txt" ascii wide
        $vidar_dl       = "\\Downloads\\%s_%s.txt" ascii wide

        // Vidar wallet target
        $vidar_exodus   = "Exodus\\exodus.wallet" ascii wide

        // Vidar config file marker
        $vidar_config   = "\\config" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 15MB
        and (
            // Packed form: detect by PE structure (.fptable + large .rsrc)
            (
                pe.section_index(".fptable") >= 0
                and for any i in (0..pe.number_of_sections - 1): (
                    pe.sections[i].name == ".rsrc"
                    and pe.sections[i].virtual_size > 1000000
                )
            )
            or
            // Unpacked/extracted form: detect by Vidar-specific strings
            (
                $vidar_mutex or
                $vidar_reg or
                any of ($vidar_drop*) or
                (any of ($vidar_tg, $vidar_steam) and 1 of ($vidar_cc, $vidar_autofill, $vidar_dl)) or
                $vidar_exodus
            )
        )
        and vt.metadata.analysis_stats.malicious > 3
}


// ── RULE 5: GhostSocks binary — unpacked Golang SOCKS5 proxy ────────────────
//
// Detects the GhostSocks payload itself when submitted to VT separately.
// Based on SpyCloud Labs + Synthient research + Infrawatch network YARA.
// GhostSocks is Golang, obfuscated with garble, 32-bit DLL or standalone EXE.
// Mutex "start to run" prevents duplicate instances.
// Check-in uses JSON: {"affiliate":…, "build_version":…} to port 30001.
// C2 infra predominantly on AS216071 (VDSina).
//
// Detection strength: CRITICAL (mutex string is definitive)

rule GhostSocks_GoLang_SOCKS5_Proxy {
    meta:
        description = "GhostSocks SOCKS5 backconnect proxy payload — Golang/garble, MaaS"
        author      = "Trend Micro PH THT (adapted from SpyCloud Labs + Synthient)"
        family      = "GhostSocks"
        reference   = "https://spycloud.com/blog/on-the-hunt-for-ghostsocks/"
        reference2  = "https://synthient.com/blog/ghostsocks-from-initial-access-to-residential-proxy"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"

    strings:
        // DEFINITIVE: mutex prevents duplicate instances — unique string
        $mutex          = "start to run" ascii wide

        // GhostSocks core byte manipulation routine (SpyCloud signature)
        $gs_core        = { 89 EE C1 E5 02 39 EB 77 }

        // GhostSocks byte manipulation pattern (SpyCloud signature)
        $gs_manip       = { 0F B6 ?? ?? ?? 0F B6 ?? ?? ?? 31 CA 88 ?? ?? ?? 40 }

        // Golang SOCKS5 library identifiers (garble-obfuscated but sometimes visible)
        $go_socks5      = "go-socks5" ascii
        $go_yamux       = "yamux"     ascii

        // Check-in JSON payload field names
        $cfg_affiliate  = "affiliate"     ascii
        $cfg_version    = "build_version" ascii
        $cfg_proxy_user = "proxy_user"    ascii
        $cfg_proxy_pass = "proxy_pass"    ascii

        // API key rejection string (Infrawatch network detection reference)
        $api_reject     = "Forbidden: Invalid API Key" ascii

        // SOCKS5 backconnect port (C2 check-in port 30001)
        $port_c2        = "30001" ascii

        // Dynamic C2 switching: relay server response format
        $relay_resp     = "relay_server" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and (
            $mutex or                                   // Definitive alone
            ($gs_core and $gs_manip) or                // SpyCloud binary sigs
            $api_reject or                             // Network detection sig
            ($go_socks5 and $go_yamux) or             // Golang SOCKS5 libs
            (2 of ($cfg_affiliate, $cfg_version, $cfg_proxy_user, $cfg_proxy_pass))
        )
        and vt.metadata.analysis_stats.malicious > 1
}


// ── RULE 6: Vidar v18.7 stealer payload — extracted/standalone ───────────────
//
// Catches the Vidar stealer DLL/EXE when submitted to VT as a standalone file
// (e.g., extracted from a memory dump or dropped file analysis).
// Vidar v18.7 uses Telegram + Steam Community profiles as dead-drop resolvers
// for its C2 address — this is its defining characteristic.
//
// Detection strength: HIGH

rule Vidar_v18_Infostealer_Payload {
    meta:
        description = "Vidar v18.7 infostealer — Telegram/Steam dead-drop C2 resolver, credential/wallet theft"
        author      = "Trend Micro PH THT"
        family      = "Vidar"
        version     = "v18.7"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"

    strings:
        // Dead-drop C2 resolvers — BOTH used together in v18.7
        $c2_tg      = "https://t.me/" ascii wide
        $c2_steam   = "steamcommunity.com/profiles/" ascii wide

        // Browser credential exfil path templates
        $ldb        = "\\Local Storage\\leveldb" ascii wide   // Chromium localStorage
        $cc         = "\\CC\\%s_%s.txt"          ascii wide   // Credit cards
        $autofill   = "\\Autofill\\%s_%s.txt"   ascii wide   // Autofill
        $dl         = "\\Downloads\\%s_%s.txt"   ascii wide   // Downloads

        // Cryptocurrency wallet targets
        $exodus     = "Exodus\\exodus.wallet" ascii wide
        $electrum   = "Electrum\\wallets"     ascii wide

        // Vidar version string or debug artifact (sometimes visible)
        $vidar_str  = "Vidar" ascii wide nocase

        // Known C2 IPs (Zscaler ThreatLabz IOCs)
        $c2_ip1     = "147.45.197.92" ascii wide
        $c2_ip2     = "94.228.161.88" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and (
            // Telegram + Steam combo is Vidar v18.7's signature C2 pattern
            ($c2_tg and $c2_steam) or
            // Browser exfil templates
            (2 of ($ldb, $cc, $autofill, $dl)) or
            // Wallet + C2
            (any of ($exodus, $electrum) and any of ($c2_tg, $c2_steam, $c2_ip1, $c2_ip2))
        )
        and vt.metadata.analysis_stats.malicious > 2
}


// ── RULE 7: Campaign-wide IOC net — any binary with known campaign strings ───
//
// Broad catch: any PE containing known campaign infrastructure, filenames,
// or unique log file name. High recall, lower precision — use as a supplement.

rule TradeAI_Campaign_IOC_Any {
    meta:
        description = "Any PE file containing known TradeAI/ClaudeCode/OpenClaw campaign IOCs"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI rotating lure"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "HIGH"

    strings:
        // Known C2 IPs (Zscaler)
        $c2_ip1  = "147.45.197.92"  ascii wide
        $c2_ip2  = "94.228.161.88"  ascii wide

        // Known C2 domains (Zscaler + new discovery)
        $c2_dom1 = "rti.cargomanbd.com"  ascii wide
        $c2_dom2 = "steamhostserver.cc"  ascii wide   // NEW — first documented here

        // Dead-drop resolver unique to campaign (more FP-resistant than pastebin)
        $ddr     = "snippet.host"  ascii wide

        // Known malware filenames
        $fn1     = "ClaudeCode_x64.exe"  ascii wide nocase
        $fn2     = "TradeAI.exe"         ascii wide nocase
        $fn3     = "openclaudecode.exe"  ascii wide nocase

        // Campaign-unique log filename — high specificity
        $log_upd = "upd152b_log.txt"  ascii wide

        // Stealth Packer definitive identifier
        $packer  = "StealthPackerMutex"  ascii wide

    condition:
        uint16(0) == 0x5A4D
        and (
            any of ($c2_ip*) or
            any of ($c2_dom*) or
            $log_upd or
            $packer or
            any of ($fn*)
        )
}
