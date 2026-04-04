// ═══════════════════════════════════════════════════════════════════════════
// RULESET  : claude_lure_packer
// Author   : Trend Micro PH THT — Jacob Santos
// TLP      : GREEN
// Purpose  : VT Livehunt — catch Stealth Packer samples:
//            (a) GhostSocks SOCKS5 loader (~update.tmp.exe, c3eede99)
//            (b) Vidar container loader (QuantumEdge/SentinelAI, 623c2e57/984e415b)
//
// Create this ruleset in VT as: claude_lure_packer
// ═══════════════════════════════════════════════════════════════════════════

import "vt"
import "pe"


// ── RULE 3: Stealth Packer → GhostSocks SOCKS5 proxy loader ─────────────────
// Sample c3eede99 (~update.tmp.exe) — CRITICAL definitive indicators.
// StealthPackerMutex_9A8B7C is unique to this packer family.
// Firewall rules for ports 57001/57002 are the SOCKS5 proxy tunnel.
// New C2 domain steamhostserver.cc (45.55.35.48) — not in public reports yet.

rule TradeAI_StealthPacker_GhostSocks {
    meta:
        description = "Stealth Packer → GhostSocks SOCKS5 proxy — firewall tunnel + WinLogon persistence"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI / OpenClaw rotating lure"
        sample      = "c3eede99459a16ca90f7cc62cdae861967413dc1cb5d6393e86f146beaef734f"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"
        new_ioc     = "steamhostserver.cc:45.55.35.48 — first documented 2026-04-04"

    strings:
        // DEFINITIVE — unique to Stealth Packer family
        $mutex_packer    = "StealthPackerMutex" ascii wide

        // Firewall rules for SOCKS5 tunnel (ports 57001/57002)
        $fw_out_57001    = "Telemetry_Out_57001" ascii wide
        $fw_in_57002     = "Telemetry_In_57002"  ascii wide
        $fw_out_57002    = "Telemetry_Out_57002" ascii wide
        $fw_in_57001     = "Telemetry_In_57001"  ascii wide
        $fw_prefix       = "Telemetry_Out_57"    ascii wide   // catches port variants

        // NEW C2 domain — only seen in this sample, not yet public
        $c2_new          = "steamhostserver.cc"  ascii wide

        // Known Zscaler C2 infrastructure
        $c2_known_dom    = "rti.cargomanbd.com"  ascii wide
        $c2_known_ip1    = "147.45.197.92"       ascii wide
        $c2_known_ip2    = "94.228.161.88"       ascii wide

        // Persistence: SoftwareProtectionPlatform scheduled task abuse
        $task_svc        = "SvcRestartTask" ascii wide

        // Dropped SOCKS5 component filename
        $drop_svchost    = "svc_host.exe"      ascii wide
        $drop_update     = "~update.tmp.exe"   ascii wide

        // WinLogon Userinit abuse for persistence
        $userinit        = "userinit.exe,," ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and (
            $mutex_packer or                                   // definitive alone
            (2 of ($fw_out_57001, $fw_in_57002, $fw_out_57002, $fw_in_57001)) or
            ($fw_prefix and any of ($c2_known_dom, $c2_known_ip1, $c2_known_ip2, $c2_new)) or
            $c2_new or                                         // new C2 = high confidence
            $task_svc or                                       // SvcRestartTask persistence
            ($userinit and any of ($drop_svchost, $drop_update))
        )
        and vt.metadata.analysis_stats.malicious > 1
}


// ── RULE 4: Stealth Packer → Vidar stealer container (.fptable + large .rsrc) ─
// Samples 623c2e57 (QuantumEdge) and 984e415b (SentinelAI).
// Identical compiler profile → same Stealth Packer builder.
// .fptable is a non-standard PE section not found in legitimate software.
// .rsrc section holds the encrypted Vidar payload (1.4MB – 5.5MB).

rule TradeAI_PackedLoader_Vidar_Container {
    meta:
        description = "Stealth Packer container for Vidar v18.7 — .fptable section + oversized .rsrc"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI rotating lure"
        samples     = "623c2e578d33, 984e415b8002"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"

    strings:
        // Vidar mutex — {WinService9376}_XXXXXXXXX
        $vidar_mutex  = "{WinService9376}"            ascii wide
        $vidar_reg    = "{AudioService}"              ascii wide   // persistence run key

        // Dropped payload path — %AppData%\Local\Temp\System\svchost.exe
        $vidar_drop1  = "Local\\Temp\\System\\svchost.exe"   ascii wide
        $vidar_drop2  = "Roaming\\Local\\Temp\\System"       ascii wide

        // Vidar C2 dead-drop (Telegram + Steam)
        $vidar_tg     = "https://t.me/"                      ascii wide
        $vidar_steam  = "steamcommunity.com/profiles/"       ascii wide

        // Vidar exfiltration path templates
        $vidar_cc     = "\\CC\\%s_%s.txt"       ascii wide
        $vidar_autof  = "\\Autofill\\%s_%s.txt" ascii wide
        $vidar_dl     = "\\Downloads\\%s_%s.txt" ascii wide

        // Crypto wallet target
        $vidar_exodus = "Exodus\\exodus.wallet" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 15MB
        and (
            // Packed form — detect by PE structure (.fptable + huge .rsrc)
            (
                pe.section_index(".fptable") >= 0
                and for any section in pe.sections : (
                    section.name == ".rsrc"
                    and section.virtual_size > 1000000
                )
            )
            or
            // Unpacked/extracted — detect Vidar strings directly
            $vidar_mutex or
            $vidar_reg or
            any of ($vidar_drop*) or
            (
                any of ($vidar_tg, $vidar_steam)
                and 1 of ($vidar_cc, $vidar_autof, $vidar_dl)
            ) or
            $vidar_exodus
        )
        and vt.metadata.analysis_stats.malicious > 3
}
