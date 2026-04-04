// ═══════════════════════════════════════════════════════════════════════════
// RULESET  : claude_lure_dropper
// Author   : Trend Micro PH THT — Jacob Santos
// TLP      : GREEN
// Purpose  : VT Livehunt — catch Rust dropper EXEs that use dead-drop resolvers
//            (snippet.host / pastebin.com) to fetch Vidar/GhostSocks payload URL.
//            These are the executables extracted from the 100MB+ lure archives.
//
// Create this ruleset in VT as: claude_lure_dropper
// ═══════════════════════════════════════════════════════════════════════════

import "vt"
import "pe"


// ── RULE 1 (HIGH confidence) ─────────────────────────────────────────────────
// Requires snippet.host (low FP rate) + at least one campaign-specific TTP.
// Catches: NeuralUpdater, UpdaterForge, VersionPulse, AetherSync, and variants.

rule TradeAI_Rust_Dropper_DeadDrop {
    meta:
        description = "Rust dropper — snippet.host dead-drop C2 resolver + campaign masquerade TTPs"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI rotating lure"
        samples     = "3d85ed30, 5a4033aa, fd67063f, d5dffba4"
        tlp         = "GREEN"
        date        = "2026-04-04"
        severity    = "CRITICAL"

    strings:
        $ddr_snippet  = "snippet.host"  ascii wide   // dead-drop; not used by legit software
        $ddr_pastebin = "pastebin.com"  ascii wide   // secondary dead-drop

        $log_upd  = "upd152b_log.txt"  ascii wide   // campaign-unique log, seen across all samples
        $log_sys  = "system_log.txt"   ascii wide

        $mask_adobe  = "AdobeCloudSync.exe"    ascii wide
        $mask_chrome = "ChromeSyncHost.exe"    ascii wide
        $mask_edge   = "EdgeUpdateSvc.exe"     ascii wide
        $mask_intel  = "IntelGraphicsHost.exe" ascii wide
        $mask_od     = "OneDriveSync.exe"      ascii wide

        $task_telem  = "TelemetrySyncSvc"  ascii wide
        $task_nvidia = "NvidiaDisplaySys"  ascii wide
        $task_chrome = "ChromeUpdateSvc"   ascii wide

        $reg_persist = "WindowsSystemUpdate" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 1MB and filesize < 8MB
        and $ddr_snippet
        and (
            $log_upd or
            $log_sys or
            2 of ($mask_*) or
            1 of ($task_*) or
            $reg_persist
        )
        and vt.metadata.analysis_stats.malicious > 3
}


// ── RULE 2 (MEDIUM confidence) ───────────────────────────────────────────────
// Broader variant: pastebin + _RDATA Rust section. More false positives possible
// since pastebin is used by many programs — only fire when _RDATA confirms Rust.

rule TradeAI_Rust_Dropper_Broad {
    meta:
        description = "Rust dropper variant — pastebin dead-drop + Rust _RDATA section + campaign TTPs"
        author      = "Trend Micro PH THT"
        campaign    = "TradeAI rotating lure (emerging variants)"
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
        and pe.section_index("_RDATA") >= 0   // unique Rust binary marker
        and $ddr_pastebin
        and (
            $log_upd or
            2 of ($mask_*) or
            1 of ($task_*) or
            $reg_persist
        )
        and vt.metadata.analysis_stats.malicious > 2
}
