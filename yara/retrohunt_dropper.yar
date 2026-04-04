// ═══════════════════════════════════════════════════════════════════════════
// RULE     : Vidar_v18_7_GhostSocks_Combo_ClaudeCode_OpenClaw
// Author   : Trend Micro PH THT — Jacob Santos
// TLP      : GREEN
// Use      : VT RETROHUNT only — targets droppers and combined payload files
//            which may exceed 100MB in archive form but are <15MB as EXEs.
//
// IMPORTANT: This rule is NOT suitable for livehunt.
//   The $gs1 "POST" string alone causes massive false positives in livehunt.
//   Use the livehunt ruleset (claude_code_lures.yar) for real-time detection.
//
// What it catches:
//   - Rust dropper EXEs that contain both GhostSocks + Vidar strings
//     (i.e., the combined payload EXE extracted from the archive)
//   - Rust loader binaries that reference known campaign filenames
//     (cloudvideo.exe, serverdrive.exe, svc_service.exe) alongside Vidar
//
// Condition fix vs original:
//   Original had a YARA operator precedence issue — the `or` branch for $rust*
//   lacked uint16/filesize guards. Fixed by wrapping both branches in parens
//   so the PE/filesize checks apply to both.
//
// Samples this would catch retrospectively:
//   3d85ed30ec30155a8812ddf0fa9a57fc8e239215c6f30c989a28018548827e41
//   5a4033aa864e8c6e3cf8c973b426aff8128a3397feb65fc5de4e3a9fb41ebb6e
//   fd67063ffb0bcde44dca5fea09cc0913150161d7cb13cffc2a001a0894f12690
//   d5dffba463beae207aee339f88a18cfcd2ea2cd3e36e98d27297d819a1809846
// ═══════════════════════════════════════════════════════════════════════════

rule Vidar_v18_7_GhostSocks_Combo_ClaudeCode_OpenClaw
{
    meta:
        description = "Vidar v18.7 + GhostSocks dropper combo — ClaudeCode / OpenClaw lure campaign"
        author      = "Trend Micro PH THT"
        tlp         = "GREEN"
        date        = "2026-04-04"
        use         = "retrohunt"
        severity    = "CRITICAL"

    strings:
        // === GhostSocks proxy component (SpyCloud signature + campaign-specific) ===
        $gs1 = "POST" fullword ascii                             // generic — only use in combo
        $gs2 = { 89 EE C1 E5 02 39 EB 77 }                     // GhostSocks core routine (SpyCloud)
        $gs3 = { 0F B6 ?? ?? ?? 0F B6 ?? ?? ?? 31 CA 88 ?? ?? ?? 40 }  // byte manipulation

        // === Vidar v18.7 stealer strings (Telegram + Steam dead-drop C2 resolver) ===
        $vidar1 = "https://t.me/" ascii wide
        $vidar2 = "steamcommunity.com/profiles/" ascii wide
        $vidar3 = "%s\\%s\\Local Storage\\leveldb" ascii wide   // Chromium localStorage theft
        $vidar4 = "\\Autofill\\%s_%s.txt" ascii wide
        $vidar5 = "\\Downloads\\%s_%s.txt" ascii wide
        $vidar6 = "\\CC\\%s_%s.txt" ascii wide                  // credit card exfil
        $vidar7 = "Exodus\\exodus.wallet" ascii wide             // crypto wallet target
        $vidar8 = "Vidar" ascii wide nocase                     // version string or debug artifact

        // === Rust dropper / loader strings in ClaudeCode_x64.exe + OpenClaw ===
        $rust1 = "ClaudeCode_x64" ascii wide nocase
        $rust2 = "OpenClaw"       ascii wide nocase
        $rust3 = "cloudvideo.exe"   ascii wide                  // Vidar-downloaded component
        $rust4 = "serverdrive.exe"  ascii wide                  // Vidar-downloaded component
        $rust5 = "svc_service.exe"  ascii wide                  // Vidar-downloaded component

    condition:
        uint16(0) == 0x5A4D                                     // PE file (MZ header)
        and filesize < 15MB                                     // typical dropper/payload size
        and (
            (2 of ($gs*) and 3 of ($vidar*))                   // GhostSocks + Vidar combined
            or
            (all of ($rust*) and any of ($vidar*))             // Rust dropper + Vidar payload
        )
}
