#!/usr/bin/env python3
"""
Ingest known IOCs from Trend Micro published research as COVERED/PROCESSED findings.

Sources:
  1. Trend Micro IOC list (weaponizing-trust-signals-claude-code.txt) — SHA256
  2. Additional SHA1 hashes provided by Jacob Santos (PH THT)

All entries are stored as platform='vt_known_ioc' with dismissed=False.
They appear in the VT Files tab with a COVERED badge so analysts can see what
is already processed vs what needs investigation.

Usage:
    SUPABASE_URL=... SUPABASE_SERVICE_KEY=... VT_API_KEY=... python ingest_known_iocs.py
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx
from supabase import create_client   # sync client — no await needed on .execute()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("ioc-ingest")

VT_API_KEY    = os.environ["VT_API_KEY"]
SUPABASE_URL  = os.environ["SUPABASE_URL"]
SUPABASE_KEY  = os.environ["SUPABASE_SERVICE_KEY"]
VT_BASE       = "https://www.virustotal.com/api/v3"

# ── Known SHA256s from Trend Micro research (with file name + detection) ─────

TM_SHA256_IOCS = [
    # ClaudeCode_x64.exe dropper variants
    ("17145a933525ca8a6f29a818cf0fd94c37f20836090791bec349ae6e705670d4", "ClaudeCode_x64.exe",    "TrojanSpy.Win64.VIDAR.CLB", "Dropper"),
    ("52e83c718ca96a12b98c5b31af177204145837f4208b0ee0c8e9c2b454795a64", "ClaudeCode_x64.exe",    "TrojanSpy.Win64.VIDAR.CLA", "Dropper"),
    ("7d5e84dd59165422f31a5a0e53aabba657a6fbccc304e8649f72d49e468ae91a", "ClaudeCode_x64.exe",    "TrojanSpy.Win64.VIDAR.CLC", "Dropper"),
    ("80920e8843ead75c58d56f55d351dbff01ccf9f28090e401479f21d651190b41", "ClaudeCode_x64.exe",    "TrojanSpy.Win64.VIDAR.CLC", "Dropper"),
    # TradeAI.exe variants — the rotating campaign dropper
    ("0b6ed577b993fd81e14f9abbef710e881629b8521580f3a127b2184685af7e05", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLU", "Dropper"),
    # 0f69513905b9aeca9ad2659ae16f4363ac03a359abeac9ac05cab70a50f17b65 — excluded (already covered by livehunt)
    ("18467faa4fa10ea30fef2012fbd2c36f31407d0466b4e880dd1b6e1e37c9aff6", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLK", "Dropper"),
    ("249058ce8dc6e74cff9fb84d4d32c82e371265b40d02bb70b7955dceea008139", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLD", "Dropper"),
    ("2a4a8f58ad259bde54e9d37cc4a86563797c99a5dc31a0ae39a92f7807b846b9", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLI", "Dropper"),
    ("30be8190db0627a363927be8b8c8f38f31891fb8958b3691944b69533f6770b3", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLT", "Dropper"),
    ("36c4bb55b7e4c072e0cbc344d85b3530aca8f0237cc4669aecdd4dd8f67ab43a", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLM", "Dropper"),
    ("385d00d5dcefa918858e1d2d6623e7d1155f972b694f48944f98fcceb2624211", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLQ", "Dropper"),
    ("44d40a9e59f08252a22939f76c92362c15a1ffab0dd3a4e3414bf4a5adc5d7c4", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLO", "Dropper"),
    ("518ff5fbfa4296abf38dfc342107f70e1491a7460978da6315a75175fb70e2b3", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLS", "Dropper"),
    ("537243230e14fb0f82bee8f51cac2e1d7ae955bb497c78b109972df51690edcf", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLH", "Dropper"),
    ("789835888a76eca8cc9e8625004607be99a90ec9f7a4db06c568a69ccb76bd60", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLE", "Dropper"),
    ("8090c3ecad7e4559ead21be02c564d20329e21fe3f449bcd9dbd8734f041aebd", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLJ", "Dropper"),
    ("87133e737b2892cebee006068b341012e2c07db1526c08d0a13d0e0cf11d25d1", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLN", "Dropper"),
    ("96db6133e7ca04264ffdf18928c394376323c283a82e8106feec2ac28ee21eeb", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLL", "Dropper"),
    ("b73bd2e4cb16e9036aa7125587c5b3289e17e62f8831de1f9709896797435b82", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLR", "Dropper"),
    ("cce96b39831ce36b9fd1262a7cf4024218dbb3e2c7f1829c261cf79e5c9b50a8", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLF", "Dropper"),
    ("f96d80f7702cb1d5a340ab774e759e3357790c131cfac14a018716813dbc54dd", "TradeAI.exe",           "TrojanSpy.Win64.VIDAR.CLP", "Dropper"),
    # Other payload components
    ("40fc240febf2441d58a7e2554e4590e172bfefd289a5d9fa6781de38e266b378", "Suspected PureLogs",    "TrojanSpy.Win32.PURELOGS.E",    "Payload"),
    ("a22ddb3083b62dae7f2c8e1e86548fc71b63b7652b556e50704b5c8908740ed5", "GhostSocks",            "Trojan.Win32.GHOSTSOCKS.B",     "GhostSocks"),
    ("b4554c85f50c56d550d6c572a864deb0442404ddefe05ff27facb3cbfb90b4d6", "Vidar v18.7",           "TrojanSpy.Win64.VIDAR.YXGDCZ",  "Vidar"),
    ("d5dffba463beae207aee339f88a18cfcd2ea2cd3e36e98d27297d819a1809846", "Information Stealer",   "TROJ.Win32.TRX.XXPE50FFF104",   "Payload"),
    ("e13d9304f7ebdab13f6cb6fae3dff3a007c87fed59b0e06ebad3ecfebf18b9fd", "Suspected AMOS",        "—",                             "Payload"),
    ("f03e38e1c39ac52179e43107cf7511b9407edf83c008562250f5f340523b4b51", "Vidar Infostealer",     "TrojanSpy.Win64.VIDAR.YXGBLZ",  "Vidar"),
]

# ── SHA1 hashes provided by Jacob Santos (additional coverage) ────────────────
# These are SHA1 — will be resolved to SHA256 via VT API

JACOB_SHA1S = {
    "Dropper": [
        "15969dbe6f2a483cb3420f0fd2a7333f2b67a852",
        "18cd06002b7c64929cd3a58e1e4e270945b3ed5a",
        "58cba31a731996bcf8b753cd906bb00c4fea64a8",
        "8a6218a523898d3a41d71acff0937d7de990447d",
        "fceccf7c86e02261c138457433f2b9cbb201b688",
        "4c08771b8bd3c3f4620c234aefdefa85d1907ea1",
        "1a32f348e1725bf1c517691093bccc4f11d109ff",
        "cf3eeab39500150d2920f8a911fb772308a1e515",
        "a7753eb9e8b60b2fcc09dd4dc43f39e23f354aa8",
        "0e8a5518b5ebc9ae69f15dc119a87df40003c700",
        "f3e92a21adbfc97eb921126c929cdc06abb7445a",
        "d3c3bbf01fe2bd7d00e898a24d62e427ccdb03c6",
        "97be9c14966e1d8d430b54602013efe7f9139175",
        "54c67ba1bc1e476aada6beddf0f77161ae7696f6",
        "073377a91ef7659fb3f36028702e7b950332a694",
        "2d4a1b989d27646c069fb4172ad50d3e91baeb93",
        "6519d1c0dad441180a3df2ab13a212b7058ef81f",
        "d7e0e2ea88b4c303e3fd8bc32e71d82d785386a2",
        "cd1becd58df8980d09b088712439261ca14d99dd",
        "444dfe6f8e0ebe6ce5b31f5ad46aa2c3da2b7a38",
        "e11604400a68321401bc1aad94eec2d935f6daa4",
        "c39c8f87aca34d26d79cbf24e83f059d1cf50167",
        "ac52f1e823b15e71298ab5fde58772c82bfc0818",
        "1695147110132c89b26977fe30f6a96c4298e700",
        "597d19e6385d27778262539cdfe7e1c835d885bd",
        "5b27c0f63d27f8dc5c4cf8b3de27b6a6f28cd811",
        "8d72f0afcef2bb513a2d6750fc8f9365bfbf5e41",
        "950c82b1d9c30dd04c662640b0974699e8abfaf1",
        "ee6bf00c4ee07aed57aed4d0b4b8163e80d032e8",
        "618f2d1ef01dcc20d02a7ce41a0c257fea127411",
        "8fc104816f3c62b652be8982f4c683350f929475",
        "8bbcb0d6fe376585b95af9a8c2b422c1f73dbe36",
        "22b1dc3caa3448973532fd9d95c5108e46c09b66",
        "6069b2778afa007cbb26d2d466a278edf5dcf869",
        "7e6a32c00cf02e4105878bdc8a5156f4e4b61836",
        "0166bea250d01a15515cdb418dde8e12c900f264",
        "15f449d907022c4796c992e4060ba32ba9cf9d63",
        "160d9b4c32b1a74aca45bd92e91c3cc0dfce5146",
        "2d6e4ae6e35442989f40a9129151e15df027e4ad",
        "354dd662ab93ef8e84bd91b035aca41d6c9f2406",
        "3603ef13f7f417569b64b8dab21481c9431fa0c7",
        "418683c8ef44fe2c468257bd90b5c96a3504a252",
        "41b6235fe1eb939f7cb922812a48b2f3cdf69b91",
        "4841d90e982b369c016cc9b4faddec6c53bfa76a",
        "6a1318350286681d1bc472a83f6ef768e42e8c6b",
        "ad36d9cc6a9d1a4261c6953c8bd56f2f1e3dc9f1",
        "ad90535d466f42623195b1f788320cff65cef646",
        "bba2dc40e98eadc655487bfb0b65d7cfe3e681ba",
        "bee546c14a7135cb0d6cced6e2a55ad6e9564b28",
        "c1ebd9b8278ec9501541344e69b889a3000eac69",
        "ccc6326fef976edafc625a59ce64a245fae13e15",
        "cd27134a16b6573e94896b8f71844e4124f515dc",
        "e441537c95b2760f99811760a8611044baa4b8f6",
        "02821f6b60628b216910a4af0812cdabdf29732e",
        "174073b8eea92904fa13121be71f2ceb86d9b119",
        "1eaa40fbe1e65b202292b8514312cd20c1f55fff",
        "30ce5d1e119d670ca7bb952d23bfab50cce11f09",
        "4ba05ddc08e3d1f43ec99c4ba983e2e93c26285e",
        "e701a397528c844a140ef16f7493b2cadc9c1047",
        "fa45847d8532b1d779aa1b9d2d5acc2170985949",
        "18c80ea5470ad42f4dd494e2a174bc1db485d76e",
        "2fbd3304582c13b187a66a6e426da0775f2dcf72",
        "4fc953d79c9d7c02a9bde0680b3e00a627b51836",
        "9ba2fa166b7891aa58e55a67c507a22e275c2fcd",
        "9d9ebb6ba488fae44c6131a1e467a5fc906de5a9",
        "a6ec04ec779070e39eec9711798615177fda1c3e",
        "6e7d406a9a956785d2541c1a5ff8aec341cda41c",
        "94735b8974d4304aa49a83c88e72263b4d34580b",
        "1622948052e8fb63186f83a41d4be3e5bede6891",
        "f818283930900c6744ace059878b8d2d91b6afd5",
        "750f368eb27379b6b3b7eb7c4fbd5ad30ae11af4",
        "09d284f1e174ea358a2483b39c7c25ec81382afc",
    ],
    "Dropper Payload": [
        "048c3a7604c9e8bc426d111c652f108bf9f093de",
        "080eac6d972c2582a411d34bd207bc43b086cb40",
        "102de892dacf0bfb249eb0f4f214a27d705b466a",
        "131a59bf23f3dd23396bd10cb77e368c0758b296",
        "19347a06704d4db0ea602c36355470d453e33204",
        "212e743e63c32e37ec959eabbd72ac8a4d23f53f",
        "24d4395f7208f9d61ee06ed77f8d8f63e260bf9b",
        "2de7da3e838d92251d060302126d50df027a98ce",
        "32a55b28e053b334f6c74f97c70b2327739d1040",
        "58eafd5aef5e1c5321f3c19d9ebbe5c87bc4da07",
        "5fd0adf84e02d89c036d52d2fa3b086333d340ae",
        "6236ed980a8fef3d45c40d533cbea5c52fb4d76c",
        "739bda908889db883f94a4a2eb9f0ea0c3b921f9",
        "755e553b88e0acbefb22714c3b23cb861ec9adca",
        "f732348c8fbd77798041e7c575d273c69887861a",
        "7a3cf712741d1a98833951db1740b70c6264350f",
        "7aeb12a65da0243b1a28b12fc18e91064c060f82",
        "88ea5aa7630fe652e7ba6ce9c5123c0b40aba140",
        "91ecb99290f659187b4d0307f5be610b4f3d6b64",
        "9bd3892f781dabd2bd9893810e773b12acaba689",
        "a064ca9939c803f49a94ea3542b5471695544369",
        "b574e58e85bb37370f905652be215fbedb4f547e",
        "ba528c515a889ddec35bbbaebb6310ec7fc2b946",
        "c4e44268f44d36ebdac135ea207fefa9a73d2bc7",
        "cc48c1e0cf2e9dcbb5ec228c22202e0b1f1960f0",
        "dab3fefaddaed1a555080bef1ca8aaef9ab0fbd0",
        "e6d91637de90773a42588962f37bf93625c20e46",
    ],
    "GhostSocks": [
        "019e8e7c7294d1185c34e5c7e5ade9d2267797c0",
        "08e585bc3ea2ba1a4a9cd68ce3b4496d9664dde7",
        "0f8aafc5808faa6efc4ba8ef98b8880f256fb101",
        "31f400effbe9f8e5eb357a0d445ec7ef876d1ef4",
        "391030795a39bfdfb606f6d3056b8a1465ced8bd",
        "43660c726d4b0f42daada8cff083e865acb4101c",
        "699bae60f8e7e5055a4e237fff702a4bb382aaae",
        "6ad537436f19aeab9973af80e06759aa060d7f22",
        "7697602d056a5818c7734b9684c07490c708eefa",
        "778128b06fc296c559811d6082b7be20a49d368a",
        "7dd550ce0633466d7a7f12edfe037fbbd456c4ce",
        "8a9d259ad67596492720aebda0a88617da881ccd",
        "92bce49ab40ba8a2fcf6a15ad11daa07a1430e9a",
        "d2e866357feebdc5cbb570eadb23d7db0afd0101",
        "d8eaf1bfe14b3767ab6949274b5459deb9e6e604",
        "14bb613c50280ba31a7c126ed0bb6762dd8758a5",
    ],
    "Unknown Backdoor": [
        "f8ce0adbd10fc30fd059ed91c35c8a7ac7d29afd",
        "bee7a64fd81f240064820532cdc3f7456e372a4d",
        "74dcf10e01e0cbf28388286555e02a6532e07c16",
        "e713f0625d93d51dc5a02c5d03c12134c0375093",
        "3a6a6d7f33848980ffbfba469ed3c7bf89af9a48",
        "d0ecf08a01c831e4e12355d12cf7d333e3bc94c3",
    ],
}


async def lookup_hash(http: httpx.AsyncClient, hash_val: str, hash_type: str) -> dict | None:
    """Look up a hash on VT. Returns file attributes or None if not found."""
    try:
        resp = await http.get(f"{VT_BASE}/files/{hash_val}")
        if resp.status_code == 404:
            logger.warning(f"  Not found on VT: {hash_val[:16]}… ({hash_type})")
            return None
        if not resp.is_success:
            logger.warning(f"  VT error {resp.status_code} for {hash_val[:16]}…")
            return None
        return resp.json().get("data", {})
    except Exception as e:
        logger.warning(f"  Lookup failed {hash_val[:16]}…: {e}")
        return None


def build_known_ioc_record(sha256: str, filename: str, tm_detection: str,
                           category: str, file_data: dict | None) -> dict:
    """Build a Supabase findings record for a known IOC."""
    now = datetime.now(timezone.utc).isoformat()

    # Get extra info from VT if available
    vt_attrs     = (file_data or {}).get("attributes", {}) if file_data else {}
    file_type    = vt_attrs.get("type_description", "—")
    size_mb      = round((vt_attrs.get("size") or 0) / (1024 * 1024), 1)
    stats        = vt_attrs.get("last_analysis_stats", {})
    malicious    = stats.get("malicious", 0)
    total        = max(sum(stats.values()), 1) if stats else 1
    first_sub    = vt_attrs.get("first_submission_date")
    first_sub_dt = datetime.fromtimestamp(first_sub, tz=timezone.utc) if first_sub else None
    first_sub_str = first_sub_dt.strftime("%Y-%m-%d %H:%M UTC") if first_sub_dt else "—"

    # Actual filename from VT if available
    vt_filename = (
        vt_attrs.get("meaningful_name")
        or vt_attrs.get("name")
        or filename
    )

    return {
        "id":               f"vt_known_ioc:{sha256}",
        "platform":         "vt_known_ioc",
        "repo_name":        vt_filename,
        "repo_url":         f"https://www.virustotal.com/gui/file/{sha256}",
        "description":      f"{file_type} · {malicious}/{total} dets · {size_mb} MB",
        "owner_login":      category,          # category label (Dropper, GhostSocks, etc.)
        "score":            0,                 # already processed — not scored
        "severity":         "LOW",
        "reasons":          [
            f"TM Detection: {tm_detection}",
            f"First submitted to VT: {first_sub_str}",
            f"COVERED: Published in Trend Micro research — weaponizing-trust-signals-claude-code",
            f"Category: {category}",
        ],
        "suspicious_files": [sha256],
        "repo_created_at":  first_sub_dt.isoformat() if first_sub_dt else now,
        "dismissed":        False,             # visible but clearly marked covered
        "scan_count":       1,
    }


async def main():
    logger.info("Connecting to Supabase and VT...")
    db = create_client(SUPABASE_URL, SUPABASE_KEY)   # sync — no await

    http = httpx.AsyncClient(
        timeout=30.0,
        headers={"x-apikey": VT_API_KEY, "Accept": "application/json"},
    )

    ingested = 0
    skipped  = 0

    # ── Process TM IOC list SHA256s ───────────────────────────────────────────
    logger.info(f"Processing {len(TM_SHA256_IOCS)} TM IOC list SHA256s...")
    for sha256, filename, tm_detection, category in TM_SHA256_IOCS:
        file_data = await lookup_hash(http, sha256, "SHA256")
        record    = build_known_ioc_record(sha256, filename, tm_detection, category, file_data)
        try:
            db.table("findings").upsert(record, on_conflict="id").execute()
            logger.info(f"  ✓ [{category:16s}] {record['repo_name'][:40]} | {tm_detection}")
            ingested += 1
        except Exception as e:
            logger.error(f"  ✗ {sha256[:16]}…: {e}")
            skipped += 1

    # ── Process Jacob's SHA1 hashes — resolve to SHA256 via VT ───────────────
    all_sha1s = [(sha1, cat) for cat, hashes in JACOB_SHA1S.items() for sha1 in hashes]
    logger.info(f"\nProcessing {len(all_sha1s)} SHA1 hashes via VT lookup...")

    for sha1, category in all_sha1s:
        file_data = await lookup_hash(http, sha1, f"SHA1/{category}")
        if not file_data:
            skipped += 1
            continue

        vt_attrs = file_data.get("attributes", {})
        sha256   = vt_attrs.get("sha256") or file_data.get("id", "")
        if not sha256 or len(sha256) != 64:
            logger.warning(f"  No SHA256 for SHA1 {sha1[:16]}…")
            skipped += 1
            continue

        # Extract TM detection from VT results
        analysis  = vt_attrs.get("last_analysis_results") or {}
        tm_det    = "—"
        for key in ("TrendMicro", "TrendMicro-HouseCall", "Trend Micro", "TrendMicro-hippa"):
            res = analysis.get(key, {})
            if res.get("result"):
                tm_det = res["result"]
                break

        filename = (
            vt_attrs.get("meaningful_name")
            or vt_attrs.get("name")
            or f"{sha256[:16]}…"
        )
        record = build_known_ioc_record(sha256, filename, tm_det, category, file_data)
        # Also store the original SHA1 in reasons for cross-reference
        record["reasons"].append(f"Original SHA1: {sha1}")

        try:
            db.table("findings").upsert(record, on_conflict="id").execute()
            logger.info(f"  ✓ [{category:16s}] {filename[:40]} | {tm_det[:30]}")
            ingested += 1
        except Exception as e:
            logger.error(f"  ✗ SHA1 {sha1[:16]}…: {e}")
            skipped += 1

    await http.aclose()
    logger.info(f"\n{'═'*50}")
    logger.info(f"Done: {ingested} ingested, {skipped} skipped")
    logger.info("Known IOCs now appear in VT Files tab with COVERED badge.")


if __name__ == "__main__":
    asyncio.run(main())
