#!/usr/bin/env python3
"""Inventory aligned 0x02003xxx words in decoded GT-1 updater/app payloads.

The output is a lead list, not a pointer or code classifier. Instruction-boundary
and reachability observations must be cross-checked against the saved Ghidra
combined-address reports.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import struct
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
ROOT = next(
    parent for parent in SCRIPT_PATH.parents
    if (parent / "firmware/work/decoded/v109-GT1Appli.bin").is_file()
)
TARGET_LO = 0x02003000
TARGET_HI = 0x02003140
EXPECTED = {
    ("v105", "GT1Appli"): "8297887084af48b04189955bbd8bdb4e0e6ff6a0e0fbcac7f85a175792775e29",
    ("v107", "GT1Appli"): "304b88a2c628cf47bb5091ecbc6da4fab4924f88cdea8897b44e5f474b9fb001",
    ("v108", "GT1Appli"): "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1",
    ("v109", "GT1Appli"): "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29",
    ("v105", "GT1Upd"): "0f247f1b94c0c9ca8e4eef1ec980e2f060f95ef494ed7fa6bd9fbaf52d93a6a4",
    ("v107", "GT1Upd"): "0f247f1b94c0c9ca8e4eef1ec980e2f060f95ef494ed7fa6bd9fbaf52d93a6a4",
    ("v108", "GT1Upd"): "0f247f1b94c0c9ca8e4eef1ec980e2f060f95ef494ed7fa6bd9fbaf52d93a6a4",
    ("v109", "GT1Upd"): "0f247f1b94c0c9ca8e4eef1ec980e2f060f95ef494ed7fa6bd9fbaf52d93a6a4",
}

images = []
exact_base_occurrences = []
for (version, section), expected_hash in EXPECTED.items():
    path = ROOT / f"firmware/work/decoded/{version}-{section}.bin"
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_hash:
        raise SystemExit(f"SHA-256 mismatch: {path}: {digest}")
    hits = []
    for offset in range(0, len(data) - 3, 4):
        value = struct.unpack_from("<I", data, offset)[0]
        if TARGET_LO <= value < TARGET_HI:
            hits.append({"offset": f"0x{offset:x}", "value": f"0x{value:08x}"})
    byte_hits = []
    needle = struct.pack("<I", TARGET_LO)
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            break
        byte_hits.append(f"0x{offset:x}")
        exact_base_occurrences.append({
            "version": version,
            "section": section,
            "offset": offset,
            "value": TARGET_LO,
        })
        cursor = offset + 1
    images.append({
        "version": version,
        "section": section,
        "path": str(path.relative_to(ROOT)),
        "size": len(data),
        "sha256": digest,
        "aligned_word_hits": hits,
        "exact_0x02003000_byte_hits": byte_hits,
    })

TABLE_TRAILER = bytes.fromhex("00ffff00")
table_versions = {}
for version, expected_hit in {
    "v105": 0x19515F,
    "v107": 0x195A0F,
    "v108": 0x195A93,
    "v109": 0x19708F,
}.items():
    image_path = ROOT / f"firmware/work/decoded/{version}-GT1Appli.bin"
    data = image_path.read_bytes()
    matching = [
        row for row in exact_base_occurrences
        if row["version"] == version and row["section"] == "GT1Appli" and row["offset"] == expected_hit
    ]
    assert len(matching) == 1, (version, matching)
    start = expected_hit
    while start >= 8 and data[start - 8 + 4:start] == TABLE_TRAILER:
        start -= 8
    end = expected_hit + 8
    while end + 8 <= len(data) and data[end + 4:end + 8] == TABLE_TRAILER:
        end += 8
    assert (end - start) % 8 == 0
    rows = []
    for offset in range(start, end, 8):
        address = struct.unpack_from("<I", data, offset)[0]
        trailing = data[offset + 4:offset + 8]
        assert trailing == TABLE_TRAILER
        rows.append({"offset": offset, "address": address, "trailing_bytes": trailing.hex()})
    assert len(rows) == 569, (version, start, end, len(rows))
    addresses = [row["address"] for row in rows]
    address_rows = [value for value in addresses if 0x02000000 <= value < 0x02100000]
    assert len(address_rows) == 512
    assert len(addresses) - len(address_rows) == 57
    table_versions[version] = {"start": start, "end": end, "rows": rows, "bytes": data[start:end]}

reference_addresses = [row["address"] for row in table_versions["v109"]["rows"]]
for version, table in table_versions.items():
    assert [row["address"] for row in table["rows"]] == reference_addresses
    assert table["bytes"] == table_versions["v109"]["bytes"], version

v109_table = table_versions["v109"]
v109_hit = 0x19708F
table_rows = [
    {
        "offset": f"0x{row['offset']:x}",
        "address": f"0x{row['address']:08x}",
        "trailing_bytes": row["trailing_bytes"],
    }
    for row in v109_table["rows"]
    if v109_hit - 0x20 <= row["offset"] <= v109_hit + 0x20
]

report = {
    "read_only": True,
    "method": "scan little-endian 32-bit words at 4-byte offsets, plus every-byte occurrences of the exact 0x02003000 value",
    "range_inclusive_start_exclusive_end": [f"0x{TARGET_LO:08x}", f"0x{TARGET_HI:08x}"],
    "images": images,
    "unaligned_occurrence_review": {
        "v109_app_offset": "0x19708f",
        "surrounding_record_stride": 8,
        "records": table_rows,
        "classification": "The unaligned exact-value occurrence is one row in a repeated 8-byte table with an address-like first word and identical trailing bytes, not a code pointer reference. The table's semantic role remains unidentified.",
    },
    "cross_version_table_comparison": {
        "versions": {
            version: {
                "start": f"0x{table['start']:x}",
                "end_exclusive": f"0x{table['end']:x}",
                "row_count": len(table["rows"]),
                "address_like_row_count": sum(0x02000000 <= row["address"] < 0x02100000 for row in table["rows"]),
                "sentinel_row_count": sum(not (0x02000000 <= row["address"] < 0x02100000) for row in table["rows"]),
            }
            for version, table in table_versions.items()
        },
        "byte_identical": True,
        "address_sequence_identical": True,
        "first_address_like": f"0x{next(row['address'] for row in v109_table['rows'] if 0x02000000 <= row['address'] < 0x02100000):08x}",
        "last_address_like": f"0x{next(row['address'] for row in reversed(v109_table['rows']) if 0x02000000 <= row['address'] < 0x02100000):08x}",
        "interpretation_limit": "Stable table contents do not establish the table's purpose, its consumer, or a relation to audio processing.",
    },
    "instruction_evidence": {
        "application": {
            "report": "firmware/work/ghidra-combined-v109-app-allcopies.txt",
            "reachable_path": "0x0100114E -> veneer at 0x010082DA -> 0x6000028C -> 0x600004A8",
            "instruction": "0x600004AA: LDR r4, [0x6000052C]; the word at decoded offset 0x52C is 0x020030B4",
            "indirect_calls": ["[r4-0x5C]", "[r4+0x58]", "[r4+0x70]", "[r4+0x7C]"],
            "confidence": "Ghidra instruction boundary and startup call path observed; callback target identities unresolved",
        },
        "application_secondary_candidate": {
            "report": "firmware/work/ghidra-combined-v109-app-allcopies.txt",
            "sequence": "At 0x60000446, LDR r0, [0x60000520]; decoded word at offset 0x520 is 0x02003000; following code loads [r0+0xC] and BLXes it",
            "confidence": "instruction sequence is decoded in the bounded report; its reachability from the application startup path is unproven",
        },
        "application_cross_version": {
            "report": "firmware/work/ghidra-combined-v108-app-02003.txt",
            "report_sha256": "2fe7118cae75ab84854a4cbfd0cce4df816f60dfeb66de07cb956841648d2b24",
            "input_sha256": "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1",
            "finding": "The same 0x010010AE -> 0x6000028C -> 0x600004A8 path and LDR literal at 0x600004AA are present; decoded words at offsets 0x520 and 0x52C remain 0x02003000 and 0x020030B4",
            "confidence": "entry path and literal load independently reproduced in v1.08; callback destination identities unresolved",
        },
        "updater": {
            "report": "firmware/work/ghidra-combined-v109-updater-allcopies.txt",
            "candidate_sequence": "At 0x60003ED2, LDR r1, [0x60003FD4]; decoded word at offset 0x3FD4 is 0x02003000; following code loads [r1+0xC] and BLXes it",
            "confidence": "instruction sequence appears in bounded report, but this address is not established as reachable from updater startup; it resembles the app's secondary candidate",
        },
    },
    "coverage_limits": [
        "Aligned-word scans can find data, immediates, or instruction encodings; a hit is not proof of a pointer or reference.",
        "The application callback structure's apparent extent from base-0x5C through base+0x7C is 0x02003058..0x02003130; no mapped startup copy overlaps this interval.",
        "The exact-byte scan covers only the value 0x02003000; it does not scan every possible unaligned 0x02003xxx value, reconstruct all MOVW/MOVT expressions, identify stores, or prove absence of an initializer.",
        "Ghidra imports and reports are bounded static analysis; physical address meaning and runtime table contents remain unknown.",
    ],
}
out = ROOT / "firmware/work/gt1-02003-reference-probe.json"
args = argparse.ArgumentParser()
args.add_argument("--stdout", action="store_true", help="print JSON without writing the recorded report")
if args.parse_args().stdout:
    print(json.dumps(report, indent=2))
    raise SystemExit(0)
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
for image in images:
    print(image["version"], image["section"], "hits", len(image["aligned_word_hits"]))
