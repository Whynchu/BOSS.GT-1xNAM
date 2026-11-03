#!/usr/bin/env python3
"""Inventory aligned 0x02003xxx words in decoded GT-1 updater/app payloads.

The output is a lead list, not a pointer or code classifier. Instruction-boundary
and reachability observations must be cross-checked against the saved Ghidra
combined-address reports.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
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
    images.append({
        "version": version,
        "section": section,
        "path": str(path.relative_to(ROOT)),
        "size": len(data),
        "sha256": digest,
        "aligned_word_hits": hits,
    })

report = {
    "read_only": True,
    "method": "scan little-endian 32-bit words at 4-byte offsets",
    "range_inclusive_start_exclusive_end": [f"0x{TARGET_LO:08x}", f"0x{TARGET_HI:08x}"],
    "images": images,
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
        "This scan does not search unaligned values, reconstruct all MOVW/MOVT expressions, identify stores, or prove absence of an initializer.",
        "Ghidra imports and reports are bounded static analysis; physical address meaning and runtime table contents remain unknown.",
    ],
}
out = ROOT / "firmware/work/gt1-02003-reference-probe.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
for image in images:
    print(image["version"], image["section"], "hits", len(image["aligned_word_hits"]))
