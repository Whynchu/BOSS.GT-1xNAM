#!/usr/bin/env python3
"""Recover GT-1 application startup callback lists from copied code/data."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SEGMENT_BASE = 0x01000300
VERSIONS = {
    "v108": {
        "entry": 0x010010AE,
        "r4_literal": 0x01001108,
        "r6_literal": 0x0100110C,
        "segment_sha256": "5691f04c08e52373973725ede20ff9de0bc3fc0e77a160e856a11342701168a0",
        "decoded_sha256": "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1",
    },
    "v109": {
        "entry": 0x0100114E,
        "r4_literal": 0x010011A8,
        "r6_literal": 0x010011AC,
        "segment_sha256": "019adcf28e4a12444d48699b0b2a386a1a5feb2e43b59d465c696ee42540b9f9",
        "decoded_sha256": "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29",
    },
}

def recover(version: str, config: dict) -> dict:
    segment_path = ROOT / f"firmware/work/reconstructed/{version}-GT1Appli-seg0.bin"
    decoded_path = ROOT / f"firmware/work/decoded/{version}-GT1Appli.bin"
    segment = segment_path.read_bytes()
    decoded = decoded_path.read_bytes()
    segment_sha = hashlib.sha256(segment).hexdigest()
    decoded_sha = hashlib.sha256(decoded).hexdigest()
    if segment_sha != config["segment_sha256"]:
        raise SystemExit(f"{version} segment SHA-256 mismatch: {segment_sha}")
    if decoded_sha != config["decoded_sha256"]:
        raise SystemExit(f"{version} decoded-image SHA-256 mismatch: {decoded_sha}")

    def word_at_runtime(address: int) -> int:
        offset = address - SEGMENT_BASE
        if offset < 0 or offset + 4 > len(segment):
            raise ValueError(f"runtime address outside copied segment: 0x{address:08x}")
        return struct.unpack_from("<I", segment, offset)[0]

    r4_pointer = word_at_runtime(config["r4_literal"])
    r6_pointer = word_at_runtime(config["r6_literal"])
    array_pointer_address = r6_pointer + 8
    array_address = word_at_runtime(array_pointer_address)
    callbacks = []
    for index in range(64):
        entry_address = array_address + 4 * index
        pointer = word_at_runtime(entry_address)
        if pointer == 0:
            terminator_address = entry_address
            break
        if not (pointer & 1):
            raise SystemExit(f"{version}: non-Thumb callback at 0x{entry_address:08x}: 0x{pointer:08x}")
        target = pointer & ~1
        callbacks.append({
            "index": index,
            "entry_address": f"0x{entry_address:08x}",
            "pointer": f"0x{pointer:08x}",
            "thumb_entry": f"0x{target:08x}",
            "segment_offset": f"0x{target - SEGMENT_BASE:x}",
        })
    else:
        raise SystemExit(f"{version}: no zero terminator found within 64 callback entries")

    return {
        "startup_entry": f"0x{config['entry']:08x}",
        "segment": str(segment_path.relative_to(ROOT)),
        "segment_sha256": segment_sha,
        "decoded_app": str(decoded_path.relative_to(ROOT)),
        "decoded_app_sha256": decoded_sha,
        "r4_literal_address": f"0x{config['r4_literal']:08x}",
        "r4_literal_value": f"0x{r4_pointer:08x}",
        "r6_literal_address": f"0x{config['r6_literal']:08x}",
        "r6_literal_value": f"0x{r6_pointer:08x}",
        "callback_array_pointer_address": f"0x{array_pointer_address:08x}",
        "callback_array_address": f"0x{array_address:08x}",
        "array_terminator_address": f"0x{terminator_address:08x}",
        "callback_count": len(callbacks),
        "callbacks": callbacks,
    }

report = {
    "read_only": True,
    "method": "resolve startup LDR-literal values in hash-verified copied segment; follow [r6+8] to a zero-terminated callback array",
    "segment_runtime_base": f"0x{SEGMENT_BASE:08x}",
    "versions": {version: recover(version, config) for version, config in VERSIONS.items()},
    "ghidra_followups": {
        "v108": {
            "report": "firmware/work/ghidra-combined-v108-app-02003-entry-dispatch.txt",
            "report_sha256": "509c4203898846b81f91c969f9b69352588de8a3e2f29b09b3a55670235ba252",
            "method": "Ghidra 12.2 ARM:LE:32:v7, Thumb context; combined image/copy mapping and explicit 0x600004A8 seed",
            "finding": "Same 0x600004A8 dispatch body and four callback slots as v1.09; startup loop uses the v1.08 callback array located at 0x01010888",
            "all_callbacks_report": "firmware/work/ghidra-combined-v108-app-init-callbacks.txt",
            "all_callbacks_report_sha256": "d2853b9cf7b7670e67b77000dd9d25c12b3cc75af497ed50fa0a9cecba2eb646",
        },
        "v109": {
            "report": "firmware/work/ghidra-combined-v109-app-init-callbacks.txt",
            "report_sha256": "1aefc2a76e433be5dd1d319aec2414c84e32a1d28b481e0b11fa787114728e50",
            "method": "Ghidra 12.2 ARM:LE:32:v7, Thumb context; combined image/copy mapping, startup entries, 0x600004A8, and all 14 callback entries seeded",
            "finding": "All 14 entries begin with coherent Thumb prologues in the bounded report; no aligned 0x02003xxx words occur in either reconstructed first-copy source interval",
        },
    },
    "interpretation_limits": [
        "The startup code calls each nonzero pointer in its array; this establishes callback reachability from the startup loop, not semantic roles.",
        "The app's first call through the 0x020030B4 table occurs before either version's callback loop, so these later arrays cannot alone explain how those slots were callable at first use.",
        "A missing static 0x02003xxx word in the copied segment does not exclude indirect initialization or writes through other pointers.",
        "Callback addresses and contents differ between v1.08 and v1.09; do not assume the versioned lists are interchangeable.",
    ],
}
out = ROOT / "firmware/work/gt1-app-init-callbacks.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
for version, item in report["versions"].items():
    print(version, "array", item["callback_array_address"], "count", item["callback_count"], "terminator", item["array_terminator_address"])
    for callback in item["callbacks"]:
        print(" ", callback["index"], callback["pointer"], "->", callback["thumb_entry"])
