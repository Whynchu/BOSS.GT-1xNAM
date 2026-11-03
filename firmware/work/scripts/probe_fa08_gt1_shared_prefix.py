#!/usr/bin/env python3
"""Probe the shared 194-byte ESC2 payload prefix with bounded ARM decoders."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import capstone
from capstone import (
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MCLASS,
    CS_MODE_THUMB,
    Cs,
)

ROOT = Path(__file__).resolve().parents[3]
WINDOW = 194
SOURCES = {
    "FA ESC2 image": (ROOT / "firmware/work/reference/esc2-comparators/fa08_v203/extracted/_tmp/fantom_e_up.bin", 0x2044),
    "GT-1 v1.09 updater": (ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN", 0x2040),
    "GT-1 v1.09 application": (ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN", 0x40040),
    "KATANA v4.00 updater": (ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN", 0x2040),
    "KATANA v4.00 application": (ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN", 0x40040),
}

windows = {}
for label, (path, offset) in SOURCES.items():
    data = path.read_bytes()[offset:offset + WINDOW]
    windows[label] = {
        "path": str(path.relative_to(ROOT)),
        "file_offset": f"0x{offset:06X}",
        "window_bytes": len(data),
        "window_sha256": hashlib.sha256(data).hexdigest(),
        "data": data,
    }

unique = {item["data"] for item in windows.values()}
if len(unique) != 1 or len(next(iter(unique))) != WINDOW:
    raise SystemExit("the selected windows are not one identical 194-byte prefix")
raw = next(iter(unique))

probes = []
for transform, data in (
    ("raw", raw),
    ("delete_0xFF", bytes(value for value in raw if value != 0xFF)),
    ("delete_0xFF_and_0xDF", bytes(value for value in raw if value not in (0xFF, 0xDF))),
):
    for decoder_name, mode in (
        ("ARM Thumb", CS_MODE_THUMB),
        ("ARM Thumb M-class", CS_MODE_THUMB | CS_MODE_MCLASS),
        ("ARM state", CS_MODE_ARM),
    ):
        decoder = Cs(CS_ARCH_ARM, mode | CS_MODE_LITTLE_ENDIAN)
        instructions = list(decoder.disasm(data, 0x10000000))
        decoded_bytes = sum(inst.size for inst in instructions)
        probes.append({
            "transform": transform,
            "transform_definition": "delete listed byte values only; no other decoding or reordering",
            "decoder": decoder_name,
            "input_bytes": len(data),
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "deleted_byte_count": len(raw) - len(data),
            "decoded_instruction_count": len(instructions),
            "decoded_bytes_before_stop": decoded_bytes,
            "coverage_fraction": round(decoded_bytes / len(data), 6) if data else 0,
            "stop_stream_offset": f"0x{decoded_bytes:X}",
            "instructions": [
                {
                    "transformed_stream_offset": f"0x{inst.address - 0x10000000:X}",
                    "bytes": inst.bytes.hex(" "),
                    "mnemonic": inst.mnemonic,
                    "operands": inst.op_str,
                }
                for inst in instructions
            ],
        })

report = {
    "read_only": True,
    "scope": "Bounded 194-byte cross-product payload-prefix probe; not an ISA detector.",
    "capstone_version": capstone.__version__,
    "samples": {
        label: {key: value for key, value in item.items() if key != "data"}
        for label, item in windows.items()
    },
    "all_samples_byte_identical": len(unique) == 1,
    "raw_common_prefix_sha256": hashlib.sha256(raw).hexdigest(),
    "normalization_rationale": (
        "The separate bounded runtime-string probe observed 0xFF/0xDF interleaving in one exact diagnostic. "
        "Removing these bytes here is only a falsification probe; it is not an established firmware transform."
    ),
    "probes": probes,
    "interpretation": (
        "The raw data stops early under ARM/Thumb decoding. Deleting 0xFF permits a somewhat longer Thumb-M decode, "
        "but the decoder still stops before half the transformed window and deletion destroys the original offset map. "
        "The snippets do not establish coherent code, the application ISA, or that the prefix executes on ESC2."
    ),
}
out = ROOT / "firmware/work/fa08-gt1-prefix-decode-probe.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
