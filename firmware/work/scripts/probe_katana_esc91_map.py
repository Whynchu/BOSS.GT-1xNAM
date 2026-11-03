#!/usr/bin/env python3
"""Probe the same candidate ESC91 Thumb map in Katana v2.01 and v4.00."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import capstone
from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_MCLASS, CS_MODE_THUMB, Cs

ROOT = Path(__file__).resolve().parents[3]
RUNTIME_BASE = 0x00FFFFD0
IMAGES = {
    "KATANA v2.01": ROOT / "firmware/work/reference/esc2-comparators/katana_v201/extracted/katana_sys_v201/KATANARM.BIN",
    "KATANA v4.00": ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN",
}
decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS | CS_MODE_LITTLE_ENDIAN)


def word(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def decode(data: bytes, file_offset: int, size: int) -> list[dict]:
    return [
        {
            "file_offset": f"0x{ins.address - RUNTIME_BASE:06X}",
            "runtime_address": f"0x{ins.address:08X}",
            "bytes": ins.bytes.hex(" "),
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
        }
        for ins in decoder.disasm(data[file_offset:file_offset + size], RUNTIME_BASE + file_offset)
    ]


results = {}
for label, path in IMAGES.items():
    image = path.read_bytes()
    reset_vector = word(image, 0x34)
    vector_target = (reset_vector & ~1) - RUNTIME_BASE
    trampoline_literal_offset = vector_target + 0x18
    trampoline_literal = word(image, trampoline_literal_offset)
    startup_target = (trampoline_literal & ~1) - RUNTIME_BASE
    results[label] = {
        "path": str(path.relative_to(ROOT)),
        "size": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "bootstrap_sha256": hashlib.sha256(image[:0x2000]).hexdigest(),
        "marker": image[:9].decode("ascii", "replace"),
        "candidate_runtime_base": f"0x{RUNTIME_BASE:08X}",
        "vector_table_file_offset": "0x000030",
        "vector_table_runtime_address": f"0x{RUNTIME_BASE + 0x30:08X}",
        "initial_stack_word": f"0x{word(image, 0x30):08X}",
        "reset_vector_word": f"0x{reset_vector:08X}",
        "reset_vector_target_file_offset": f"0x{vector_target:06X}",
        "reset_vector_target_disassembly": decode(image, vector_target, 0x20),
        "trampoline_literal_file_offset": f"0x{trampoline_literal_offset:06X}",
        "trampoline_literal_value": f"0x{trampoline_literal:08X}",
        "literal_target_file_offset": f"0x{startup_target:06X}",
        "startup_disassembly_at_0x2f0": decode(image, startup_target, 0x20),
    }

v201 = IMAGES["KATANA v2.01"].read_bytes()
v400 = IMAGES["KATANA v4.00"].read_bytes()
common = sum(a == b for a, b in zip(v201[:0x2000], v400[:0x2000]))
for result in results.values():
    assert result["marker"] == "ESC91.000"
    assert result["reset_vector_target_file_offset"] == "0x000A4C"
    assert result["trampoline_literal_value"] == "0x010002C1"
    assert result["literal_target_file_offset"] == "0x0002F0"
    assert result["reset_vector_target_disassembly"][0]["mnemonic"] == "ldr"
    assert result["reset_vector_target_disassembly"][1]["mnemonic"] == "bx"
    assert any(ins["mnemonic"] == "bl" for ins in result["startup_disassembly_at_0x2f0"])
assert word(v201, 0x34) == word(v400, 0x34) == 0x01000A1D
assert common == 7884

report = {
    "read_only": True,
    "capstone_version": capstone.__version__,
    "scope": "Candidate Thumb mapping probe of Katana ESC91.000 blocks only; does not apply to later updater/application sections.",
    "candidate_mapping": "runtime_address = 0x00FFFFD0 + file_offset",
    "images": results,
    "version_comparison": {
        "range": "0x000000–0x001FFF",
        "same_offset_equal_bytes": common,
        "range_bytes": 0x2000,
        "equal_fraction": round(common / 0x2000, 8),
        "longest_identical_run_file_range": "0x000C50–0x001FFF",
        "longest_identical_run_bytes": 5040,
    },
    "interpretation": (
        "The vector word, Thumb-state reset target, literal-loaded startup address, and decoded branch at startup "
        "are internally consistent under the candidate base in both Katana releases. This supports Thumb code in "
        "the ESC91.000 block only. It does not identify the MB8AA4181 core ISA or the later application payload ISA."
    ),
}
out = ROOT / "firmware/work/katana-esc91-map-probe.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
