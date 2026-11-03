#!/usr/bin/env python3
"""Reproduce the candidate address map for the initial ESC91.000 block.

Read-only. Requires Capstone 5.x from the Python environment used for the report.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ("v108", "v109")
RUNTIME_BASE = 0x00FFFFD0
HEADER_SIZE = 0x30
VECTOR_TABLE_RUNTIME = RUNTIME_BASE + HEADER_SIZE
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)


def u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 4], "little")


def decode(data: bytes, file_off: int, size: int = 0x30) -> list[dict[str, str]]:
    return [
        {
            "runtime_address": f"0x{i.address:08X}",
            "file_offset": f"0x{i.address - RUNTIME_BASE:06X}",
            "bytes": i.bytes.hex(" "),
            "mnemonic": i.mnemonic,
            "operands": i.op_str,
        }
        for i in md.disasm(data[file_off : file_off + size], RUNTIME_BASE + file_off)
    ]


results = {}
first_block = None
for version in VERSIONS:
    path = ROOT / "firmware" / "extracted" / version / f"gt1_sys_{version}" / "GT1ROM.BIN"
    data = path.read_bytes()
    block = data[:0x2000]
    if first_block is None:
        first_block = block
    results[version] = {
        "path": str(path.relative_to(ROOT)),
        "image_size": len(data),
        "image_sha256": hashlib.sha256(data).hexdigest(),
        "first_block_sha256": hashlib.sha256(block).hexdigest(),
        "first_block_matches_v108": block == first_block,
        "load_base": f"0x{RUNTIME_BASE:08X}",
        "header_size": f"0x{HEADER_SIZE:X}",
        "vector_table_runtime_address": f"0x{VECTOR_TABLE_RUNTIME:08X}",
        "reset_vector_sp_word_at_0x30": f"0x{u32(data, 0x30):08X}",
        "reset_vector_pc_word_at_0x34": f"0x{u32(data, 0x34):08X}",
        "reset_trampoline_file_offset": f"0x{(u32(data, 0x34) & ~1) - RUNTIME_BASE:06X}",
        "entry_code_at_0x2f0": decode(data, 0x2F0, 0x20),
        "code_at_branch_target_0xbe0": decode(data, 0x0BE0, 0x30),
        "code_at_literal_target_0xa20": decode(data, 0x0A20, 0x30),
        "code_at_vector_target_0xb14": decode(data, 0x0B14, 0x20),
        "reset_trampoline_literal_at_0xb2c": f"0x{u32(data, 0x0B2C):08X}",
        "entry_literals": {
            "word_at_0x2fc": f"0x{u32(data, 0x2FC):08X}",
            "word_at_0x300": f"0x{u32(data, 0x300):08X}",
        },
        "candidate_updater_header_pointer_at_0x2034": f"0x{u32(data, 0x2034):08X}",
        "candidate_pointer_target_fill_0xe80_0xeff_all_ff": data[0x0E80:0x0F00] == b"\xFF" * 0x80,
    }

header_cross_check = {
    "file_offset": "0x002034",
    "field_le": results["v109"]["candidate_updater_header_pointer_at_0x2034"],
    "candidate_pointer_interpretation": "If interpreted in the initial block address space, maps to file offset 0x0EEA.",
    "observation": "File offsets 0x0E80-0x0EFF are 0xFF fill in both v1.08 and v1.09.",
    "conclusion": "This field is not validated as an entry pointer into the initial block; it likely belongs to another section/address-space field or needs a different interpretation.",
}

# Structural checks for the proposed first-block map.
for version, item in results.items():
    assert item["reset_vector_pc_word_at_0x34"] == "0x01000AE5"
    assert item["entry_literals"]["word_at_0x2fc"] == "0x010009F1"
    assert item["entry_literals"]["word_at_0x300"] == "0x01028000"
    assert item["candidate_updater_header_pointer_at_0x2034"] == "0x01000EBA"
    assert item["candidate_pointer_target_fill_0xe80_0xeff_all_ff"]
    assert item["reset_trampoline_file_offset"] == "0x000B14"
    assert item["reset_trampoline_literal_at_0xb2c"] == "0x010002C1"
    assert any(i["mnemonic"] == "bl" and i["operands"] == "#0x1000bb0" for i in item["entry_code_at_0x2f0"])
    assert item["code_at_branch_target_0xbe0"]
    assert item["code_at_literal_target_0xa20"]
    assert item["code_at_vector_target_0xb14"]

assert results["v109"]["first_block_matches_v108"]

report = {
    "analysis": "ESC91.000 first-block candidate Thumb map",
    "read_only": True,
    "candidate_runtime_mapping": "runtime_address = 0x00FFFFD0 + file_offset; file offset 0x30 maps to runtime 0x01000000 (the 0x30-byte image header precedes the vector table).",
    "scope": "Initial 0x000000-0x001FFF block only; not the later GT1Upd or GT1Appli payloads.",
    "images": results,
    "header_cross_check": header_cross_check,
}
out = ROOT / "firmware" / "work" / "updater-address-map-hypothesis.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
