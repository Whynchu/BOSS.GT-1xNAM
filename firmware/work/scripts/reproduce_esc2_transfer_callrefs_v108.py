#!/usr/bin/env python3
"""Scan v1.08 for aligned Thumb BL references to the bounded ESC2 transfer path.

This is a candidate-address scan over the decoded image, not a full control-flow
or reachability proof. It hash-pins the app, decodes only structurally possible
Thumb-2 BL encodings, and separately scans aligned words for absolute pointers.
It prints JSON to stdout and does not modify inputs or write output files.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from capstone import (
    CS_ARCH_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MCLASS,
    CS_MODE_THUMB,
    Cs,
)
from capstone.arm import ARM_OP_IMM

PROJECT = Path(__file__).resolve().parents[3]
APP_PATH = "firmware/work/decoded/v108-GT1Appli.bin"
APP_SHA256 = "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1"
BASE = 0x60000000
TARGETS = {
    "receive_state_handler": 0x6007D686,
    "transfer_parser": 0x6007CDE2,
    "batch_stager": 0x60093B14,
    "flush_dispatcher": 0x6007CCD0,
    "read_helper": 0x60058E1C,
    "write_helper": 0x60058D3C,
    "class7_helper": 0x600593A2,
}


def main() -> None:
    data = (PROJECT / APP_PATH).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == APP_SHA256, f"decoded app hash mismatch: {digest}"

    md = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB | CS_MODE_MCLASS | CS_MODE_LITTLE_ENDIAN,
    )
    md.detail = True
    direct_refs: dict[int, list[int]] = {value: [] for value in TARGETS.values()}
    candidate_bl_encodings = 0

    # Thumb-2 BL has a recognizable first/second halfword pattern. Check each
    # halfword boundary, then let Capstone validate and resolve the target.
    for offset in range(0, len(data) - 3, 2):
        first, second = struct.unpack_from("<HH", data, offset)
        if (first & 0xF800) != 0xF000 or (second & 0xD000) != 0xD000:
            continue
        candidate_bl_encodings += 1
        ins = next(md.disasm(data[offset : offset + 4], BASE + offset, count=1), None)
        if not ins or ins.mnemonic not in ("bl", "blx") or not ins.operands:
            continue
        operand = ins.operands[0]
        if operand.type == ARM_OP_IMM and operand.imm in direct_refs:
            direct_refs[operand.imm].append(ins.address)

    aligned_pointer_refs: dict[int, list[int]] = {value: [] for value in TARGETS.values()}
    for offset in range(0, len(data) - 3, 4):
        value = struct.unpack_from("<I", data, offset)[0] & ~1
        if value in aligned_pointer_refs:
            aligned_pointer_refs[value].append(offset)

    result = {
        "classification": "bounded static direct-call and aligned-pointer scan; not a full call graph or reachability proof",
        "input": APP_PATH,
        "input_sha256": digest,
        "mapping": "candidate decoded-image mapping: address = 0x60000000 + file offset",
        "method": "scan every halfword for Thumb-2 BL encoding shape, validate/decode with Capstone M-class; separately scan aligned 32-bit words for absolute target pointers (Thumb bit ignored)",
        "candidate_bl_encodings_decoded": candidate_bl_encodings,
        "targets": {},
        "interpretation_limits": [
            "A decoded direct-call site is a candidate code reference; its containing code path may not be reachable at runtime.",
            "No direct BL or aligned absolute pointer to a target does not exclude indirect calls, relative tables, computed addresses, or non-aligned data references.",
            "The receive-state handler recognizes SysEx commands in its body, but this scan does not identify its registration/caller or prove that the DSP transfer path participates in normal audio processing.",
        ],
    }
    for name, address in TARGETS.items():
        result["targets"][name] = {
            "address": f"0x{address:08X}",
            "direct_calls": [f"0x{site:08X}" for site in direct_refs[address]],
            "aligned_absolute_pointer_file_offsets": [
                f"0x{offset:X}" for offset in aligned_pointer_refs[address]
            ],
        }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
