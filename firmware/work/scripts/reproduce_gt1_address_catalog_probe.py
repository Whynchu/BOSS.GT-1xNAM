#!/usr/bin/env python3
"""Reproduce v1.09 address-catalog and bounded caller evidence.

The probe hash-pins the decoded app, validates the address rows, adjacent
four-byte-stride index area, and nine descriptor records, and scans direct
Thumb BL references to the small translation helpers. It does not infer the
catalog's product-level semantics or connect it to realtime audio.
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
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

SCRIPT_PATH = Path(__file__).resolve()
ROOT = next(
    parent for parent in SCRIPT_PATH.parents
    if (parent / "firmware/work/decoded/v109-GT1Appli.bin").is_file()
)
APP_PATH = ROOT / "firmware/work/decoded/v109-GT1Appli.bin"
APP_SHA256 = "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29"
BASE = 0x60000000
ADDRESS_TABLE_OFFSET = 0x196E0F
ADDRESS_TABLE_ROWS = 569
LOOKUP_TABLE_OFFSET = 0x197FD8
LOOKUP_ENTRY_COUNT = 0x89A
DESCRIPTOR_OFFSET = 0x19A240
DESCRIPTOR_COUNT = 9
DESCRIPTOR_STRIDE = 0x28
TARGETS = {
    0x6007AD8A: "range_descriptor_search",
    0x6007B0F8: "descriptor_lookup",
    0x6007B1B8: "lookup_wrapper_a",
    0x6007B1D4: "lookup_wrapper_b",
}


def main() -> None:
    data = APP_PATH.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == APP_SHA256, f"decoded app hash mismatch: {digest}"

    address_rows = []
    address_bytes_end = ADDRESS_TABLE_OFFSET + ADDRESS_TABLE_ROWS * 8
    for row in range(ADDRESS_TABLE_ROWS):
        offset = ADDRESS_TABLE_OFFSET + row * 8
        address = struct.unpack_from("<I", data, offset)[0]
        trailer = data[offset + 4:offset + 8]
        assert trailer == bytes.fromhex("00ffff00")
        address_rows.append(address)
    mapped_addresses = [x for x in address_rows if 0x02000000 <= x < 0x02100000]
    assert len(mapped_addresses) == 512
    assert sum(x == 0x00FFFF00 for x in address_rows) == 57
    assert address_rows.index(0x02003000) == 80

    lookup_end = LOOKUP_TABLE_OFFSET + LOOKUP_ENTRY_COUNT * 4
    assert lookup_end == DESCRIPTOR_OFFSET
    lookup_values = [
        struct.unpack_from("<h", data, LOOKUP_TABLE_OFFSET + i * 4)[0]
        for i in range(LOOKUP_ENTRY_COUNT)
    ]
    assert data[address_bytes_end:LOOKUP_TABLE_OFFSET] == b"\0"

    descriptors = []
    for index in range(DESCRIPTOR_COUNT):
        offset = DESCRIPTOR_OFFSET + index * DESCRIPTOR_STRIDE
        words = struct.unpack_from("<10I", data, offset)
        assert words[7] == 0x60197FD8 if index in range(2, 7) else words[7] in (0, 0x601966D0, 0x60196DD8)
        descriptors.append({
            "index": index,
            "file_offset": f"0x{offset:x}",
            "words": [f"0x{x:08x}" for x in words],
        })

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    windows = {
        "range_descriptor_search": (0x6007AD8A, 0x54),
        "descriptor_lookup": (0x6007B0F8, 0xC0),
        "lookup_wrappers": (0x6007B1B8, 0x50),
    }
    disassembly = {}
    for name, (address, length) in windows.items():
        rows = []
        start = address - BASE
        for ins in md.disasm(data[start:start + length], address):
            row = {
                "address": f"0x{ins.address:08x}",
                "bytes": ins.bytes.hex(),
                "mnemonic": ins.mnemonic,
                "operands": ins.op_str,
            }
            if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1:
                operand = ins.operands[1]
                if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                    literal = ((ins.address + 4) & ~3) + operand.mem.disp
                    literal_offset = literal - BASE
                    if 0 <= literal_offset <= len(data) - 4:
                        row["literal_address"] = f"0x{literal:08x}"
                        row["literal_value"] = f"0x{struct.unpack_from('<I', data, literal_offset)[0]:08x}"
            rows.append(row)
        disassembly[name] = rows

    direct_calls = {target: [] for target in TARGETS}
    for offset in range(0, len(data) - 3, 2):
        first, second = struct.unpack_from("<HH", data, offset)
        if (first & 0xF800) != 0xF000 or (second & 0xD000) != 0xD000:
            continue
        ins = next(md.disasm(data[offset:offset + 4], BASE + offset, count=1), None)
        if not ins or ins.mnemonic != "bl" or not ins.operands:
            continue
        operand = ins.operands[0]
        if operand.type == ARM_OP_IMM and operand.imm in direct_calls:
            direct_calls[operand.imm].append(ins.address)

    report = {
        "read_only": True,
        "input": str(APP_PATH.relative_to(ROOT)),
        "input_sha256": digest,
        "mapping": "candidate decoded-image address = 0x60000000 + file offset",
        "address_rows": {
            "start_file_offset": f"0x{ADDRESS_TABLE_OFFSET:x}",
            "row_count": ADDRESS_TABLE_ROWS,
            "end_exclusive_file_offset": f"0x{address_bytes_end:x}",
            "mapped_address_count": len(mapped_addresses),
            "sentinel_count": 57,
            "first_mapped_address": f"0x{mapped_addresses[0]:08x}",
            "last_mapped_address": f"0x{mapped_addresses[-1]:08x}",
            "02003000_row_index": address_rows.index(0x02003000),
            "trailer_per_row": "00ffff00",
        },
        "adjacent_lookup_area": {
            "start_file_offset": f"0x{LOOKUP_TABLE_OFFSET:x}",
            "entry_count": LOOKUP_ENTRY_COUNT,
            "entry_stride": 4,
            "end_exclusive_file_offset": f"0x{lookup_end:x}",
            "signed_halfword_sample": [lookup_values[i] for i in (0, 1, 2, 3, 4, 5, 10, 100, 1000, LOOKUP_ENTRY_COUNT - 1)],
            "ends_at_descriptor_array": True,
        },
        "descriptor_array": {
            "file_offset": f"0x{DESCRIPTOR_OFFSET:x}",
            "candidate_address": f"0x{BASE + DESCRIPTOR_OFFSET:08x}",
            "count": DESCRIPTOR_COUNT,
            "stride": DESCRIPTOR_STRIDE,
            "records": descriptors,
        },
        "disassembly": disassembly,
        "direct_callers": {
            TARGETS[target]: {
                "target": f"0x{target:08x}",
                "sites": [f"0x{x:08x}" for x in sites],
            }
            for target, sites in direct_calls.items()
        },
        "interpretation": "The bounded helpers search nine range descriptors, index a four-byte-stride lookup area, and call a common parameter/key operation. The data layout is consistent with an address-to-object or parameter-catalog path; its exact role is not named by this trace.",
        "limits": [
            "This static catalog path does not identify the amp-model implementation, audio callback, or a DSP execution domain.",
            "The address values and descriptor shapes do not by themselves establish whether entries are patch controls, SysEx regions, runtime objects, or another catalog.",
            "Direct BL sites are not a complete call graph and their containing paths are not all proven reachable during normal operation.",
        ],
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
