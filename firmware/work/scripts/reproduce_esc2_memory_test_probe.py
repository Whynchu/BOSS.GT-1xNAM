#!/usr/bin/env python3
"""Reproduce bounded v1.09 ESC2 internal-memory test-path evidence.

The probe hash-checks the decoded app, disassembles the candidate test routine
and its two direct test wrappers, resolves PC-relative literal loads, and
extracts nearby factory-test labels. Co-location is not treated as a proven
string xref or proof of the normal audio path. Output is JSON on stdout only.
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
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

PROJECT = Path(__file__).resolve().parents[4]
APP_PATH = "firmware/work/decoded/v109-GT1Appli.bin"
APP_SHA256 = "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29"
BASE = 0x60000000
CODE_WINDOWS = {
    "candidate_internal_memory_test": (0x600466E2, 0xC6),
    "test_result_wrappers": (0x60066CB0, 0x44),
    "failure_label_dispatch": (0x60089832, 0x52),
    "test_dispatch_entry": (0x60007E1C, 0x30),
    "test_dispatch_pram_calls": (0x60007E88, 0x28),
    "test_dispatch_transfer_callers": (0x600080E0, 0x40),
    "test_dispatch_caller": (0x6007D8D2, 0x26),
}
TEST_DISPATCH_TABLE_OFFSET = 0x7E30
TEST_DISPATCH_SELECTOR_COUNT = 6
FAILURE_LABEL_TABLE_OFFSET = 0x10DC20
FAILURE_LABELS = [
    "NG (IRAM0)",
    "NG (IRAM1)",
    "NG (PRAM0)",
    "NG (PRAM1)",
    "NG (ERAM IN)",
    "NG (ERAM EXT)",
    "NG (SDRAM)",
    "NG (R/W)",
    "NG (USER)",
]
FACTORY_TEST_STRINGS = {
    "audio_self_test_menu_label": 0x26CF1C,
    "iram0_failure_label": 0x26D1E3,
    "pram0_failure_label": 0x26D1EE,
    "iram1_failure_label": 0x26D1F9,
    "pram1_failure_label": 0x26D204,
    "sdram_failure_label": 0x26D20F,
    "eram_in_failure_label": 0x26D21A,
}


def read_c_string(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("ascii", errors="replace")


def disassemble_window(md: Cs, data: bytes, address: int, length: int) -> list[dict[str, str]]:
    offset = address - BASE
    rows = []
    for ins in md.disasm(data[offset : offset + length], address):
        row = {
            "address": f"0x{ins.address:08X}",
            "bytes": ins.bytes.hex(),
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
        }
        if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1:
            operand = ins.operands[1]
            if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                literal_address = ((ins.address + 4) & ~3) + operand.mem.disp
                literal_offset = literal_address - BASE
                if 0 <= literal_offset <= len(data) - 4:
                    literal_value = struct.unpack_from("<I", data, literal_offset)[0]
                    row["literal_address"] = f"0x{literal_address:08X}"
                    row["literal_value"] = f"0x{literal_value:08X}"
        rows.append(row)
    return rows


def main() -> None:
    data = (PROJECT / APP_PATH).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == APP_SHA256, f"decoded app hash mismatch: {digest}"
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    result = {
        "classification": "PRAM0/PRAM1 self-test path is strongly supported by code and failure-label dispatch; normal audio relationship is not shown",
        "input": APP_PATH,
        "input_sha256": digest,
        "mapping": "candidate decoded-image mapping: address = 0x60000000 + file offset",
        "method": "hash-pinned Thumb-M disassembly with PC-relative literal resolution; extract NUL-terminated labels from pinned image",
        "code": {},
        "strings": {},
        "failure_label_table": {},
        "test_result_bit_to_label_index": {"0x40": 2, "0x80": 3},
        "test_dispatch_selector_targets": {},
        "interpretation_limits": [
            "The PRAM0/PRAM1 identification comes from the test result bits selecting corresponding labels in the common failure-label dispatcher; it does not independently map the physical memory windows or identify the processor architecture.",
            "The code probes candidate windows at 0x4014E000/0x4016E000 and 0x40150000/0x40170000 and calls shared transfer helpers; the code/data mapping remains candidate.",
            "A factory memory test does not identify the normal audio callback, amp-model implementation, or NAM integration boundary.",
        ],
    }
    for name, (address, length) in CODE_WINDOWS.items():
        result["code"][name] = {
            "address": f"0x{address:08X}",
            "length": f"0x{length:X}",
            "instructions": disassemble_window(md, data, address, length),
        }
    result["strings"] = {
        name: {
            "file_offset": f"0x{offset:X}",
            "candidate_address": f"0x{BASE + offset:08X}",
            "text": read_c_string(data, offset),
        }
        for name, offset in FACTORY_TEST_STRINGS.items()
    }
    label_rows = []
    for index, expected in enumerate(FAILURE_LABELS):
        pointer = struct.unpack_from("<I", data, FAILURE_LABEL_TABLE_OFFSET + index * 4)[0]
        label_offset = pointer - BASE
        text = read_c_string(data, label_offset)
        assert text == expected, f"failure-label table entry {index}: {text!r} != {expected!r}"
        label_rows.append({
            "index": index,
            "pointer": f"0x{pointer:08X}",
            "text": text,
        })
    result["failure_label_table"] = {
        "candidate_address": f"0x{BASE + FAILURE_LABEL_TABLE_OFFSET:08X}",
        "file_offset": f"0x{FAILURE_LABEL_TABLE_OFFSET:X}",
        "entries": label_rows,
    }
    selector_targets = []
    for selector, relative_halfwords in enumerate(
        data[TEST_DISPATCH_TABLE_OFFSET : TEST_DISPATCH_TABLE_OFFSET + TEST_DISPATCH_SELECTOR_COUNT]
    ):
        selector_targets.append({
            "selector": selector,
            "table_byte": relative_halfwords,
            "candidate_target": f"0x{BASE + TEST_DISPATCH_TABLE_OFFSET + 2 * relative_halfwords:08X}",
        })
    result["test_dispatch_selector_targets"] = selector_targets
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
