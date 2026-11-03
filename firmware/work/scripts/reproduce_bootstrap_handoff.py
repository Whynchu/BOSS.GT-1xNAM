#!/usr/bin/env python3
"""Reproduce the GT-1 bootstrap's conditional section and handoff evidence.

Read-only static analysis. Requires Capstone (`python3 -m pip install capstone`).
The script checks exact source/output hashes, decodes bounded instruction spans,
and records computed targets. It does not assert the runtime contents of the
validator callback table or physical memory mappings beyond the stated evidence.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs

ROOT = Path(__file__).resolve().parents[3]
IMAGE = ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN"
BASE = 0x00FFFFD0
EXPECTED_IMAGE_SHA256 = "412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf"
VERSIONS = ("v105", "v107", "v108", "v109")
EXPECTED_UPD_SHA256 = "0f247f1b94c0c9ca8e4eef1ec980e2f060f95ef494ed7fa6bd9fbaf52d93a6a4"
EXPECTED_APP_SHA256 = {
    "v105": "8297887084af48b04189955bbd8bdb4e0e6ff6a0e0fbcac7f85a175792775e29",
    "v107": "304b88a2c628cf47bb5091ecbc6da4fab4924f88cdea8897b44e5f474b9fb001",
    "v108": "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1",
    "v109": "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def decode(data: bytes, start: int, size: int, address: int) -> list[dict[str, str]]:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    rows = []
    for ins in md.disasm(data[start:start + size], address):
        rows.append({
            "file_offset": hex(start + ins.address - address),
            "runtime_address": hex(ins.address),
            "bytes": ins.bytes.hex(),
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
        })
    return rows


image = IMAGE.read_bytes()
image_hash = sha256(image)
assert image_hash == EXPECTED_IMAGE_SHA256, image_hash
assert len(image) == 0x400000

# Loader instruction flow: validator return selects one of two section bases.
loader_rows = decode(image, 0xA02, 0x9E, BASE + 0xA02)
assert [row["bytes"] for row in loader_rows if row["file_offset"] in ("0xa32", "0xa36", "0xa3a", "0xa3e")] == [
    "fff7dbff", "0128", "314c", "4ff04174"
]
assert u32(image, 0xB00) == 0x03002000
upd_header, app_header = 0x2000, 0x40000
assert image[upd_header:upd_header + 8] == b"BSSESC2:"
assert image[app_header:app_header + 8] == b"BSSESC2:"
assert u32(image, upd_header + 0x28) == u32(image, app_header + 0x28) == 0x60000000

# Validator semantics visible in code: each nonzero callback is invoked, its
# return is compared with the record's first word; a mismatch returns zero.
validator_rows = decode(image, 0x9EC, 0x34, BASE + 0x9EC)
assert image[0xA10:0xA16] == bytes.fromhex("08b9002070bd")
assert image[0xA1C:0xA20] == bytes.fromhex("0120f9e7")

# The transfer trampoline is inside a word also used as the initial SP literal
# by code at 0x2F0. Verify only its executing halfwords and don't reinterpret
# the surrounding literal bytes as an independently established function.
trampoline_rows = decode(image, 0x304, 6, BASE + 0x304)
assert [(r["bytes"], r["mnemonic"], r["operands"]) for r in trampoline_rows] == [
    ("40f00100", "orr", "r0, r0, #1"),
    ("0047", "bx", "r0"),
]
assert image[0xAC6:0xACA] == bytes.fromhex("a06a fff7")[:4]  # LDR r0,[r4,#0x28]
assert image[0xAC8:0xACC] == bytes.fromhex("fff71cfc")

version_rows = []
for version in VERSIONS:
    upd_path = ROOT / f"firmware/work/decoded/{version}-GT1Upd.bin"
    app_path = ROOT / f"firmware/work/decoded/{version}-GT1Appli.bin"
    upd, app = upd_path.read_bytes(), app_path.read_bytes()
    upd_hash, app_hash = sha256(upd), sha256(app)
    assert upd_hash == EXPECTED_UPD_SHA256, (version, upd_hash)
    assert app_hash == EXPECTED_APP_SHA256[version], (version, app_hash)
    assert upd[:0xE8] == app[:0xE8]
    # At 0x7C the common startup code loads a Thumb target from its literal at
    # 0x164, then executes BX r0. The targets intentionally remain unmapped.
    assert upd[0x7C:0x80] == app[0x7C:0x80] == bytes.fromhex("39480047")
    assert u32(upd, 0x164) & 1 == 1
    assert u32(app, 0x164) & 1 == 1
    section_rows = {}
    for name, blob, blob_hash in (("updater", upd, upd_hash), ("application", app, app_hash)):
        copies = []
        for dst_off, length_off, src_off in (
            (0xE4, 0xE8, 0xEC), (0xF8, 0xFC, 0x100), (0x10C, 0x110, 0x114),
            (0x120, 0x124, 0x128), (0x134, 0x138, 0x13C), (0x148, 0x14C, 0x150),
        ):
            dst, length, src = u32(blob, dst_off), u32(blob, length_off), u32(blob, src_off)
            assert src >= 0x60000000
            src_start = src - 0x60000000
            assert src_start + length <= len(blob)
            copies.append({"destination": hex(dst), "length": hex(length), "source_runtime": hex(src),
                           "source_output_offset": hex(src_start), "destination_end_exclusive": hex(dst + length)})
        zeros = []
        for dst_off, length_off in (
            (0xF0, 0xF4), (0x104, 0x108), (0x118, 0x11C), (0x12C, 0x130),
            (0x140, 0x144), (0x154, 0x158), (0x15C, 0x160),
        ):
            dst, length = u32(blob, dst_off), u32(blob, length_off)
            zeros.append({"destination": hex(dst), "length": hex(length),
                          "destination_end_exclusive": hex(dst + length)})

        first_target_raw = u32(blob, 0x164)
        first_target = first_target_raw & ~1
        containing = [c for c in copies if int(c["destination"], 16) <= first_target < int(c["destination_end_exclusive"], 16)]
        assert len(containing) == 1, (version, name, hex(first_target), containing)
        copy = containing[0]
        src_target_offset = int(copy["source_output_offset"], 16) + (first_target - int(copy["destination"], 16))
        first_target_code = blob[src_target_offset:src_target_offset + 0x20]
        assert first_target_code[:18] == bytes.fromhex("4ff08070034908600348d0f804d003480047")
        first_target_disasm = decode(blob, src_target_offset, 0x20, first_target)
        second_target_raw = u32(blob, src_target_offset + 0x1C)
        second_target = second_target_raw & ~1
        containing2 = [c for c in copies if int(c["destination"], 16) <= second_target < int(c["destination_end_exclusive"], 16)]
        assert len(containing2) == 1, (version, name, hex(second_target), containing2)
        copy2 = containing2[0]
        src_second_offset = int(copy2["source_output_offset"], 16) + (second_target - int(copy2["destination"], 16))
        second_target_disasm = decode(blob, src_second_offset, 0x20, second_target)

        section_rows[name] = {
            "size": len(blob), "sha256": blob_hash,
            "common_startup_prefix_equal_to_other_section_length": "0xe8",
            "startup_branch_instruction_output_offset": "0x7e",
            "startup_target_literal_output_offset": "0x164",
            "startup_target_literal": hex(first_target_raw),
            "startup_target": hex(first_target),
            "copy_operations_from_startup_literals": copies,
            "zero_operations_from_startup_literals": zeros,
            "first_target_is_inside_copy": {
                "copy_destination": copy["destination"], "copy_source_output_offset": copy["source_output_offset"],
                "target_output_offset": hex(src_target_offset), "target_code_bytes": first_target_code.hex(),
                "disassembly": first_target_disasm,
            },
            "first_target_trampoline_literals": {
                "write_value": "0x01000000",
                "written_to_address": hex(u32(blob, src_target_offset + 0x14)),
                "stack_table_address": hex(u32(blob, src_target_offset + 0x18)),
                "second_target_literal": hex(second_target_raw),
            },
            "second_target_is_inside_copy": {
                "copy_destination": copy2["destination"], "copy_source_output_offset": copy2["source_output_offset"],
                "target_output_offset": hex(src_second_offset), "target_code_bytes": blob[src_second_offset:src_second_offset + 0x20].hex(),
                "disassembly": second_target_disasm,
            },
        }
    version_rows.append({"version": version, "sections": section_rows})

report = {
    "read_only": True,
    "image": str(IMAGE.relative_to(ROOT)),
    "image_sha256": image_hash,
    "tool": "Capstone Python binding; Thumb mode, little-endian",
    "section_selection": {
        "validator_call_file_offset": "0xa32",
        "validator_runtime_entry": hex(BASE + 0x9EC),
        "observed_validator_behavior": "scans up to four 8-byte records; invokes nonzero callback; compares callback return with record word 0; returns 0 on mismatch or missing callback and 1 after all visited records pass",
        "runtime_callback_table_pointer": "0x01010028",
        "runtime_callback_table_contents": "unknown; candidate file mapping does not establish runtime contents",
        "return_1_selects": {"header": "GT1Upd", "file_offset": "0x2000", "runtime_section_base": "0x03002000"},
        "return_0_selects": {"header": "GT1Appli", "file_offset": "0x40000", "runtime_section_base": "0x03040000"},
        "meaning_of_validator_result": "unresolved; code alone does not identify update/recovery mode",
    },
    "loader_to_selected_image": {
        "decoder_output_destination_header_offset": "+0x38",
        "entry_address_header_offset": "+0x28",
        "both_header_values": "0x60000000",
        "loader_load_instruction_file_offset": "0xac6",
        "loader_call_file_offset": "0xac8",
        "trampoline_runtime_address": "0x010002d4",
        "trampoline_file_offset_under_candidate_bootstrap_mapping": "0x304",
        "trampoline_instructions": trampoline_rows,
        "effective_transfer_for_current_headers": "0x60000001 (Thumb entry candidate)",
        "decoded_outputs": version_rows,
        "entry_code_observation": "updater and application outputs share identical bytes from 0x000 through 0x0e7; at 0x007c they load a target literal at 0x0164 and BX r0 at 0x007e. The common startup stub performs six copy and seven zero calls using literal descriptors.",
        "final_target_interpretation": "the selected 0x0100xxxx target falls inside a segment copied there by the startup stub. That target is another small trampoline which writes 0x01000000 to an image-specific address, loads a stack pointer through an image-specific table address, and branches to a second target also located inside a copied segment. The hardware meanings of those memory regions remain unresolved.",
    },
    "loader_instruction_excerpt": loader_rows,
    "validator_instruction_excerpt": validator_rows,
    "interpretation_limits": [
        "The code establishes conditional selection from the validator return value, not the semantic meaning of the validation table or mode.",
        "The output destination and entry field equal 0x60000000 in the inspected official image; this supports but does not prove physical RAM placement.",
        "The computed 0x60000001 transfer is a static control-flow consequence under the candidate bootstrap mapping.",
        "The copied 0x0100xxxx target range is a statically derived destination range; its physical memory type and CPU visibility are not established.",
        "The first copied target trampoline's write address and stack-table address are literal values; their hardware meanings are unknown.",
        "The second target code is disassembled as ARM Thumb for inspection; early app releases contain an instruction Capstone renders as a coprocessor transfer, so this is not proof of exact ISA or processor feature support.",
        "The decoded updater and app outputs are static results of the reproduced parser, not evidence of execution on hardware.",
    ],
}
out = ROOT / "firmware/work/bootstrap-handoff-evidence.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
