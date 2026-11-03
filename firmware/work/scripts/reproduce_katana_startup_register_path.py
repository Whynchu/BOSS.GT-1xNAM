#!/usr/bin/env python3
"""Trace the bounded Katana ESC91 reset-to-second-stage path and 0x4002D400 lead."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import capstone
from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_MCLASS, CS_MODE_THUMB, Cs
from capstone.arm import ARM_INS_BL, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

ROOT = Path(__file__).resolve().parents[3]
BASE = 0x00FFFFD0
IMAGES = {
    "v2.01": ("firmware/work/reference/esc2-comparators/katana_v201/extracted/katana_sys_v201/KATANARM.BIN", "73b63f48050818e6e1cc0738d741e50ce8dcc6f644109cf8ec346a44dff1bdac", 0x0B60),
    "v4.00": ("firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN", "3e17ba95e21ed10a3cb5c60af8da0a375db613cc8409eb33b6d80e4248c9b493", 0x0B54),
}
MAP_PROBE = "firmware/work/katana-esc91-map-probe.json"
MAP_PROBE_SHA256 = "fa8d9aeeafc06dd6ddcdc452971c60b8538f6782042594877b1c44dad369b414"
DECODER = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS | CS_MODE_LITTLE_ENDIAN)
DECODER.detail = True


def word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def decode(data: bytes, start: int, end: int) -> list[dict]:
    out = []
    for ins in DECODER.disasm(data[start:end], BASE + start):
        out.append({"file_offset": f"0x{ins.address - BASE:X}", "candidate_runtime_address": f"0x{ins.address:08X}", "bytes": ins.bytes.hex(), "mnemonic": ins.mnemonic, "operands": ins.op_str})
    return out


def main() -> None:
    map_bytes = (ROOT / MAP_PROBE).read_bytes()
    assert hashlib.sha256(map_bytes).hexdigest() == MAP_PROBE_SHA256
    map_data = json.loads(map_bytes)
    report = {
        "read_only": True,
        "capstone_version": capstone.__version__,
        "candidate_mapping": "runtime address = 0x00FFFFD0 + file offset; only the ESC91 bootstrap block is in scope",
        "map_probe": {"path": MAP_PROBE, "sha256": MAP_PROBE_SHA256},
        "scope_limit": "This reconstructs the reset descriptor loop and bounded second-stage entry only. Calls through the external 0x03040000 descriptor/configuration area are unresolved; no complete application call graph or peripheral name is asserted.",
        "images": {},
    }
    for version, (relpath, expected_hash, expected_loader_file) in IMAGES.items():
        data = (ROOT / relpath).read_bytes()
        actual_hash = hashlib.sha256(data).hexdigest()
        assert actual_hash == expected_hash
        loader_start = expected_loader_file
        loader_code = decode(data, loader_start, loader_start + 0x1C)
        # The first two PC-relative loads in this loop provide the descriptor
        # table bounds. Resolve them from instruction bytes, not guessed offsets.
        pointers = []
        for ins in DECODER.disasm(data[loader_start:loader_start + 0x1C], BASE + loader_start):
            if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1 and ins.operands[1].type == ARM_OP_MEM and ins.operands[1].mem.base == ARM_REG_PC:
                literal_runtime = ((ins.address + 4) & ~3) + ins.operands[1].mem.disp
                literal_offset = literal_runtime - BASE
                pointers.append({"instruction_file_offset": f"0x{ins.address-BASE:X}", "literal_file_offset": f"0x{literal_offset:X}", "literal_value": f"0x{word(data, literal_offset):08X}"})
        assert len(pointers) >= 2
        table_start = int(pointers[0]["literal_value"], 16) - BASE
        table_end = int(pointers[1]["literal_value"], 16) - BASE
        descriptors = []
        for offset in range(table_start, table_end, 0x10):
            values = struct.unpack_from("<4I", data, offset)
            fn = values[3] & ~1
            fn_file = fn - BASE
            descriptors.append({"descriptor_file_offset": f"0x{offset:X}", "words": [f"0x{x:08X}" for x in values], "handler_runtime": f"0x{values[3]:08X}", "handler_file_offset": f"0x{fn_file:X}", "handler_body": decode(data, fn_file, min(fn_file + 0x20, len(data)))})
        handoff_word = word(data, 0x2FC)
        handoff_target = (handoff_word & ~1) - BASE
        second_stage_start = 0x96C
        # Calls in the directly seeded windows reveal the calls to the
        # descriptor writer's record-walker and the dynamic callback veneer.
        call_xrefs = []
        for start, end in ((0x300, 0x400), (0x5D0, 0x6F0), (0x6F0, 0x822), (second_stage_start, 0xA10)):
            for ins in DECODER.disasm(data[start:end], BASE + start):
                if ins.id == ARM_INS_BL and ins.operands and ins.operands[0].type == ARM_OP_IMM:
                    target = ins.operands[0].imm & ~1
                    if target in (0x010002D4, 0x010002DC, 0x01000362):
                        call_xrefs.append({"caller_file_offset": f"0x{ins.address-BASE:X}", "caller_runtime": f"0x{ins.address:08X}", "instruction": f"{ins.mnemonic} {ins.op_str}", "target_runtime": f"0x{target:08X}", "target_file_offset": f"0x{target-BASE:X}"})
        report["images"][version] = {
            "path": relpath,
            "sha256": actual_hash,
            "reset_trampoline": {"file_offset": "0x2F0", "disassembly": decode(data, 0x2F0, 0x300), "handoff_literal_file_offset": "0x2FC", "handoff_literal": f"0x{handoff_word:08X}", "second_stage_file_offset": f"0x{handoff_target:X}", "second_stage_disassembly": decode(data, second_stage_start, 0xA10)},
            "reset_descriptor_loop": {"entry_file_offset": f"0x{loader_start:X}", "entry_runtime": f"0x{BASE+loader_start:08X}", "disassembly": loader_code, "table_bound_literals": pointers[:2], "descriptor_file_range": [f"0x{table_start:X}", f"0x{table_end:X}"], "descriptors": descriptors},
            "descriptor_register_helper": {"runtime": "0x010002DC", "file_offset": "0x30C", "literal_file_offset": "0x3B8", "literal_value": f"0x{word(data, 0x3B8):08X}", "disassembly": decode(data, 0x30C, 0x390)},
            "direct_call_xrefs_in_bounded_windows": call_xrefs,
            "dynamic_boundary": {"second_stage_config_base_candidate": "0x03040000", "observed_callback_load": "[r4 + 0x28]", "call_veneer_runtime": "0x010002D4", "veneer_disassembly": decode(data, 0x304, 0x30C), "interpretation": "The veneer sets the Thumb bit on its input and branches indirectly. The external configuration/callback value is not present in this bounded image mapping, so the register helper at 0x010002DC is not proven reachable from the reset path here."},
        }
    out_path = ROOT / "firmware/work/katana-startup-register-path.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    print(out_path.relative_to(ROOT))
    print(hashlib.sha256(out_path.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
