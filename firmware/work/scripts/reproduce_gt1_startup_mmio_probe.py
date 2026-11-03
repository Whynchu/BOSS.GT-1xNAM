#!/usr/bin/env python3
"""Reproduce bounded GT-1 v1.08/v1.09 startup MMIO evidence.

The script disassembles only the reachable shared-app windows discussed in
docs/GT1-RESEARCH-PLAN.md. Peripheral names are intentionally not inferred.
Requires Capstone's Python bindings.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

ROOT = Path(__file__).resolve().parents[3]
BASE = 0x60000000
VERSIONS = {
    "v1.08": {
        "path": "firmware/work/decoded/v108-GT1Appli.bin",
        "sha256": "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1",
        "report": "firmware/work/ghidra-combined-v108-app-02003-entry-dispatch.txt",
        "report_sha256": "509c4203898846b81f91c969f9b69352588de8a3e2f29b09b3a55670235ba252",
        "windows": [[0x302, 0x342], [0x342, 0x3A0], [0x3A0, 0x3CE], [0x3F4, 0x440], [0x440, 0x46A], [0x46A, 0x4A8], [0x4A8, 0x500], [0x233E, 0x23C4]],
    },
    "v1.09": {
        "path": "firmware/work/decoded/v109-GT1Appli.bin",
        "sha256": "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29",
        "report": "firmware/work/ghidra-combined-v109-app-02003-entry-dispatch.txt",
        "report_sha256": "42bc3071bf1095bd0c3f5351c071f5569a2a94c1584ad32defbe279e156ce61e",
        "windows": [[0x302, 0x342], [0x342, 0x39E], [0x39E, 0x3CE], [0x3F4, 0x440], [0x440, 0x46A], [0x46A, 0x4A8], [0x4A8, 0x500], [0x233E, 0x23C4]],
    },
}
COMPARATORS = {
    "Katana v2.01": {"path": "firmware/work/reference/esc2-comparators/katana_v201/extracted/katana_sys_v201/KATANARM.BIN", "sha256": "73b63f48050818e6e1cc0738d741e50ce8dcc6f644109cf8ec346a44dff1bdac"},
    "Katana v4.00": {"path": "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN", "sha256": "3e17ba95e21ed10a3cb5c60af8da0a375db613cc8409eb33b6d80e4248c9b493"},
    "GT-100 v2.12": {"path": "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN", "sha256": "0c44ab01ac310927bf8dcc95f4ab5fcc487ed106dfcc6fc067832a35a4e32d34"},
    "FA-08 v2.01": {"path": "firmware/work/reference/esc2-comparators/fa08_v201/extracted/fa060708_sys_v201/FA_UPA.BIN", "sha256": "2b13d943af307525f52d2fdae3cc3446b7933adf1afa9530b1d3ba11c4f6d358"},
    "FA-08 v2.02": {"path": "firmware/work/reference/esc2-comparators/fa08_v202/extracted/fa060708_sys_v202/FA_UPA.BIN", "sha256": "c618d0c533f8c3705e1f181512c4eb8039e5a5a862d3f0902fe5bf33feaa5181"},
    "FA-08 v2.03": {"path": "firmware/work/reference/esc2-comparators/fa08_v203/extracted/fa060708_sys_v203/FA_UPA.BIN", "sha256": "4e4182a334455b02f7935b0f6cca00b2a16b9b53f533b4d650b17939694bec96"},
}

LITERALS = list(range(0x500, 0x540, 4))
MMIO_INTERPRETATION = [
    {"version_scope": "v1.08 and v1.09", "code": "0x60000302", "literal_offset": "0x508", "register": "0x40007804", "accesses": [{"offset": "0x0", "operation": "read-modify-write; set bit 26"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x60000302", "literal_offset": "0x50C", "register": "0x40025000", "accesses": [{"offset": "0x8", "operation": "read-modify-write; clear bit 7"}, {"offset": "0x28", "operation": "read-modify-write; clear bit 7"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x60000302", "literal_offset": "0x510", "register": "0x4002E000", "accesses": [{"offset": "0x8 + i*0x10", "operation": "read-modify-write; set bit 6 for i=0..3"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x60000302", "literal_offset": "0x514", "register": "0x40021184", "accesses": [{"offset": "0x0", "operation": "read-modify-write; replace low byte with 0xFE"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x60000342, 0x6000039E", "literal_offset": "0x500", "register": "0x6025F68C (v1.08); 0x60260C88 (v1.09)", "accesses": [{"offset": "configuration fields", "operation": "build configuration records and call 0x6000233E/0x60002448"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x6000233E", "literal_offset": "0x23C4", "register": "0x4002D400", "accesses": [{"offset": "descriptor-derived index", "operation": "read-modify-write byte lanes in 32-bit words; input is a halfword descriptor stream"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x60000342", "literal_offset": "0x518", "register": "0x4002D000", "accesses": [{"offset": "0x0", "operation": "write 3"}, {"offset": "0x10", "operation": "write 0"}, {"offset": "0x18", "operation": "write 0"}, {"offset": "0x30", "operation": "write 0x00FF0000"}, {"offset": "0x20", "operation": "write 0"}, {"offset": "0x28", "operation": "write 0"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x6000046A", "literal_offset": "0x524", "register": "0x4002D800", "accesses": [{"offset": "0x0", "operation": "clear bits 20-21, then set bit 20"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x6000046A", "literal_offset": "0x528", "register": "0x40023000", "accesses": [{"offset": "0x0", "operation": "set bit 7"}, {"offset": "0x4", "operation": "clear bit 7"}, {"offset": "0x14", "operation": "set bit 7"}, {"offset": "0x18", "operation": "clear bit 7"}, {"offset": "0x10", "operation": "set bit 7"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x600004A8", "literal_offset": "0x534", "register": "0x4002E0F0", "accesses": [{"offset": "0x0", "operation": "write 0"}, {"offset": "0x4", "operation": "write 0"}]},
    {"version_scope": "v1.08 and v1.09", "code": "0x600004A8", "literal_offset": "0x538", "register": "0x4002DFFC", "accesses": [{"offset": "0x0", "operation": "read-modify-write; set bits 8, 28, and 29"}]},
]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    result = {"purpose": "Bounded static record of reachable pre-callback register accesses; register function names are unknown.", "address_mapping": "decoded app file offset = address - 0x60000000 for the analyzed shared window", "versions": {}, "interpretation": MMIO_INTERPRETATION, "related_product_literal_scan": {"method": "aligned little-endian 32-bit word scan across preserved extracted images; occurrences are not instruction xrefs and may be data", "addresses": [f"0x{x:08X}" for x in sorted({0x40007804, 0x40025000, 0x4002E000, 0x40021184, 0x4002D000, 0x4002D400, 0x4002D800, 0x40023000, 0x4002E0F0, 0x4002DFFC})], "images": {}}}
    for version, meta in VERSIONS.items():
        blob = (ROOT / meta["path"]).read_bytes()
        report = (ROOT / meta["report"]).read_bytes()
        assert digest(blob) == meta["sha256"], f"input hash changed: {version}"
        assert digest(report) == meta["report_sha256"], f"Ghidra report hash changed: {version}"
        literals = {f"0x{off:04X}": f"0x{struct.unpack_from('<I', blob, off)[0]:08X}" for off in LITERALS}
        decoded = []
        for start, end in meta["windows"]:
            file_start, file_end = start, end
            lines = []
            for ins in md.disasm(blob[file_start:file_end], BASE + file_start):
                lines.append({"address": f"0x{ins.address:08X}", "bytes": ins.bytes.hex(), "mnemonic": ins.mnemonic, "operands": ins.op_str})
            decoded.append({"start": f"0x{BASE+start:08X}", "end_exclusive": f"0x{BASE+end:08X}", "instructions": lines})
        helper_literal = struct.unpack_from("<I", blob, 0x23C4)[0]
        assert helper_literal == 0x4002D400, f"configuration helper literal changed: {version}"
        result["versions"][version] = {"input": meta["path"], "input_sha256": digest(blob), "ghidra_report": meta["report"], "ghidra_report_sha256": digest(report), "literal_pool_file_offsets_0x500_0x53f": literals, "descriptor_helper_literal": {"file_offset": "0x23C4", "value": f"0x{helper_literal:08X}"}, "disassembly_windows": decoded}
    scan_values = {int(value, 16) for value in result["related_product_literal_scan"]["addresses"]}
    for name, meta in COMPARATORS.items():
        relpath, expected_hash = meta["path"], meta["sha256"]
        blob = (ROOT / relpath).read_bytes()
        assert digest(blob) == expected_hash, f"comparator hash changed: {name}"
        hits = {f"0x{value:08X}": [] for value in sorted(scan_values)}
        for offset in range(0, len(blob) - 3, 4):
            value = struct.unpack_from("<I", blob, offset)[0]
            if value in scan_values:
                hits[f"0x{value:08X}"].append(f"0x{offset:X}")
        result["related_product_literal_scan"]["images"][name] = {"path": relpath, "sha256": digest(blob), "hits": {key: offsets for key, offsets in hits.items() if offsets}}
        if name.startswith("Katana"):
            # Candidate Thumb bootstrap mapping is separately recorded in
            # katana-esc91-map-probe.json. Seed the mixed code/data area at
            # file offset 0x30C to avoid decoding from the image origin.
            candidate_base = 0x00FFFFD0
            start, end = 0x30C, 0x390
            refs = []
            instructions = []
            for ins in md.disasm(blob[start:end], candidate_base + start):
                instructions.append({"runtime_address_under_candidate_map": f"0x{ins.address:08X}", "file_offset": f"0x{ins.address-candidate_base:X}", "bytes": ins.bytes.hex(), "mnemonic": ins.mnemonic, "operands": ins.op_str})
                if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1 and ins.operands[1].type == ARM_OP_MEM and ins.operands[1].mem.base == ARM_REG_PC:
                    target = ((ins.address + 4) & ~3) + ins.operands[1].mem.disp
                    target_offset = target - candidate_base
                    if 0 <= target_offset <= len(blob) - 4:
                        word = struct.unpack_from("<I", blob, target_offset)[0]
                        if word in scan_values:
                            refs.append({"instruction_file_offset": f"0x{ins.address-candidate_base:X}", "instruction_runtime_address_under_candidate_map": f"0x{ins.address:08X}", "instruction_bytes": ins.bytes.hex(), "instruction": f"{ins.mnemonic} {ins.op_str}", "literal_file_offset": f"0x{target_offset:X}", "literal_value": f"0x{word:08X}"})
            result["related_product_literal_scan"]["images"][name]["candidate_thumb_code_window"] = {"file_offsets": [f"0x{start:X}", f"0x{end:X}"], "runtime_base_hypothesis": "0x00FFFFD0 + file_offset", "instruction_references": refs, "disassembly": instructions}
    out = ROOT / "firmware/work/gt1-startup-mmio-probe.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(out.relative_to(ROOT))
    print(digest(out.read_bytes()))


if __name__ == "__main__":
    main()
