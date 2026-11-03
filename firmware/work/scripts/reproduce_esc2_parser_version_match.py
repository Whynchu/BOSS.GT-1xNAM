#!/usr/bin/env python3
"""Verify the ESC2 SysEx parser/caller instruction match in GT-1 v1.08 and v1.09."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs, CS_GRP_CALL
from capstone.arm import ARM_OP_IMM

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = {
    "v105": {
        "sha256": "8297887084af48b04189955bbd8bdb4e0e6ff6a0e0fbcac7f85a175792775e29",
        "parser": 0x7CB5A,
        "caller": 0x7D3FE,
        "callsite": 0x7D52E,
        "normalize": 0x7CBE8,
        "store": 0x7CDF6,
        "classifier": 0x7C9A4,
    },
    "v107": {
        "sha256": "304b88a2c628cf47bb5091ecbc6da4fab4924f88cdea8897b44e5f474b9fb001",
        "parser": 0x7CD8E,
        "caller": 0x7D632,
        "callsite": 0x7D762,
        "normalize": 0x7CE1C,
        "store": 0x7D02A,
        "classifier": 0x7CBD8,
    },
    "v108": {
        "sha256": "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1",
        "parser": 0x7CDE2,
        "caller": 0x7D686,
        "callsite": 0x7D7B6,
        "normalize": 0x7CE70,
        "store": 0x7D07E,
        "classifier": 0x7CC2C,
    },
    "v109": {
        "sha256": "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29",
        "parser": 0x7E1F2,
        "caller": 0x7EA96,
        "callsite": 0x7EBC6,
        "normalize": 0x7E280,
        "store": 0x7E48E,
        "classifier": 0x7E03C,
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def insns(md: Cs, data: bytes, offset: int, count: int = 1):
    return list(md.disasm(data[offset : offset + 0x80], 0x60000000 + offset, count=count))


reports = {}
images = {}
for version, spec in VERSIONS.items():
    path = ROOT / f"firmware/work/decoded/{version}-GT1Appli.bin"
    data = path.read_bytes()
    digest = sha256(data)
    if digest != spec["sha256"]:
        raise SystemExit(f"{version} decoded app SHA-256 mismatch: {digest}")
    images[version] = data

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    call = next((i for i in insns(md, data, spec["callsite"]) if i.address == 0x60000000 + spec["callsite"]), None)
    if call is None or not call.group(CS_GRP_CALL) or not call.operands or call.operands[0].type != ARM_OP_IMM:
        raise SystemExit(f"{version}: expected direct parser call not decoded at 0x{spec['callsite']:x}")
    call_target = call.operands[0].imm
    if call_target != 0x60000000 + spec["parser"]:
        raise SystemExit(f"{version}: parser call target mismatch: 0x{call_target:x}")

    norm = insns(md, data, spec["normalize"], count=1)[0]
    store = insns(md, data, spec["store"], count=1)[0]
    if norm.mnemonic != "lsr.w" or "#1" not in norm.op_str:
        raise SystemExit(f"{version}: expected right-shift normalization at 0x{norm.address:x}")
    if store.mnemonic != "str.w":
        raise SystemExit(f"{version}: expected direct word store at 0x{store.address:x}")
    if spec["parser"] != spec["classifier"] + 0x1B6:
        raise SystemExit(f"{version}: parser/classifier relative offset changed")
    if spec["caller"] != spec["classifier"] + 0xA5A or spec["callsite"] != spec["caller"] + 0x130:
        raise SystemExit(f"{version}: caller/callsite relative offset changed")
    if spec["normalize"] != spec["parser"] + 0x8E or spec["store"] != spec["parser"] + 0x29C:
        raise SystemExit(f"{version}: parser normalization/store relative offset changed")

    address_builder = []
    for rel, expected in (
        (0x10A, "94f90800"),
        (0x10E, "94f90910"),
        (0x112, "4005"),
        (0x114, "40ea8130"),
        (0x118, "94f90a10"),
        (0x120, "40eac110"),
        (0x124, "94f90b10"),
        (0x128, "0143"),
    ):
        offset = spec["caller"] + rel
        instruction = insns(md, data, offset, count=1)[0]
        actual = data[offset : offset + instruction.size].hex()
        if actual != expected:
            raise SystemExit(f"{version}: packed SysEx address instruction mismatch at 0x{instruction.address:x}: {actual}")
        address_builder.append({
            "address": f"0x{instruction.address:x}",
            "bytes": actual,
            "text": f"{instruction.mnemonic} {instruction.op_str}",
        })

    caller_start = spec["caller"]
    caller_bytes = data[caller_start : spec["callsite"] + 4]
    reports[version] = {
        "path": str(path.relative_to(ROOT)),
        "sha256": digest,
        "parser_entry_offset": f"0x{spec['parser']:x}",
        "classifier_entry_offset": f"0x{spec['classifier']:x}",
        "caller_entry_offset": f"0x{caller_start:x}",
        "parser_callsite_offset": f"0x{spec['callsite']:x}",
        "parser_call_target": f"0x{call_target:x}",
        "normalization_instruction": {
            "address": f"0x{norm.address:x}",
            "bytes": data[spec["normalize"] : spec["normalize"] + norm.size].hex(),
            "text": f"{norm.mnemonic} {norm.op_str}",
        },
        "direct_store_instruction": {
            "address": f"0x{store.address:x}",
            "bytes": data[spec["store"] : spec["store"] + store.size].hex(),
            "text": f"{store.mnemonic} {store.op_str}",
        },
        "packed_sysEx_address_builder": address_builder,
        "caller_to_parser_bytes_sha256": sha256(caller_bytes),
        "caller_instructions": [
            {"address": f"0x{i.address:x}", "bytes": data[i.address - 0x60000000 : i.address - 0x60000000 + i.size].hex(), "text": f"{i.mnemonic} {i.op_str}"}
            for i in md.disasm(caller_bytes, 0x60000000 + caller_start)
        ],
    }

for earlier, later, delta in (("v105", "v107", 0x234), ("v107", "v108", 0x54), ("v108", "v109", 0x1410)):
    for field in ("parser_entry_offset", "caller_entry_offset", "parser_callsite_offset", "classifier_entry_offset"):
        if int(reports[later][field], 16) != int(reports[earlier][field], 16) + delta:
            raise SystemExit(f"{earlier}/{later}: unexpected {field} relocation delta")

classifier_size = 0xA4
classifier_bytes = {
    version: images[version][spec["classifier"] : spec["classifier"] + classifier_size]
    for version, spec in VERSIONS.items()
}
if len({sha256(code) for code in classifier_bytes.values()}) != 1:
    raise SystemExit("classifier instruction bytes differ across the four decoded versions")
raw_comparison = {
    "classifier_span_bytes": classifier_size,
    "versions": {
        version: {"offset": f"0x{spec['classifier']:x}", "sha256": sha256(classifier_bytes[version])}
        for version, spec in VERSIONS.items()
    },
    "byte_identical": True,
}

report = {
    "read_only": True,
    "method": "verify pinned decoded-app hashes; disassemble explicit parser/caller offsets in Thumb mode; assert direct call, right shift, direct STR, and common relocation delta",
    "interpretation_limit": "The matching instruction paths support version stability for this transfer utility only; they do not identify its numeric address unit, physical memory map, or relation to live audio processing.",
    "versions": reports,
    "raw_classifier_comparison": raw_comparison,
}
out = ROOT / "firmware/work/esc2-parser-version-match.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
for version, item in reports.items():
    print(version, item["sha256"], "parser", item["parser_entry_offset"], "caller", item["caller_entry_offset"], "call", item["parser_callsite_offset"], "->", item["parser_call_target"])
    print(" ", item["normalization_instruction"]["address"], item["normalization_instruction"]["text"])
    print(" ", item["direct_store_instruction"]["address"], item["direct_store_instruction"]["text"])
