#!/usr/bin/env python3
"""Verify stable GT-1 ESC2 SysEx transfer-state anchors across four app versions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, CS_GRP_CALL, Cs
from capstone.arm import ARM_OP_IMM

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = {
    "v105": {"sha256": "8297887084af48b04189955bbd8bdb4e0e6ff6a0e0fbcac7f85a175792775e29", "parser": 0x7CB5A, "state": 0x7D3FE},
    "v107": {"sha256": "304b88a2c628cf47bb5091ecbc6da4fab4924f88cdea8897b44e5f474b9fb001", "parser": 0x7CD8E, "state": 0x7D632},
    "v108": {"sha256": "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1", "parser": 0x7CDE2, "state": 0x7D686},
    "v109": {"sha256": "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29", "parser": 0x7E1F2, "state": 0x7EA96},
}
BASE = 0x60000000
READ_CALL_REL = 0x130
RESPONSE_CALL_REL = 0x1DE
RESPONSE_BUILDER_REL = 0x540
RESPONSE_HEADER_REL = 0x80
HEADER_BUILD_BYTES = bytes.fromhex("f0218df8001041218df8011010218df802103c218df8031012218df80410")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_one(md: Cs, data: bytes, offset: int):
    ins = next(md.disasm(data[offset:offset + 4], BASE + offset, count=1), None)
    if ins is None:
        raise SystemExit(f"could not decode instruction at 0x{BASE + offset:x}")
    return ins


def call_target(md: Cs, data: bytes, offset: int) -> int:
    ins = decode_one(md, data, offset)
    if not ins.group(CS_GRP_CALL) or not ins.operands or ins.operands[0].type != ARM_OP_IMM:
        raise SystemExit(f"expected direct call at 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
    return ins.operands[0].imm


md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True
records = {}
for name, spec in VERSIONS.items():
    path = ROOT / f"firmware/work/decoded/{name}-GT1Appli.bin"
    data = path.read_bytes()
    digest = sha(data)
    if digest != spec["sha256"]:
        raise SystemExit(f"{name} decoded app SHA-256 mismatch: {digest}")

    parser = spec["parser"]
    state = spec["state"]
    expected_parser = BASE + parser
    expected_builder = BASE + parser + RESPONSE_BUILDER_REL
    read_target = call_target(md, data, state + READ_CALL_REL)
    response_target = call_target(md, data, state + RESPONSE_CALL_REL)
    if read_target != expected_parser:
        raise SystemExit(f"{name}: state parser call target mismatch: 0x{read_target:x}")
    if response_target != expected_builder:
        raise SystemExit(f"{name}: response-builder call target mismatch: 0x{response_target:x}")

    builder = parser + RESPONSE_BUILDER_REL
    prefix_off = builder + RESPONSE_HEADER_REL
    prefix = data[prefix_off:prefix_off + len(HEADER_BUILD_BYTES)]
    if prefix != HEADER_BUILD_BYTES:
        raise SystemExit(f"{name}: response SysEx header construction bytes differ at 0x{BASE + prefix_off:x}")

    command_check = []
    for relative in (0x48, 0x4C, 0x52):
        ins = decode_one(md, data, state + relative)
        command_check.append({
            "address": f"0x{ins.address:x}",
            "bytes": data[state + relative:state + relative + ins.size].hex(),
            "instruction": f"{ins.mnemonic} {ins.op_str}",
        })
    if "0x3c0000" not in command_check[0]["instruction"] or "0x1100" not in command_check[1]["instruction"] or "0x100" not in command_check[2]["instruction"]:
        raise SystemExit(f"{name}: command discriminator instruction sequence changed")

    records[name] = {
        "decoded_app": str(path.relative_to(ROOT)),
        "decoded_app_sha256": digest,
        "state_machine_candidate": f"0x{BASE + state:x}",
        "parser_candidate": f"0x{expected_parser:x}",
        "read_payload_parser_call": {
            "address": f"0x{BASE + state + READ_CALL_REL:x}",
            "target": f"0x{read_target:x}",
        },
        "read_response_builder_call": {
            "address": f"0x{BASE + state + RESPONSE_CALL_REL:x}",
            "target": f"0x{response_target:x}",
        },
        "response_builder_candidate": f"0x{expected_builder:x}",
        "response_header_build_offset": f"0x{BASE + prefix_off:x}",
        "response_header_build_bytes": prefix.hex(),
        "incoming_command_discriminator_instructions": command_check,
    }

out = {
    "read_only": True,
    "method": "verify pinned decoded application hashes; disassemble stable state-machine callsites in Thumb mode; check common relative targets, command-discriminator instructions, and exact response-header construction bytes",
    "result": "The bounded protocol path is structurally stable across v1.05/v1.07/v1.08/v1.09. This does not prove checksum validation, device-side address semantics, physical memory mapping, or a connection to realtime audio.",
    "versions": records,
}
out_path = ROOT / "firmware/work/esc2-protocol-version-match.json"
out_path.write_text(json.dumps(out, indent=2) + "\n")
print(out_path.relative_to(ROOT))
