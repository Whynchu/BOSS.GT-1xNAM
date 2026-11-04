#!/usr/bin/env python3
"""Reproduce bounded Cortex-M startup evidence in GT-1 v1.08 and v1.09.

Reads the hash-verified reconstructed first-copy segments and decoded app
images in the project workspace. Prints JSON to stdout and does not modify
inputs or write output files.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_MCLASS, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

PROJECT = Path(__file__).resolve().parents[3]
BASE = 0x01000300
VERSIONS = {
    "v1.08": {
        "segment": "firmware/work/reconstructed/v108-GT1Appli-seg0.bin",
        "segment_sha256": "5691f04c08e52373973725ede20ff9de0bc3fc0e77a160e856a11342701168a0",
        "decoded_app": "firmware/work/decoded/v108-GT1Appli.bin",
        "decoded_app_sha256": "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1",
        "startup": 0x010010AE,
        "startup_length": 0x52,
        "rate_init": 0x010020A4,
        "svc_setup": 0x0100468C,
        "basepri": 0x010045DC,
        "handler": 0x010045DD,
    },
    "v1.09": {
        "segment": "firmware/work/reconstructed/v109-GT1Appli-seg0.bin",
        "segment_sha256": "019adcf28e4a12444d48699b0b2a386a1a5feb2e43b59d465c696ee42540b9f9",
        "decoded_app": "firmware/work/decoded/v109-GT1Appli.bin",
        "decoded_app_sha256": "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29",
        "startup": 0x0100114E,
        "startup_length": 0x50,
        "rate_init": 0x01002144,
        "svc_setup": 0x01004728,
        "basepri": 0x01004678,
        "handler": 0x01004679,
    },
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def disassemble(blob: bytes, address: int, length: int) -> list[dict[str, str]]:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN | CS_MODE_MCLASS)
    md.detail = True
    start = address - BASE
    rows = []
    for ins in md.disasm(blob[start:start + length], address):
        row = {"address": f"0x{ins.address:08X}", "bytes": ins.bytes.hex(),
               "mnemonic": ins.mnemonic, "operands": ins.op_str}
        if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1:
            op = ins.operands[1]
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                literal = ((ins.address + 4) & ~3) + op.mem.disp
                offset = literal - BASE
                if 0 <= offset <= len(blob) - 4:
                    row["literal_address"] = f"0x{literal:08X}"
                    row["literal_value"] = f"0x{struct.unpack_from('<I', blob, offset)[0]:08X}"
        rows.append(row)
    return rows


def main() -> None:
    result = {
        "classification": "reproduced static code/data evidence; ARM M-profile behavior strongly supported, exact ESC2 core and clock unproven",
        "method": "Thumb-M disassembly of hash-pinned app startup and reconstructed first-copy segments; resolve PC-relative literal loads",
        "versions": {},
        "interpretation_limits": [
            "Writing 0x01000000 to 0xE000ED08 is consistent with setting Cortex-M VTOR to the relocated vector table; it does not identify the exact core.",
            "BASEPRI, SVC, and VTOR behavior supports an M-profile execution environment; it does not prove FPU, DSP extensions, clock rate, or NAM timing.",
            "The divide/remainder initializer's descriptor semantics are unknown and are not identified as audio scheduling.",
        ],
    }
    for version, meta in VERSIONS.items():
        segment = (PROJECT / meta["segment"]).read_bytes()
        app = (PROJECT / meta["decoded_app"]).read_bytes()
        assert sha(segment) == meta["segment_sha256"], f"segment hash mismatch: {version}"
        assert sha(app) == meta["decoded_app_sha256"], f"app hash mismatch: {version}"
        result["versions"][version] = {
            "segment_sha256": sha(segment), "decoded_app_sha256": sha(app),
            "startup": disassemble(segment, meta["startup"], meta["startup_length"]),
            "divide_remainder_initializer": disassemble(segment, meta["rate_init"], 0x30),
            "vector_and_svc_setup": disassemble(segment, meta["svc_setup"], 0x22),
            "basepri_helpers": disassemble(segment, meta["basepri"], 0x2E),
            "svc_handler_thumb_pointer": f"0x{meta['handler']:08X}",
        }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
