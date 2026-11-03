#!/usr/bin/env python3
"""Hash-check GT-1 decoded app images and inventory ESC2 transfer strings/register literals."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = {
    "v105": ("8297887084af48b04189955bbd8bdb4e0e6ff6a0e0fbcac7f85a175792775e29", 0x7CE34),
    "v107": ("304b88a2c628cf47bb5091ecbc6da4fab4924f88cdea8897b44e5f474b9fb001", 0x7D068),
    "v108": ("c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1", 0x7D0BC),
    "v109": ("2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29", 0x7E4CC),
}
REGISTERS = (0x40100900, 0x40100000, 0x40100904)
TRANSFER_HELPERS = {
    "v105": {"read_code": 0x58BC0, "read_literals": (0x58FCC, 0x58FD0, 0x58FD4), "write_code": 0x58AE0, "write_literals": (0x58B50, 0x58B54)},
    "v107": {"read_code": 0x58DC8, "read_literals": (0x591D4, 0x591D8, 0x591DC), "write_code": 0x58CE8, "write_literals": (0x58D58, 0x58D5C)},
    "v108": {"read_code": 0x58E1C, "read_literals": (0x59228, 0x5922C, 0x59230), "write_code": 0x58D3C, "write_literals": (0x58DAC, 0x58DB0)},
    "v109": {"read_code": 0x57A20, "read_literals": (0x57E2C, 0x57E30, 0x57E34), "write_code": 0x57940, "write_literals": (0x579B0, 0x579B4)},
}
STRINGS = (
    b"CPrmESC2DT1",
    b"PRG Set without DSP Halt",
    b"DRP Set without DSP Halt",
)

def offsets(data: bytes, needle: bytes) -> list[int]:
    result = []
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return result
        result.append(pos)
        pos += 1

versions = {}
for version, (expected_sha, expected_text_offset) in VERSIONS.items():
    path = ROOT / f"firmware/work/decoded/{version}-GT1Appli.bin"
    data = path.read_bytes()
    actual_sha = hashlib.sha256(data).hexdigest()
    if actual_sha != expected_sha:
        raise SystemExit(f"{version} decoded app SHA-256 mismatch: {actual_sha}")
    found_strings = {s.decode("ascii"): offsets(data, s) for s in STRINGS}
    if not found_strings["CPrmESC2DT1"] or found_strings["CPrmESC2DT1"][0] != expected_text_offset:
        raise SystemExit(f"{version} ESC2 transfer diagnostic cluster offset changed")
    register_occurrences = {
        f"0x{value:08x}": offsets(data, struct.pack("<I", value)) for value in REGISTERS
    }
    helper = TRANSFER_HELPERS[version]
    read_values = [struct.unpack_from("<I", data, offset)[0] for offset in helper["read_literals"]]
    write_values = [struct.unpack_from("<I", data, offset)[0] for offset in helper["write_literals"]]
    if read_values != [0x40100900, 0x40100000, 0x40100904]:
        raise SystemExit(f"{version} read-helper literal values changed: {read_values}")
    if write_values != [0x40100900, 0x40100904]:
        raise SystemExit(f"{version} write-helper literal values changed: {write_values}")
    versions[version] = {
        "path": str(path.relative_to(ROOT)),
        "sha256": actual_sha,
        "CPrmESC2DT1_string_offsets": [f"0x{x:x}" for x in found_strings["CPrmESC2DT1"]],
        "PRG_without_halt_string_offsets": [f"0x{x:x}" for x in found_strings["PRG Set without DSP Halt"]],
        "DRP_without_halt_string_offsets": [f"0x{x:x}" for x in found_strings["DRP Set without DSP Halt"]],
        "register_word_offsets": {
            value: [f"0x{x:x}" for x in positions]
            for value, positions in register_occurrences.items()
        },
        "transfer_helper_crosscheck": {
            "candidate_read_helper_payload_offset": f"0x{helper['read_code']:x}",
            "candidate_write_helper_payload_offset": f"0x{helper['write_code']:x}",
            "read_helper_literal_offsets": [f"0x{x:x}" for x in helper["read_literals"]],
            "read_helper_literal_values": [f"0x{x:08x}" for x in read_values],
            "write_helper_literal_offsets": [f"0x{x:x}" for x in helper["write_literals"]],
            "write_helper_literal_values": [f"0x{x:08x}" for x in write_values],
        },
    }
    if version == "v109":
        for value, offset in ((0x40100900, 0x57E2C), (0x40100000, 0x57E30), (0x40100904, 0x57E34)):
            actual = struct.unpack_from("<I", data, offset)[0]
            if actual != value:
                raise SystemExit(f"v109 expected 0x{value:08x} at payload offset 0x{offset:x}, got 0x{actual:08x}")

report = {
    "read_only": True,
        "method": "verify decoded app hashes; locate ESC2 transfer diagnostics/register words and validate MMIO literal windows at bounded read/write helper candidates in all four versions",
    "versions": versions,
    "v109_register_literal_window": {
        "payload_offsets": ["0x57e2c", "0x57e30", "0x57e34"],
        "words": ["0x40100900", "0x40100000", "0x40100904"],
        "runtime_candidate_addresses": ["0x60057e2c", "0x60057e30", "0x60057e34"],
        "limits": "literal windows are only address-value evidence; bounded Ghidra disassembly/decompilation reports supply code references for read, status-poll, and write roles in each version",
    },
}
out = ROOT / "firmware/work/esc2-transfer-register-probe.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
for version, item in versions.items():
    print(version, item["sha256"])
    for value, positions in item["register_word_offsets"].items():
        print(" ", value, "count", len(positions), "offsets", ", ".join(positions))
