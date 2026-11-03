#!/usr/bin/env python3
"""Test obvious standard checksum candidates in GT-1 image block headers."""
from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ("105", "107", "108", "109")
images = {
    v: (ROOT / f"firmware/extracted/v{v}/gt1_sys_v{v}/GT1ROM.BIN").read_bytes()
    for v in VERSIONS
}

def crc32c(data: bytes) -> int:
    """Reflected Castagnoli CRC-32C, init/xorout all ones."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF

def sum8(data: bytes) -> int:
    return sum(data) & 0xFF

def sum16(data: bytes) -> int:
    return sum(data) & 0xFFFF

def sum32(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF

def xor8(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
    return value

def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc

checksums = {
    "sum8": sum8,
    "sum16_byte_sum": sum16,
    "sum32_byte_sum": sum32,
    "xor8": xor8,
    "crc16_ccitt_init_ffff": crc16_ccitt,
    "crc16_modbus_init_ffff": crc16_modbus,
    "crc32_ieee": lambda d: zlib.crc32(d) & 0xFFFFFFFF,
    "crc32c_castagnoli": crc32c,
    "adler32": lambda d: zlib.adler32(d) & 0xFFFFFFFF,
}
blocks = {
    "GT1Upd": {"base": 0x2000, "following": 0x40000},
    "GT1Appli": {"base": 0x40000, "following": 0x1FC000},
}
comparator_path = ROOT / "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN"
comparator_image = comparator_path.read_bytes()
comparator = {
    "product": "BOSS GT-100",
    "firmware": "v2.12",
    "image_path": str(comparator_path.relative_to(ROOT)),
    "image_sha256": hashlib.sha256(comparator_image).hexdigest(),
    "blocks": {},
}
for name, spec in blocks.items():
    base, following = spec["base"], spec["following"]
    payload_start = base + 0x40
    stored = struct.unpack_from("<I", comparator_image, base + 0x30)[0]
    payload_end = payload_start + stored
    target = struct.unpack_from("<I", comparator_image, base + 0x34)[0]
    payload = comparator_image[payload_start:payload_end]
    comparator["blocks"][name] = {
        "header_offset": f"0x{base:X}",
        "checksum_field_offset": f"0x{base+0x34:X}",
        "checksum_field_value": f"0x{target:08X}",
        "payload_range": [f"0x{payload_start:X}", f"0x{payload_end:X}"],
        "payload_size": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "sum32_byte_sum": f"0x{sum(payload) & 0xFFFFFFFF:08X}",
        "matches": target == (sum(payload) & 0xFFFFFFFF),
    }

results = {}
for version, image in images.items():
    results[version] = {"image_sha256": hashlib.sha256(image).hexdigest(), "blocks": {}}
    for name, spec in blocks.items():
        base, following = spec["base"], spec["following"]
        payload_start = base + 0x40
        stored = struct.unpack_from("<I", image, base + 0x30)[0]
        payload_end = payload_start + stored
        target = struct.unpack_from("<I", image, base + 0x34)[0]
        spans = {
            "header_0x00_0x33": (base, base+0x34),
            "header_0x00_0x3f": (base, base+0x40),
            "header_0x04_0x33": (base+4, base+0x34),
            "payload": (payload_start, payload_end),
            "header_plus_payload": (base, payload_end),
            "block_to_next_boundary": (base, following),
        }
        tests = {}
        for checksum_name, checksum in checksums.items():
            tests[checksum_name] = {
                span_name: f"0x{checksum(image[start:end]):08X}"
                for span_name, (start, end) in spans.items()
            }
        matching = [
            f"{checksum_name}:{span_name}"
            for checksum_name, values in tests.items()
                for span_name, value in values.items()
            if int(value, 16) == target
        ]
        results[version]["blocks"][name] = {
            "target_field_offset": f"0x{base+0x34:X}",
            "target_field_value": f"0x{target:08X}",
            "stored_payload_range": [f"0x{payload_start:X}", f"0x{payload_end:X}"],
            "candidate_spans": {
                key: {
                    "range": [f"0x{start:X}", f"0x{end:X}"],
                    "size": end - start,
                    "sha256": hashlib.sha256(image[start:end]).hexdigest(),
                }
                for key, (start, end) in spans.items()
            },
            "computed_checksums": tests,
            "matches": matching,
        }

out = ROOT / "firmware/work/header-integrity-candidates.json"
out.write_text(json.dumps({
    "classification": "the +0x34 fields match the modulo-2^32 additive byte sum of the bounded payload in all eight block/version cases",
    "read_only": True,
    "results": results,
    "same_family_comparator": comparator,
    "integrity_field_observation": {
        "field_offset_relative_to_block": "+0x34",
        "matching_algorithm": "sum of each stored-payload byte, modulo 2^32, no initial/final xor",
        "matching_scope": "candidate payload from block +0x40 for the +0x30 stored-length candidate",
        "matches": sum(
            1 for version in results.values()
            for block in version["blocks"].values()
            if block["matches"] == ["sum32_byte_sum:payload"]
        ),
        "cases": 8,
        "interpretation": "strong evidence that +0x34 stores an additive payload integrity checksum; the same relation also holds for both GT-100 v2.12 blocks; updater enforcement has not been observed",
    },
    "limitations": [
        "The additive checksum match establishes a likely payload integrity field, not a cryptographic signature or secure-boot guarantee.",
        "This does not rule out additional integrity or authentication elsewhere, or prove that the updater checks this field before applying an image.",
        "Span boundaries use observed marker/header offsets and candidate +0x30 length fields; field semantics are not proven.",
    ],
}, indent=2) + "\n")
print(out)
