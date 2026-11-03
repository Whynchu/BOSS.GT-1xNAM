#!/usr/bin/env python3
"""Compare official GT-1B packages with GT-1 firmware structure.

Read-only. The goal is to characterize shared updater metadata and checksum
arithmetic without inferring undocumented ROMINFO field meanings.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GT1B_ROOT = ROOT / "firmware/work/reference/gt1b-comparator"
GT1_ROOT = ROOT / "firmware/extracted"
BLOCKS = {"updater": 0x2000, "application": 0x40000}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def inspect_image(path: Path, family: str, version: str) -> dict:
    image = path.read_bytes()
    rominfo_path = path.with_name("ROMINFO.TXT")
    rominfo = rominfo_path.read_bytes()
    archive_path = (
        ROOT / "firmware/original" / f"gt1_sys_{version}.zip"
        if family == "GT-1"
        else GT1B_ROOT / "original" / f"gt1b_sys_{version}.zip"
    )
    text = rominfo.decode("ascii")
    fields = text.strip().split(",")
    blocks = {}
    for name, base in BLOCKS.items():
        length = u32(image, base + 0x30)
        payload_start = base + 0x40
        payload_end = payload_start + length
        payload = image[payload_start:payload_end]
        stored_field = u32(image, base + 0x34)
        byte_sum = sum(payload) & 0xFFFFFFFF
        blocks[name] = {
            "header_offset": f"0x{base:06X}",
            "first_16_header_bytes": image[base : base + 16].hex(" "),
            "header_version_bytes": image[base + 0x20 : base + 0x28].decode("ascii", "replace"),
            "stored_length_field_0x30": f"0x{length:X}",
            "payload_start": f"0x{payload_start:06X}",
            "payload_end_exclusive": f"0x{payload_end:06X}",
            "payload_sha256": sha(payload),
            "checksum_field_0x34": f"0x{stored_field:08X}",
            "payload_byte_sum_mod32": f"0x{byte_sum:08X}",
            "field_equals_sum": stored_field == byte_sum,
            "field_equals_ones_complement_of_sum": stored_field == ((~byte_sum) & 0xFFFFFFFF),
            "field_plus_sum_equals_ffffffff": ((stored_field + byte_sum) & 0xFFFFFFFF) == 0xFFFFFFFF,
            "field_0x3c": f"0x{u32(image, base + 0x3C):08X}",
            "first_byte_after_payload": f"0x{image[payload_end]:02X}",
        }
    return {
        "family": family,
        "version": version,
        "image_path": str(path.relative_to(ROOT)),
        "image_size": len(image),
        "image_sha256": sha(image),
        "archive_path": str(archive_path.relative_to(ROOT)),
        "archive_size": archive_path.stat().st_size,
        "archive_sha256": sha(archive_path.read_bytes()),
        "rominfo_path": str(rominfo_path.relative_to(ROOT)),
        "rominfo_size": len(rominfo),
        "rominfo_sha256": sha(rominfo),
        "rominfo_raw_hex": rominfo.hex(" "),
        "rominfo_text_without_line_ending": text.rstrip("\r\n"),
        "rominfo_line_ending": "CRLF" if rominfo.endswith(b"\r\n") else "none",
        "rominfo_decimal_fields": [int(value) for value in fields],
        "blocks": blocks,
    }


records = []
for version in ("v105", "v107", "v108", "v109"):
    image = GT1_ROOT / version / f"gt1_sys_{version}" / "GT1ROM.BIN"
    records.append(inspect_image(image, "GT-1", version))
for version in ("v102", "v103", "v104"):
    image = GT1B_ROOT / f"gt1b_sys_{version}" / "GT1BROM.BIN"
    records.append(inspect_image(image, "GT-1B", version))

gt1b_bootstrap_reference = (GT1B_ROOT / "gt1b_sys_v104" / "GT1BROM.BIN").read_bytes()[:0x2000]
gt1_bootstrap = (GT1_ROOT / "v109" / "gt1_sys_v109" / "GT1ROM.BIN").read_bytes()[:0x2000]
all_rominfo = {r["rominfo_text_without_line_ending"] for r in records}
assert len(all_rominfo) == 1
assert all(r["image_size"] == 4 * 1024 * 1024 for r in records)
assert gt1_bootstrap == gt1b_bootstrap_reference
for record in records:
    for block in record["blocks"].values():
        assert block["first_byte_after_payload"] == "0xFF"
        if record["family"] == "GT-1":
            assert block["field_equals_sum"]
        else:
            assert block["field_equals_ones_complement_of_sum"]
result = {
    "classification": "static cross-product comparison of official update packages; no device interaction",
    "read_only": True,
    "limitations": [
        "ROMINFO field meanings are not inferred from repeated values or numeric coincidences.",
        "Checksum arithmetic shows a repeated relation to the bounded payload bytes; updater enforcement is not demonstrated.",
        "The GT-1B comparator is a related product, not proof that every GT-1B update behavior applies to GT-1.",
        "The +0x3c header word remains semantically unclassified; arithmetic does not validate decompression or expanded size.",
    ],
    "rominfo_normalized_text_unique_across_both_families": sorted(all_rominfo),
    "rominfo_content_same_across_both_families": len(all_rominfo) == 1,
    "GT1_v109_vs_GT1B_v104_first_0x2000_equal": gt1_bootstrap == gt1b_bootstrap_reference,
    "GT1_v109_vs_GT1B_v104_first_0x2000_sha256": sha(gt1_bootstrap),
    "records": records,
}
out = ROOT / "firmware/work/gt1-gt1b-comparator-evidence.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
