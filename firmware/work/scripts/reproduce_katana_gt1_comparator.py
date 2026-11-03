#!/usr/bin/env python3
"""Record read-only GT-1 v1.09 vs original KATANA v4.00 firmware evidence."""
from __future__ import annotations

import hashlib
import json
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GT1 = ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN"
ARCHIVE = ROOT / "firmware/work/reference/esc2-comparators/katana_v400/original/katana_sys_v400.zip"
KATANA = ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN"
ROMINFO = KATANA.with_name("ROMINFO.TXT")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def section(image: bytes, base: int) -> dict:
    stored = struct.unpack_from("<I", image, base + 0x30)[0]
    expected_sum = struct.unpack_from("<I", image, base + 0x34)[0]
    expanded_candidate = struct.unpack_from("<I", image, base + 0x3C)[0]
    start, end = base + 0x40, base + 0x40 + stored
    payload = image[start:end]
    return {
        "header_offset": f"0x{base:06X}",
        "header_label": image[base:base + 16].decode("ascii", "replace").rstrip("\0 "),
        "stored_length_offset": f"0x{base + 0x30:06X}",
        "stored_length": f"0x{stored:X}",
        "payload_start": f"0x{start:06X}",
        "payload_end_exclusive": f"0x{end:06X}",
        "stored_payload_sha256": sha(payload),
        "checksum_offset": f"0x{base + 0x34:06X}",
        "checksum_field": f"0x{expected_sum:08X}",
        "modulo_2_32_byte_sum": f"0x{sum(payload) & 0xFFFFFFFF:08X}",
        "checksum_equals_direct_sum": expected_sum == (sum(payload) & 0xFFFFFFFF),
        "expanded_length_candidate_offset": f"0x{base + 0x3C:06X}",
        "expanded_length_candidate": f"0x{expanded_candidate:X}",
        "first_64_payload_bytes": payload[:64].hex(" "),
    }


def common_prefix(a: bytes, b: bytes) -> int:
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))


gt1, katana = GT1.read_bytes(), KATANA.read_bytes()
archive = ARCHIVE.read_bytes()
rominfo = ROMINFO.read_bytes()
sections = {}
for label, base in (("updater", 0x2000), ("application", 0x40000)):
    g = section(gt1, base)
    k = section(katana, base)
    glen = int(g["stored_length"], 16)
    klen = int(k["stored_length"], 16)
    gp = gt1[base + 0x40:base + 0x40 + glen]
    kp = katana[base + 0x40:base + 0x40 + klen]
    prefix = common_prefix(gp, kp)
    sections[label] = {
        "GT-1_v1.09": g,
        "KATANA_v4.00": k,
        "common_prefix_bytes": prefix,
        "common_prefix_sha256": sha(gp[:prefix]),
        "common_prefix_exact_match": gp[:prefix] == kp[:prefix],
    }

first_8k_gt1, first_8k_katana = gt1[:0x2000], katana[:0x2000]
assert len(gt1) == len(katana) == 0x400000
assert first_8k_gt1[:9] == first_8k_katana[:9] == b"ESC91.000"
assert all(v["GT-1_v1.09"]["checksum_equals_direct_sum"] for v in sections.values())
assert all(v["KATANA_v4.00"]["checksum_equals_direct_sum"] for v in sections.values())
assert all(v["common_prefix_bytes"] == 194 for v in sections.values())

with zipfile.ZipFile(ARCHIVE) as zf:
    archive_members = [
        {"name": item.filename, "size": item.file_size, "crc32": f"0x{item.CRC:08X}"}
        for item in zf.infolist()
    ]

report = {
    "read_only": True,
    "scope": "Static package and binary comparison; no device access or firmware modification.",
    "sources": {
        "GT-1_v1.09": {
            "path": str(GT1.relative_to(ROOT)),
            "size": len(gt1),
            "sha256": sha(gt1),
        },
        "KATANA_v4.00_archive": {
            "path": str(ARCHIVE.relative_to(ROOT)),
            "size": len(archive),
            "sha256": sha(archive),
            "members": archive_members,
        },
        "KATANA_v4.00_image": {
            "path": str(KATANA.relative_to(ROOT)),
            "size": len(katana),
            "sha256": sha(katana),
            "rominfo_exact_bytes_hex": rominfo.hex(" "),
            "rominfo_ascii": rominfo.decode("ascii", "replace"),
        },
    },
    "esc91_initial_block": {
        "range": "0x000000–0x001FFF",
        "GT-1_label": first_8k_gt1[:9].decode("ascii"),
        "KATANA_label": first_8k_katana[:9].decode("ascii"),
        "GT-1_sha256": sha(first_8k_gt1),
        "KATANA_sha256": sha(first_8k_katana),
        "byte_identical": first_8k_gt1 == first_8k_katana,
        "different_byte_positions_count": sum(a != b for a, b in zip(first_8k_gt1, first_8k_katana)),
        "common_prefix_bytes": common_prefix(first_8k_gt1, first_8k_katana),
    },
    "sections": sections,
    "interpretation": (
        "GT-1 and original KATANA v4.00 use an ESC91.000 first block and structurally similar "
        "0x40-byte updater/application headers. Both bounded payloads share the first 194 bytes "
        "with GT-1. This is cross-product format/content evidence only; it does not identify the "
        "payload transform, prove that the common bytes are executable, establish application ISA, "
        "or show that KATANA firmware is compatible with GT-1."
    ),
}
out = ROOT / "firmware/work/katana-gt1-comparator-evidence.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
