#!/usr/bin/env python3
"""Reproduce read-only Katana v2.01/v4.00 same-offset firmware comparisons."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = {
    "v2.01": {
        "archive": ROOT / "firmware/work/reference/esc2-comparators/katana_v201/original/katana_sys_v201.zip",
        "image": ROOT / "firmware/work/reference/esc2-comparators/katana_v201/extracted/katana_sys_v201/KATANARM.BIN",
        "rominfo": ROOT / "firmware/work/reference/esc2-comparators/katana_v201/extracted/katana_sys_v201/ROMINFO.TXT",
    },
    "v4.00": {
        "archive": ROOT / "firmware/work/reference/esc2-comparators/katana_v400/original/katana_sys_v400.zip",
        "image": ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN",
        "rominfo": ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/ROMINFO.TXT",
    },
}
SPECS = {"updater": 0x2000, "application": 0x40000}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ranges(a: bytes, b: bytes) -> list[tuple[int, int]]:
    result = []
    start = None
    for i, (left, right) in enumerate(zip(a, b)):
        if left == right and start is None:
            start = i
        elif left != right and start is not None:
            result.append((start, i))
            start = None
    if start is not None:
        result.append((start, min(len(a), len(b))))
    return result


images = {version: item["image"].read_bytes() for version, item in VERSIONS.items()}
if any(len(image) != 0x400000 for image in images.values()):
    raise SystemExit("unexpected KATANA firmware image size")
left, right = images["v2.01"], images["v4.00"]

source_records = {}
for version, files in VERSIONS.items():
    archive = files["archive"].read_bytes()
    image = images[version]
    rominfo = files["rominfo"].read_bytes()
    source_records[version] = {
        "archive_path": str(files["archive"].relative_to(ROOT)),
        "archive_size": len(archive),
        "archive_sha256": sha(archive),
        "image_path": str(files["image"].relative_to(ROOT)),
        "image_size": len(image),
        "image_sha256": sha(image),
        "rominfo_path": str(files["rominfo"].relative_to(ROOT)),
        "rominfo_exact_hex": rominfo.hex(" "),
        "rominfo_ascii": rominfo.decode("ascii", "replace"),
    }

section_records = {}
for label, base in SPECS.items():
    versions = {}
    payloads = {}
    for version, image in images.items():
        stored = struct.unpack_from("<I", image, base + 0x30)[0]
        checksum = struct.unpack_from("<I", image, base + 0x34)[0]
        expanded = struct.unpack_from("<I", image, base + 0x3C)[0]
        start, end = base + 0x40, base + 0x40 + stored
        payload = image[start:end]
        payloads[version] = payload
        versions[version] = {
            "header_offset": f"0x{base:06X}",
            "label": image[base:base + 16].decode("ascii", "replace").rstrip("\0 "),
            "version_or_build_text": image[base + 16:base + 0x28].decode("ascii", "replace").rstrip("\0 "),
            "stored_length_offset": f"0x{base + 0x30:06X}",
            "stored_length": f"0x{stored:X}",
            "payload_start": f"0x{start:06X}",
            "payload_end_exclusive": f"0x{end:06X}",
            "payload_sha256": sha(payload),
            "checksum_field_offset": f"0x{base + 0x34:06X}",
            "checksum_field": f"0x{checksum:08X}",
            "payload_byte_sum_mod32": f"0x{sum(payload) & 0xFFFFFFFF:08X}",
            "checksum_equals_direct_byte_sum": checksum == (sum(payload) & 0xFFFFFFFF),
            "expanded_length_candidate_offset": f"0x{base + 0x3C:06X}",
            "expanded_length_candidate": f"0x{expanded:X}",
        }
    a, b = payloads["v2.01"], payloads["v4.00"]
    common = min(len(a), len(b))
    same = sum(x == y for x, y in zip(a, b))
    section_records[label] = {
        "versions": versions,
        "compared_min_payload_bytes": common,
        "same_offset_equal_bytes": same,
        "same_offset_equal_fraction": round(same / common, 8),
        "common_prefix_bytes": next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), common),
        "common_prefix_sha256": sha(a[:next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), common)]),
        "same_offset_identical_run_count": len(ranges(a, b)),
        "longest_same_offset_equal_runs": [
            {
                "file_start": f"0x{base + 0x40 + start:06X}",
                "file_end_exclusive": f"0x{base + 0x40 + end:06X}",
                "length": end - start,
                "sha256": sha(a[start:end]),
            }
            for start, end in sorted(ranges(a, b), key=lambda row: row[1] - row[0], reverse=True)[:10]
        ],
    }

bootstrap_runs = ranges(left[:0x2000], right[:0x2000])
bootstrap_same = sum(a == b for a, b in zip(left[:0x2000], right[:0x2000]))
report = {
    "read_only": True,
    "scope": "Official Katana v2.01/v4.00 package and same-file-offset comparison only.",
    "sources": source_records,
    "esc91_bootstrap": {
        "range": "0x000000–0x001FFF",
        "v201_marker": left[:9].decode("ascii", "replace"),
        "v400_marker": right[:9].decode("ascii", "replace"),
        "v201_sha256": sha(left[:0x2000]),
        "v400_sha256": sha(right[:0x2000]),
        "same_offset_equal_bytes": bootstrap_same,
        "same_offset_equal_fraction": round(bootstrap_same / 0x2000, 8),
        "same_offset_identical_run_count": len(bootstrap_runs),
        "longest_same_offset_equal_runs": [
            {
                "file_start": f"0x{start:06X}",
                "file_end_exclusive": f"0x{end:06X}",
                "length": end - start,
                "sha256": sha(left[start:end]),
            }
            for start, end in sorted(bootstrap_runs, key=lambda row: row[1] - row[0], reverse=True)[:10]
        ],
    },
    "sections": section_records,
    "interpretation": (
        "The first 8 KiB ESC91.000 region is highly stable at same file offsets across KATANA v2.01 and v4.00, "
        "while the bounded updater/application payloads are highly version-dependent apart from their 194-byte "
        "common prefix. These are byte comparisons, not code/data classification or runtime relocation evidence."
    ),
}
assert all(section["versions"][version]["checksum_equals_direct_byte_sum"] for section in section_records.values() for version in images)
assert all(section["common_prefix_bytes"] == 194 for section in section_records.values())
out = ROOT / "firmware/work/katana-version-comparison-evidence.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
