#!/usr/bin/env python3
"""Measure repeated fixed-size blocks in bounded Roland firmware payloads.

Motivated by a separate TR-6S/BMC analysis that used repeated 8-byte blocks as
an ECB-like encryption clue. This script applies only the repeat statistic to
hashed GT-1 stored payloads. It does not identify encryption or a cipher.
"""
from __future__ import annotations

import collections
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ("v105", "v107", "v108", "v109")
FILES = {
    v: ROOT / "firmware/extracted" / v / f"gt1_sys_{v}" / "GT1ROM.BIN"
    for v in VERSIONS
}
SECTIONS = {"updater": 0x2000, "application": 0x40000}
BLOCK_SIZES = (8, 16)
ALIGNMENT_OFFSETS = (0, 194, 199)


def summarize(data: bytes, size: int) -> dict:
    count = len(data) // size
    blocks = [data[i * size:(i + 1) * size] for i in range(count)]
    freq = collections.Counter(blocks)
    duplicate_blocks = sum(n for n in freq.values() if n > 1)
    excess_duplicate_blocks = sum(n - 1 for n in freq.values() if n > 1)
    repeated_groups = sorted(
        ((n, block) for block, n in freq.items() if n > 1), reverse=True
    )
    return {
        "block_size": size,
        "complete_blocks": count,
        "unique_blocks": len(freq),
        "blocks_in_repeated_groups": duplicate_blocks,
        "blocks_in_repeated_groups_fraction": duplicate_blocks / count if count else 0,
        "excess_copies_after_first": excess_duplicate_blocks,
        "excess_copy_fraction": excess_duplicate_blocks / count if count else 0,
        "largest_repeat_count": repeated_groups[0][0] if repeated_groups else 1,
        "top_repeated_values": [
            {"count": n, "bytes_hex": block.hex(" ")}
            for n, block in repeated_groups[:10]
        ],
    }


def main() -> None:
    result = {
        "question": "Do bounded GT-1 payloads show the high repeated-block rate reported for a different Roland platform?",
        "read_only": True,
        "method": {
            "block_sizes": list(BLOCK_SIZES),
            "payload_relative_start_offsets": list(ALIGNMENT_OFFSETS),
            "measure": "Count exact fixed-size blocks; report all blocks participating in repeat groups and excess copies after first.",
            "limits": [
                "Repeated blocks can arise from padding, initialized data, tables, or encryption modes; this statistic alone identifies no cipher.",
                "Lack of repeats does not rule out encryption in non-ECB modes.",
                "The TR-6S comparator is a different product/platform and supplies only a motivation for this probe.",
            ],
        },
        "images": {},
    }
    for version, path in FILES.items():
        image = path.read_bytes()
        v = {"path": str(path.relative_to(ROOT)), "image_size": len(image),
             "image_sha256": hashlib.sha256(image).hexdigest(), "sections": {}}
        for section, header in SECTIONS.items():
            stored = struct.unpack_from("<I", image, header + 0x30)[0]
            start = header + 0x40
            payload = image[start:start + stored]
            record = {
                "header_offset": hex(header),
                "payload_start": hex(start),
                "payload_length": len(payload),
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "alignments": {},
            }
            for cut in ALIGNMENT_OFFSETS:
                if cut >= len(payload):
                    continue
                region = payload[cut:]
                record["alignments"][str(cut)] = {
                    "absolute_file_offset": hex(start + cut),
                    "region_length": len(region),
                    "region_sha256": hashlib.sha256(region).hexdigest(),
                    "block_statistics": [summarize(region, size) for size in BLOCK_SIZES],
                }
            v["sections"][section] = record
        result["images"][version] = v
    out = ROOT / "firmware/work/roland-payload-block-repetition.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(out.relative_to(ROOT))
    for version, image in result["images"].items():
        for section, row in image["sections"].items():
            for cut, alignment in row["alignments"].items():
                stats = alignment["block_statistics"]
                print(version, section, "cut", cut,
                      "8B repeats", f"{stats[0]['blocks_in_repeated_groups_fraction']:.4f}",
                      "16B repeats", f"{stats[1]['blocks_in_repeated_groups_fraction']:.4f}")


if __name__ == "__main__":
    main()
