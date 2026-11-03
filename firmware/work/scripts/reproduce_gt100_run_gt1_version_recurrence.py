#!/usr/bin/env python3
"""Check whether the longest GT-1/GT-100 exact app runs recur in GT-1 releases.

Read-only. This is byte identity evidence only, with app-bound checks; it does
not classify matched runs as executable code, shared algorithms, or relocation.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMPARISON = ROOT / "firmware/work/gt100-gt1-comparator-evidence.json"
VERSIONS = ("v105", "v107", "v108", "v109")
IMAGES = {
    v: ROOT / "firmware/extracted" / v / f"gt1_sys_{v}" / "GT1ROM.BIN"
    for v in VERSIONS
}
GT100_PATH = ROOT / "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN"
GT100_RANGE = (0x40040, 0x17689C)
LIMIT = 100


def hits(blob: bytes, needle: bytes, start: int, end: int) -> list[int]:
    result = []
    pos = start
    while (pos := blob.find(needle, pos, end)) >= 0:
        result.append(pos)
        pos += 1
    return result


def main() -> None:
    comparison = json.loads(COMPARISON.read_text())
    runs = comparison["byte_exact_app_matches"]["longest_runs"][:LIMIT]
    images = {v: path.read_bytes() for v, path in IMAGES.items()}
    ranges = {}
    for v, data in images.items():
        start = 0x40040
        size = struct.unpack_from("<I", data, 0x40030)[0]
        ranges[v] = (start, start + size)
    gt100 = GT100_PATH.read_bytes()
    result = {
        "read_only": True,
        "question": "Do the top GT-1/GT-100 byte-exact app runs also recur in GT-1 v1.05-v1.08?",
        "method": "For each of the top 100 maximal GT-1/GT-100 exact runs, verify source bytes and SHA-256, then search the full exact sequence inside each GT-1 release's bounded stored app payload.",
        "interpretation_limit": "Exact recurrence establishes byte identity only; it does not prove executable code, semantic equivalence, or a relocation relationship. Sequences may be repeated table/data content.",
        "inputs": {},
        "source_run_count_examined": len(runs),
        "runs": [],
    }
    for v, path in IMAGES.items():
        result["inputs"][v] = {
            "path": str(path.relative_to(ROOT)),
            "sha256": hashlib.sha256(images[v]).hexdigest(),
            "app_range": [hex(x) for x in ranges[v]],
        }
    result["inputs"]["GT-100 v2.12"] = {
        "path": str(GT100_PATH.relative_to(ROOT)),
        "sha256": hashlib.sha256(gt100).hexdigest(),
        "app_range": [hex(x) for x in GT100_RANGE],
    }
    v109 = images["v109"]
    for row in runs:
        source_offset = int(row["GT-1_file_offset"], 16)
        gt100_offset = int(row["GT-100_file_offset"], 16)
        length = row["length"]
        needle = v109[source_offset:source_offset + length]
        if len(needle) != length or gt100[gt100_offset:gt100_offset + length] != needle:
            raise ValueError(f"comparison run failed byte verification at {row['GT-1_file_offset']}")
        item = {
            "GT1_v109_offset": hex(source_offset),
            "GT100_v212_offset": hex(gt100_offset),
            "length": length,
            "GT100_minus_GT1_delta": row["delta_GT100_minus_GT1"],
            "sha256": hashlib.sha256(needle).hexdigest(),
            "GT1_release_occurrences": {},
        }
        for v, data in images.items():
            start, end = ranges[v]
            item["GT1_release_occurrences"][v] = [hex(x) for x in hits(data, needle, start, end)]
        result["runs"].append(item)
    out = ROOT / "firmware/work/gt100-run-gt1-version-recurrence.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(out.relative_to(ROOT))
    for item in result["runs"][:20]:
        prior = {v: x for v, x in item["GT1_release_occurrences"].items() if v != "v109" and x}
        if prior:
            print(item["GT1_v109_offset"], item["GT100_v212_offset"],
                  "len", item["length"], "prior", prior)


if __name__ == "__main__":
    main()
