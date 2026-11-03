#!/usr/bin/env python3
"""Correlate reported 0x409980 byte-pattern hits across GT-1 releases.

Read-only byte-level evidence only. The script compares windows around each
hit and searches the four application payloads for exact repeated windows.
It does not infer code, pointer, table, or looper semantics.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ("v105", "v107", "v108", "v109")
IMAGES = {
    v: ROOT / "firmware/extracted" / v / f"gt1_sys_{v}" / "GT1ROM.BIN"
    for v in VERSIONS
}
NEEDLES = {
    "be_409980": bytes.fromhex("40 99 80"),
    "le_409980": bytes.fromhex("80 99 40"),
}
WINDOW_RADIUS = 24


def find_all(blob: bytes, needle: bytes, start: int, end: int) -> list[int]:
    found = []
    pos = start
    while (pos := blob.find(needle, pos, end)) >= 0:
        found.append(pos)
        pos += 1
    return found


def main() -> None:
    images = {v: p.read_bytes() for v, p in IMAGES.items()}
    bounds = {
        v: (0x40040, 0x40040 + struct.unpack_from("<I", data, 0x40030)[0])
        for v, data in images.items()
    }
    out = {
        "question": "Are 0x409980 pattern hits byte-identical or locally correlated across releases?",
        "read_only": True,
        "scope": "Exact byte-pattern searches and fixed-radius byte comparisons within candidate application payload bounds.",
        "limitations": [
            "Window equality is not proof of a code/data relationship or runtime use.",
            "Different offsets may reflect relocation, repacking, unrelated content, or version changes.",
            "No ISA, payload codec, or address map is assumed.",
        ],
        "versions": {},
        "hits": [],
        "candidate_window_matches": [],
        "v109_stride_probe": {},
    }
    for v, data in images.items():
        start, end = bounds[v]
        out["versions"][v] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "application_payload_candidate_bounds": [hex(start), hex(end)],
            "payload_sha256": hashlib.sha256(data[start:end]).hexdigest(),
        }
        for name, needle in NEEDLES.items():
            for off in find_all(data, needle, start, end):
                lo = max(start, off - WINDOW_RADIUS)
                hi = min(end, off + len(needle) + WINDOW_RADIUS)
                hit = {
                    "version": v,
                    "encoding": name,
                    "offset": hex(off),
                    "needle_hex": needle.hex(" "),
                    "window_start": hex(lo),
                    "window_end_exclusive": hex(hi),
                    "window_sha256": hashlib.sha256(data[lo:hi]).hexdigest(),
                    "window_hex": data[lo:hi].hex(" "),
                    "repeated_in_other_versions": [],
                }
                for other, other_data in images.items():
                    if other == v:
                        continue
                    other_start, other_end = bounds[other]
                    matches = find_all(other_data, data[lo:hi], other_start, other_end)
                    if matches:
                        hit["repeated_in_other_versions"].append(
                            {"version": other, "offsets": [hex(x) for x in matches]}
                        )
                out["hits"].append(hit)
    # At each reported v1.09 offset, compare exact-radius windows at the same
    # file coordinate in earlier versions. This is positional evidence only.
    for off in (0x0B8914, 0x0BEBE4):
        item = {"reported_v109_offset": hex(off), "versions": {}}
        for v, data in images.items():
            lo = off - WINDOW_RADIUS
            hi = off + 3 + WINDOW_RADIUS
            item["versions"][v] = {
                "window_sha256": hashlib.sha256(data[lo:hi]).hexdigest(),
                "window_hex": data[lo:hi].hex(" "),
                "needle_at_center": data[off:off + 3].hex(" "),
            }
        out["candidate_window_matches"].append(item)
    # Examine 24-bit little-endian values at each possible 3-byte record
    # alignment in a fixed window around the table-like v1.09 occurrence.
    # This is descriptive only; it does not assume the records are pointers.
    data = images["v109"]
    center = 0x0BEBE4
    lo, hi = center - 0x60, center + 0x60
    for phase in range(3):
        records = []
        first = lo + ((phase - lo) % 3)
        for off in range(first, hi - 2, 3):
            records.append({
                "offset": hex(off),
                "relative_to_0x0BEBE4": hex(off - center),
                "bytes_hex": data[off:off + 3].hex(" "),
                "u24_le": hex(int.from_bytes(data[off:off + 3], "little")),
            })
        values = [int(r["u24_le"], 16) for r in records]
        deltas = [b - a for a, b in zip(values, values[1:])]
        out["v109_stride_probe"][str(phase)] = {
            "record_stride_bytes": 3,
            "record_start_phase_mod_3": phase,
            "range": [hex(lo), hex(hi)],
            "records": records,
            "successive_value_deltas": [hex(x) if x >= 0 else f"-0x{-x:X}" for x in deltas],
            "interpretation_limit": "Record alignment and values are observational only; no address-space interpretation is established.",
        }
    out_path = ROOT / "firmware/work/looper-candidate-correlation.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n")
    print(out_path.relative_to(ROOT))
    for h in out["hits"]:
        print(h["version"], h["encoding"], h["offset"],
              "window_matches=", h["repeated_in_other_versions"])


if __name__ == "__main__":
    main()
