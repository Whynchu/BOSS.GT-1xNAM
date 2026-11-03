#!/usr/bin/env python3
"""Search all preserved GT-1 releases for the reported looper-size byte patterns.

Read-only: this script hashes the preserved official images, searches exact
three- and four-byte encodings of 0x409980, and records context around the two
reported candidate offsets. It does not infer that either occurrence is a
looper length or executable code.
"""
from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
IMAGES = {
    "v105": ROOT / "firmware/extracted/v105/gt1_sys_v105/GT1ROM.BIN",
    "v107": ROOT / "firmware/extracted/v107/gt1_sys_v107/GT1ROM.BIN",
    "v108": ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN",
    "v109": ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN",
}
VALUE = 0x409980
CANDIDATES = {
    "reported_big_endian_triplet": (0x0B8914, VALUE.to_bytes(3, "big")),
    "reported_little_endian_triplet": (0x0BEBE4, VALUE.to_bytes(3, "little")),
}

def all_hits(data: bytes, needle: bytes) -> list[int]:
    hits, start = [], 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return hits
        hits.append(pos)
        start = pos + 1

def main() -> None:
    result = {
        "question": "Do the reported byte sequences encode the proposed 0x409980 loop-buffer size?",
        "value": hex(VALUE),
        "arithmetic": "3 * 44100 * 32 = 4233600 = 0x409980",
        "interpretation_limit": "Matching byte order and value do not establish semantic use; the app payload transform and references are unknown.",
        "images": {},
    }
    for version, path in IMAGES.items():
        data = path.read_bytes()
        updater_end = 0x2040 + struct.unpack_from("<I", data, 0x2030)[0]
        app_end = 0x40040 + struct.unpack_from("<I", data, 0x40030)[0]
        image = {
            "path": str(path.relative_to(ROOT)),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "candidate_encodings": {},
        }
        for name, (expected_offset, needle) in CANDIDATES.items():
            hits = all_hits(data, needle)
            hit_contexts = []
            for hit in hits:
                if 0x2040 <= hit < updater_end:
                    region = "bounded updater payload"
                elif 0x40040 <= hit < app_end:
                    region = "bounded application payload"
                else:
                    region = "outside bounded updater/application payload spans"
                context_start = max(0, hit - 16)
                hit_contexts.append({
                    "offset": hex(hit),
                    "region": region,
                    "context_start": hex(context_start),
                    "context_hex": data[context_start:hit + len(needle) + 16].hex(" "),
                })
            image["candidate_encodings"][name] = {
                "bytes_hex": needle.hex(" "),
                "decoded_unsigned": int.from_bytes(needle, "big" if "big_endian" in name else "little"),
                "reported_offset": hex(expected_offset),
                "occurrences": [hex(x) for x in hits],
                "occurrence_contexts": hit_contexts,
                "reported_offset_is_hit": expected_offset in hits,
                "context_start": hex(max(0, expected_offset - 16)),
                "context_hex": data[max(0, expected_offset - 16):expected_offset + 32].hex(" "),
            }
        if version == "v109":
            # Fixed triplet grouping is illustrative only; record the values
            # without treating them as pointers or a confirmed table format.
            off = CANDIDATES["reported_little_endian_triplet"][0]
            image["candidate_triplet_view"] = [
                {"relative": hex(i), "bytes_hex": data[off+i:off+i+3].hex(" "),
                 "little_endian_value": hex(int.from_bytes(data[off+i:off+i+3], "little"))}
                for i in range(0, 48, 3)
            ]
            # Also scan every byte alignment around the hit for 24-bit little-
            # endian values in the adjacent 0x4099xx range. This tests whether
            # the exact size-like value sits among other address-like values.
            lo, hi = off - 0x80, off + 0x100
            image["nearby_le_0x4099xx_values"] = [
                {"relative": hex(p - off), "bytes_hex": data[p:p+3].hex(" "),
                 "value": hex(int.from_bytes(data[p:p+3], "little"))}
                for p in range(lo, hi - 2)
                if 0x409900 <= int.from_bytes(data[p:p+3], "little") < 0x409A00
            ]
        result["images"][version] = image
    out = ROOT / "firmware/work/looper-encoding-evidence.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(out.relative_to(ROOT))
    for v, im in result["images"].items():
        print(v, im["sha256"])
        for name, hit in im["candidate_encodings"].items():
            print(" ", name, "hits=", hit["occurrences"], "expected_hit=", hit["reported_offset_is_hit"])

if __name__ == "__main__":
    main()
