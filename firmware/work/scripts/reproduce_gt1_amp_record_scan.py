#!/usr/bin/env python3
"""Locate plaintext amp/preset parameter records in the GT-1 application.

Read-only static analysis over the already-decoded application section.

Record shape under test:

    53 07 | 16-byte ASCII name | 00 00 00 | parameter bytes

The `53 07` prefix is observed before every candidate name; its meaning is not
established. Parameter bytes are in the same small-integer encoding as patch
data (`0x32` = 50, `0x64` = 100), and the editor's known custom defaults
(`sp_size 7`, `sp_color_low/high 10`, `sp_num 2`, `sp_cabinet 0`) appear
verbatim inside records, which is what makes this table a candidate for
amp/preset voicing data rather than display text.

This script reports candidate records, name and address, the gap to the next
candidate, whether the record is referenced by an aligned pointer, and the
frequency of the editor default signature. It does not claim a record layout,
a field map, or runtime use.

Output: firmware/work/gt1-amp-record-scan.json
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = 0x60000000
DECODED = ROOT / "firmware/work/decoded/v108-GT1Appli.bin"
EXPECTED_SHA256 = "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1"
OUT = ROOT / "firmware/work/gt1-amp-record-scan.json"

# custom_* defaults from the community editor's default.tsl, in patch order:
# bottom, edge, [gap], preamp_low, preamp_high, char, sp_size,
# sp_color_low, sp_color_high, sp_num, sp_cabinet
EDITOR_CUSTOM_SIGNATURE = bytes((50, 50, 50, 50, 50, 7, 10, 10, 2, 0))


def u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def main() -> None:
    d = DECODED.read_bytes()
    digest = hashlib.sha256(d).hexdigest()
    assert digest == EXPECTED_SHA256, digest

    records = []
    for o in range(0, len(d) - 19):
        if d[o] != 0x53 or d[o + 1] != 0x07:
            continue
        name = d[o + 2:o + 18]
        if not re.fullmatch(rb"[ -~]{16}", name):
            continue
        records.append({
            "file_offset": o,
            "runtime": BASE + o,
            "name": name.decode("latin-1").rstrip(),
            "name_terminated": d[o + 18:o + 21] == b"\x00\x00\x00",
            "pointer_refs": [
                p for p in range(0, len(d) - 4, 4)
                if u32(d, p) in (BASE + o, BASE + o + 1)
            ],
        })

    for i, rec in enumerate(records):
        rec["gap_to_next"] = (records[i + 1]["file_offset"] - rec["file_offset"]
                              if i + 1 < len(records) else None)

    gaps = Counter(r["gap_to_next"] for r in records if r["gap_to_next"])
    named_ok = sum(1 for r in records if r["name_terminated"])
    pointed = sum(1 for r in records if r["pointer_refs"])
    signature_hits = [m.start() for m in re.finditer(re.escape(EDITOR_CUSTOM_SIGNATURE), d)]

    out = {
        "read_only": True,
        "input": "firmware/work/decoded/v108-GT1Appli.bin",
        "input_sha256": digest,
        "record_shape_under_test": "53 07 | 16-byte name | 00 00 00 | parameter bytes",
        "candidate_records": len(records),
        "names_with_three_null_terminator": named_ok,
        "records_referenced_by_aligned_pointer": pointed,
        "gap_histogram": {str(k): v for k, v in sorted(gaps.items(), key=lambda kv: -kv[1])[:12]},
        "editor_custom_default_signature": EDITOR_CUSTOM_SIGNATURE.hex(),
        "editor_custom_default_signature_hits": [hex(x) for x in signature_hits],
        "records": [
            {
                "file_offset": hex(r["file_offset"]),
                "runtime": hex(r["runtime"]),
                "name": r["name"],
                "name_terminated": r["name_terminated"],
                "gap_to_next": r["gap_to_next"],
                "pointer_refs": [hex(x) for x in r["pointer_refs"]],
            }
            for r in records
        ],
        "limits": [
            "The 53 07 prefix meaning is unknown; it may be a tag, a length, or the tail of the preceding record.",
            "Printable name + parameter-looking bytes is structural inference, not proof of amp or preset semantics.",
            "Gap regularity in one region does not establish a global record size.",
            "No runtime consumption of these records has been demonstrated.",
        ],
    }
    OUT.write_text(json.dumps(out, indent=2) + "\n")

    print(f"candidate records           {len(records)}")
    print(f"  with 00 00 00 terminator  {named_ok}")
    print(f"  referenced by pointer     {pointed}")
    print("most common gaps:")
    for gap, count in gaps.most_common(6):
        print(f"  {gap:#06x} ({gap}) x {count}")
    print(f"editor custom-default signature hits: {[hex(x) for x in signature_hits]}")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
