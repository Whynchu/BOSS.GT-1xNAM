#!/usr/bin/env python3
"""Correlate adjacent GT-1 release notes with bounded payload byte diffs."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ("105", "107", "108", "109")
PATHS = {
    v: ROOT / f"firmware/extracted/v{v}/gt1_sys_v{v}/GT1ROM.BIN"
    for v in VERSIONS
}
NOTES = {
    "105": "Bug fixes and functionality improvements, including output selection, effects, patch switching, and UI behavior.",
    "107": "Fix for delayed pitch-shifted audio after patch switching.",
    "108": "Bug fixes for switch combinations, FX type list display, and Tone Studio assignment clearing.",
    "109": "Version number changed for management-related circumstances; specifications unaffected.",
}
SOURCES = {
    "v1.05": "https://tw.boss.info/support/by_product/gt-1/updates_drivers/352151",
    "v1.07_v1.08_v1.09": "https://www.boss.info/us/support/by_product/gt-1/updates_drivers/076a30a8-a319-4891-94e4-ef0bb08451e5/",
}

images = {v: PATHS[v].read_bytes() for v in VERSIONS}
if any(len(data) != 0x400000 for data in images.values()):
    raise ValueError("all GT-1 images must be 4 MiB")

payloads = {}
for v, data in images.items():
    length = struct.unpack_from("<I", data, 0x40030)[0]
    start = 0x40040
    end = start + length
    if end > len(data):
        raise ValueError(f"v{v} payload candidate extends past image")
    payloads[v] = (start, end, data[start:end])

pairs = []
for earlier, later in zip(VERSIONS, VERSIONS[1:]):
    a_start, a_end, a = payloads[earlier]
    b_start, b_end, b = payloads[later]
    overlap = min(len(a), len(b))
    changed = sum(x != y for x, y in zip(a[:overlap], b[:overlap]))
    pairs.append({
        "earlier": f"v{earlier[:1]}.{earlier[1:]}",
        "later": f"v{later[:1]}.{later[1:]}",
        "note_categories": {
            f"v{earlier[:1]}.{earlier[1:]}": NOTES[earlier],
            f"v{later[:1]}.{later[1:]}": NOTES[later],
        },
        "comparison": "same file offsets from 0x40040 over the shorter declared payload length",
        "overlap_bytes": overlap,
        "changed_bytes": changed,
        "unchanged_bytes": overlap - changed,
        "changed_fraction": round(changed / overlap, 8),
        "earlier_payload": {"start": f"0x{a_start:X}", "end_exclusive": f"0x{a_end:X}", "length": len(a)},
        "later_payload": {"start": f"0x{b_start:X}", "end_exclusive": f"0x{b_end:X}", "length": len(b)},
    })

result = {
    "classification": "positional byte-diff and official release-note correlation; no semantics inferred",
    "sources": SOURCES,
    "images": {
        f"v{v[:1]}.{v[1:]}": {
            "path": str(PATHS[v].relative_to(ROOT)),
            "size": len(images[v]),
            "sha256": hashlib.sha256(images[v]).hexdigest(),
            "declared_payload_length_candidate": payloads[v][1] - payloads[v][0],
        }
        for v in VERSIONS
    },
    "adjacent_payload_comparisons": pairs,
    "interpretation_limit": "Large position-wise differences do not establish functional change, code/data boundaries, encryption, compression, or a particular normalization/rebuild transform; shifts and different encodings can reduce byte equality.",
}
out = ROOT / "firmware/work/release-note-correlation-evidence.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(f"wrote {out.relative_to(ROOT)}")
for item in pairs:
    print(f"{item['earlier']}→{item['later']}: {item['changed_bytes']}/{item['overlap_bytes']} changed ({item['changed_fraction']:.2%})")
