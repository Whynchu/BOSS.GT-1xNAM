#!/usr/bin/env python3
"""Record version-diff and byte-pattern evidence for reported GT-1 offsets."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = {
    v: ROOT / "firmware/extracted" / v / f"gt1_sys_{v}" / "GT1ROM.BIN"
    for v in ("v108", "v109")
}
REGIONS = {
    "looper_big_endian_candidate": (0x0B8900, 0x0B8940),
    "looper_table_candidate": (0x0BEBD0, 0x0BEC10),
    "app_data_start": (0x1FC000, 0x1FC100),
    "reported_effect_parameter_table": (0x1FE000, 0x1FE100),
    "reported_sparse_tail": (0x331758, 0x3317A0),
}
images = {v: p.read_bytes() for v, p in VERSIONS.items()}
out = {
    "read_only": True,
    "interpretation_limit": "Byte patterns and version stability do not establish semantic role, address mapping, or runtime use.",
    "images": {
        v: {"path": str(VERSIONS[v].relative_to(ROOT)), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for v, data in images.items()
    },
    "regions": {},
}
for name, (start, end) in REGIONS.items():
    region = {"start": f"0x{start:06X}", "end_exclusive": f"0x{end:06X}", "versions": {}}
    slices = {}
    for v, data in images.items():
        chunk = data[start:end]
        slices[v] = chunk
        region["versions"][v] = {
            "sha256": hashlib.sha256(chunk).hexdigest(),
            "bytes_hex": chunk.hex(" "),
            "unique_byte_values": len(set(chunk)),
            "zero_count": chunk.count(0),
            "ff_count": chunk.count(0xFF),
            "little_endian_u32": [
                {"offset": f"0x{start+i:06X}", "value": f"0x{struct.unpack_from('<I', chunk, i)[0]:08X}"}
                for i in range(0, max(0, len(chunk) - 3), 4)
            ],
        }
    a, b = slices["v108"], slices["v109"]
    region["same_bytes_across_versions"] = a == b
    region["differing_byte_count"] = sum(x != y for x, y in zip(a, b))
    out["regions"][name] = region

out["windows"] = {}
for name, (start, end) in {
    "around_0x0B8914": (0x0B8800, 0x0B8A00),
    "around_0x0BEBE4": (0x0BEB00, 0x0BEC80),
    "app_tail_0x1FC000_to_0x200000": (0x1FC000, 0x200000),
}.items():
    a, b = images["v108"][start:end], images["v109"][start:end]
    diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    out["windows"][name] = {
        "start": f"0x{start:06X}",
        "end_exclusive": f"0x{end:06X}",
        "size": end - start,
        "differing_bytes": len(diffs),
        "first_difference": f"0x{start+diffs[0]:06X}" if diffs else None,
        "last_difference": f"0x{start+diffs[-1]:06X}" if diffs else None,
    }

# Check whether the app contains literal startup/header anchors from ESC91.000.
# Their absence is not proof against shared runtime code or relocation; it only
# records that these particular byte sequences are not present in the app.
app_start = 0x40000
anchors = {
    "ESC91.000": b"ESC91.000",
    "reset_sp_0x01011240": bytes.fromhex("40 12 01 01"),
    "reset_pc_0x01000AE5": bytes.fromhex("E5 0A 00 01"),
    "GT1Upd_marker": b"BSSESC2:GT1Upd",
}
out["app_anchor_search"] = {}
for label, anchor in anchors.items():
    hits = {}
    for version, data in images.items():
        positions = []
        pos = app_start
        while True:
            pos = data.find(anchor, pos)
            if pos < 0:
                break
            positions.append(f"0x{pos:06X}")
            pos += 1
        hits[version] = positions
    out["app_anchor_search"][label] = {"needle_hex": anchor.hex(" "), "hits": hits}

out_path = ROOT / "firmware/work/gt1-candidate-region-evidence.json"
out_path.write_text(json.dumps(out, indent=2) + "\n")
print(out_path)
