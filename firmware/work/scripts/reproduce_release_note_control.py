#!/usr/bin/env python3
"""Compare GT-1 v1.08/v1.09 bytes against BOSS's v1.09 release note."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "firmware/work/release-note-control-evidence.json"
paths = {
    "1.08": ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN",
    "1.09": ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN",
}
images = {version: path.read_bytes() for version, path in paths.items()}
if any(len(image) != 0x400000 for image in images.values()):
    raise ValueError("expected two 4 MiB GT-1 images")

v108, v109 = images["1.08"], images["1.09"]
changed_offsets = [i for i, (a, b) in enumerate(zip(v108, v109)) if a != b]
app_partition = (0x40000, 0x1FC000)
app_start = 0x40040
v108_payload_len = struct.unpack_from("<I", v108, 0x40030)[0]
v109_payload_len = struct.unpack_from("<I", v109, 0x40030)[0]
v108_payload_end = app_start + v108_payload_len
v109_payload_end = app_start + v109_payload_len
bounded_offsets = [
    i for i in range(app_start, v108_payload_end) if v108[i] != v109[i]
]
outside_partition = [
    i for i in changed_offsets if not app_partition[0] <= i < app_partition[1]
]
payload_outside = [
    i for i in changed_offsets if not app_start <= i < v108_payload_end
]

result = {
    "classification": "same-file-offset byte comparison; release-note context only",
    "source": {
        "boss_release_history": "https://www.boss.info/us/support/by_product/gt-1/updates_drivers/076a30a8-a319-4891-94e4-ef0bb08451e5/",
        "v1.09_statement": "version number updated for management-related circumstances; product specifications unaffected",
    },
    "images": {
        version: {
            "path": str(paths[version].relative_to(ROOT)),
            "size": len(images[version]),
            "sha256": hashlib.sha256(images[version]).hexdigest(),
        }
        for version in images
    },
    "comparison": {
        "total_changed_bytes": len(changed_offsets),
        "broad_application_partition": {
            "start": f"0x{app_partition[0]:X}",
            "end_exclusive": f"0x{app_partition[1]:X}",
            "changed_bytes": sum(app_partition[0] <= i < app_partition[1] for i in changed_offsets),
        },
        "outside_broad_application_partition": {
            "changed_bytes": len(outside_partition),
            "offsets": [f"0x{i:X}" for i in outside_partition],
        },
        "v108_length_bounded_app_payload": {
            "start": f"0x{app_start:X}",
            "end_exclusive": f"0x{v108_payload_end:X}",
            "length": v108_payload_len,
            "same_file_offset_changed_bytes": len(bounded_offsets),
            "same_file_offset_changed_fraction": round(len(bounded_offsets) / v108_payload_len, 8),
            "v109_declared_payload_length": v109_payload_len,
            "v109_end_exclusive": f"0x{v109_payload_end:X}",
            "changes_outside_v108_bounded_payload": len(payload_outside),
        },
        "interpretation_limit": "A broad byte rewrite despite the management-only release note does not establish functional change, compression, encryption, or any particular transform.",
    },
}
OUT.write_text(json.dumps(result, indent=2) + "\n")
print(f"wrote {OUT.relative_to(ROOT)}")
print(json.dumps(result["comparison"], indent=2))
