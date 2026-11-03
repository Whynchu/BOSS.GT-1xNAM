#!/usr/bin/env python3
"""Reproduce v1.08/v1.09 startup pool descriptor and zero-range mapping."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = 0x01000300
VERSIONS = {
    "v108": {
        "segment_sha256": "5691f04c08e52373973725ede20ff9de0bc3fc0e77a160e856a11342701168a0",
        "count_literal": 0x01001CE4,
        "records_pointer_literal": 0x01001CEC,
        "object_workspace_literal": 0x01001CE8,
        "name_index_literals": [0x01001CF0, 0x01001CF8],
        "name_pointer_literal": 0x01001CF4,
    },
    "v109": {
        "segment_sha256": "019adcf28e4a12444d48699b0b2a386a1a5feb2e43b59d465c696ee42540b9f9",
        "count_literal": 0x01001D84,
        "records_pointer_literal": 0x01001D8C,
        "object_workspace_literal": 0x01001D88,
        "name_index_literals": [0x01001D90, 0x01001D98],
        "name_pointer_literal": 0x01001D94,
    },
}

handoff = json.loads((ROOT / "firmware/work/bootstrap-handoff-evidence.json").read_text())
evidence = {}
for version, cfg in VERSIONS.items():
    segment_path = ROOT / f"firmware/work/reconstructed/{version}-GT1Appli-seg0.bin"
    segment = segment_path.read_bytes()
    digest = hashlib.sha256(segment).hexdigest()
    if digest != cfg["segment_sha256"]:
        raise SystemExit(f"{version} segment SHA-256 mismatch: {digest}")

    def word(address: int) -> int:
        offset = address - BASE
        if offset < 0 or offset + 4 > len(segment):
            raise ValueError(f"address outside copied segment: 0x{address:08x}")
        return struct.unpack_from("<I", segment, offset)[0]

    def halfword(address: int) -> int:
        offset = address - BASE
        return struct.unpack_from("<H", segment, offset)[0]

    app = next(x for x in handoff["loader_to_selected_image"]["decoded_outputs"] if x["version"] == version)["sections"]["application"]
    zero_ranges = []
    for op in app["zero_operations_from_startup_literals"]:
        start = int(op["destination"], 16)
        end = int(op["destination_end_exclusive"], 16)
        if end > start:
            zero_ranges.append((start, end))

    count_struct = word(cfg["count_literal"])
    count_a = halfword(count_struct)
    count_b = halfword(count_struct + 2)
    records_struct = word(cfg["records_pointer_literal"])
    records = word(records_struct)
    workspace = word(cfg["object_workspace_literal"])
    name_table = word(cfg["name_pointer_literal"])
    name_values = [halfword(word(lit)) for lit in cfg["name_index_literals"]]
    names = []
    for offset in (0, 0x10):
        ptr = name_table + offset
        off = ptr - BASE
        end = segment.find(b"\0", off, min(off + 64, len(segment)))
        if end < 0:
            raise SystemExit(f"{version}: unterminated pool name at 0x{ptr:08x}")
        names.append(segment[off:end].decode("ascii"))

    pool_records = []
    for index in range(count_b):
        record_address = records + index * 16
        identifier, flags, size, start = struct.unpack_from("<4I", segment, record_address - BASE)
        end = start + size
        containing_zero_range = next(
            (f"0x{a:08x}-0x{b:08x}" for a, b in zero_ranges if a <= start and end <= b), None
        )
        pool_records.append({
            "record_address": f"0x{record_address:08x}",
            "id": identifier,
            "flags": f"0x{flags:08x}",
            "start": f"0x{start:08x}",
            "size_bytes": size,
            "end_exclusive": f"0x{end:08x}",
            "fully_inside_startup_zero_range": containing_zero_range,
        })

    if count_b != 2 or [r["id"] for r in pool_records] != name_values:
        raise SystemExit(f"{version}: name index and pool descriptor IDs do not match")
    if [r["fully_inside_startup_zero_range"] for r in pool_records] == [None, None]:
        raise SystemExit(f"{version}: neither pool descriptor overlaps a recovered zero range")

    for index, row in enumerate(pool_records):
        row["name"] = names[index]

    evidence[version] = {
        "segment": str(segment_path.relative_to(ROOT)),
        "segment_sha256": digest,
        "callback_entry": "0x01001c48" if version == "v108" else "0x01001ce8",
        "metadata": {
            "record_count": count_b,
            "object_count_field": count_a,
            "records_pointer": f"0x{records:08x}",
            "object_workspace": f"0x{workspace:08x}",
            "name_indices": name_values,
            "names": names,
        },
        "pool_records": pool_records,
        "zero_ranges": [f"0x{a:08x}-0x{b:08x}" for a, b in zero_ranges],
    }

result = {
    "read_only": True,
    "method": "resolve callback-9 copied literals, two 16-byte pool records, names, and compare pool regions with startup zero descriptors",
    "interpretation_limits": [
        "The names and address/size fields are directly observed; exact allocator semantics and downstream users are not identified.",
        "The recovered zero descriptors establish these ranges are zero-filled at startup, not that they are free for NAM use.",
        "The nominal sizes are only the two named pool regions and are not the total free/available RAM budget.",
    ],
    "versions": evidence,
}
out = ROOT / "firmware/work/gt1-startup-pool-map.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
for version, item in evidence.items():
    print(version)
    for pool in item["pool_records"]:
        print(f"  {pool['name']}: {pool['start']}+0x{pool['size_bytes']:x} -> {pool['end_exclusive']} zeroed={pool['fully_inside_startup_zero_range']}")
