#!/usr/bin/env python3
"""Resolve v1.09 startup callback 0 literal pointers against copied ranges."""
from __future__ import annotations

import hashlib
import json
import string
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = 0x01000300
SEGMENT = ROOT / "firmware/work/reconstructed/v109-GT1Appli-seg0.bin"
SEGMENT_SHA256 = "019adcf28e4a12444d48699b0b2a386a1a5feb2e43b59d465c696ee42540b9f9"
LITERALS = [0x010023BC, 0x010023C0, 0x010023C4, 0x010023C8, 0x010023CC, 0x010023D0, 0x010023D4]

data = SEGMENT.read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != SEGMENT_SHA256:
    raise SystemExit(f"segment SHA-256 mismatch: {digest}")

handoff = json.loads((ROOT / "firmware/work/bootstrap-handoff-evidence.json").read_text())
v109 = next(x for x in handoff["loader_to_selected_image"]["decoded_outputs"] if x["version"] == "v109")
copy_ranges = []
zero_ranges = []
for op in v109["sections"]["application"]["copy_operations_from_startup_literals"]:
    start = int(op["destination"], 16)
    end = int(op["destination_end_exclusive"], 16)
    if end > start:
        copy_ranges.append((start, end))
for op in v109["sections"]["application"]["zero_operations_from_startup_literals"]:
    start = int(op["destination"], 16)
    end = int(op["destination_end_exclusive"], 16)
    if end > start:
        zero_ranges.append((start, end))

rows = []
for address in LITERALS:
    offset = address - BASE
    value = struct.unpack_from("<I", data, offset)[0]
    mapped = next((f"0x{start:08x}-0x{end:08x}" for start, end in copy_ranges if start <= value < end), None)
    zeroed = next((f"0x{start:08x}-0x{end:08x}" for start, end in zero_ranges if start <= value < end), None)
    target_string = None
    value_offset = value - BASE
    if 0 <= value_offset < len(data):
        end = data.find(b"\0", value_offset, min(value_offset + 64, len(data)))
        if end >= 0:
            candidate = data[value_offset:end].decode("ascii", errors="ignore")
            if candidate and all(ch in string.printable and ch not in "\r\n\t\x0b\x0c" for ch in candidate):
                target_string = candidate
    rows.append({
        "literal_runtime_address": f"0x{address:08x}",
        "segment_file_offset": f"0x{offset:05x}",
        "literal_value": f"0x{value:08x}",
        "target_in_startup_copy": mapped,
        "target_in_startup_zero_range": zeroed,
        "target_initialization_class": "copied initialized bytes" if mapped else ("startup zero-filled storage" if zeroed else "unclassified by recovered copy/zero descriptors"),
        "target_ascii_string": target_string,
    })

result = {
    "read_only": True,
    "image": "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN (decoded/reconstructed app segment only)",
    "segment": str(SEGMENT.relative_to(ROOT)),
    "segment_sha256": digest,
    "callback_entry": "0x01002308",
    "literal_values": rows,
    "interpretation_limits": [
        "Targets are classified only against recovered nonempty application startup copy and zero destination ranges.",
        "A target outside those ranges is not thereby proven unused, uninitialized, or hardware memory.",
        "The literal's semantic role is not inferred from its numeric value alone.",
    ],
}
out = ROOT / "firmware/work/gt1-callback0-dataflow.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
for row in rows:
    print(row["literal_runtime_address"], "->", row["literal_value"], "class:", row["target_initialization_class"])
