#!/usr/bin/env python3
"""Compare GT-1 numeric-looking 9-byte record chains against ESC2 comparators."""
from __future__ import annotations

import hashlib
import json
import math
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCES = {
    "GT-1 v1.09": (ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN", 0x40040, 0x15FB3A),
    "GT-100 v2.12": (ROOT / "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN", 0x40040, 0x17689C),
    "KATANA v2.01": (ROOT / "firmware/work/reference/esc2-comparators/katana_v201/extracted/katana_sys_v201/KATANARM.BIN", 0x40040, 0x161FDC),
    "KATANA v4.00": (ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN", 0x40040, 0x161657),
}
OUT = ROOT / "firmware/work/esc2-float-chain-comparison.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


images = {}
inputs = {}
for name, (path, start, end) in SOURCES.items():
    data = path.read_bytes()
    images[name] = data
    inputs[name] = {
        "path": str(path.relative_to(ROOT)),
        "size": len(data),
        "sha256": sha(data),
        "candidate_app_payload_range": [f"0x{start:X}", f"0x{end:X}"],
    }

gt1_start, gt1_end = SOURCES["GT-1 v1.09"][1:]
gt1_app = images["GT-1 v1.09"][gt1_start:gt1_end]
markers = {i for i, byte in enumerate(gt1_app) if byte == 0xFF}
chains = []
for first in sorted(markers):
    if first - 9 in markers:
        continue
    last = first
    while last + 9 in markers:
        last += 9
    records = (last - first) // 9
    if records < 12:
        continue
    blob = gt1_app[first + 1:last + 1]
    values = [v for i in range(0, len(blob), 9) for v in struct.unpack("<ff", blob[i:i + 8])]
    plausible = [v for v in values if math.isfinite(v) and abs(v) <= 100]
    nonzero = sum(abs(v) > 1e-6 for v in plausible)
    if len(plausible) < 0.95 * len(values) or nonzero < 0.25 * len(values):
        continue
    chains.append({
        "GT-1_file_offset": gt1_start + first + 1,
        "records": records,
        "byte_length": len(blob),
        "sha256": sha(blob),
        "blob": blob,
    })

matches = []
for chain in chains:
    for name, (path, start, end) in SOURCES.items():
        if name == "GT-1 v1.09":
            continue
        image = images[name]
        pos = image.find(chain["blob"], start, end)
        while pos >= 0 and pos + chain["byte_length"] <= end:
            matches.append({
                "source": "GT-1 v1.09",
                "GT-1_file_offset": f"0x{chain['GT-1_file_offset']:X}",
                "target": name,
                "target_file_offset": f"0x{pos:X}",
                "delta_target_minus_GT1": pos - chain["GT-1_file_offset"],
                "records": chain["records"],
                "byte_length": chain["byte_length"],
                "sha256": chain["sha256"],
                "exact_bytes_equal": True,
                "context_flanks": None,
            })
            pos = image.find(chain["blob"], pos + 1, end)

# Extend every exact chain match to the maximal identical byte run containing it.
for match in matches:
    a = int(match["GT-1_file_offset"], 16)
    b = int(match["target_file_offset"], 16)
    n = match["byte_length"]
    left = 0
    right = 0
    while a - left > 0 and b - left > 0 and images["GT-1 v1.09"][a-left-1] == images[match["target"]][b-left-1]:
        left += 1
    while a + n + right < len(images["GT-1 v1.09"]) and b + n + right < len(images[match["target"]]) and images["GT-1 v1.09"][a+n+right] == images[match["target"]][b+n+right]:
        right += 1
    match["context_flanks"] = {"identical_bytes_left": left, "identical_bytes_right": right, "maximal_identical_run_length": left+n+right}

# Group matches that share one file-offset delta. The interval is the span from
# the first matched chain through the last, so its equality rate is measurable.
aligned_windows = []
groups = {}
for match in matches:
    key = (match["target"], match["delta_target_minus_GT1"])
    groups.setdefault(key, []).append(match)
for (target, delta), group in groups.items():
    if len(group) < 2:
        continue
    lo = min(int(x["GT-1_file_offset"], 16) for x in group)
    hi = max(int(x["GT-1_file_offset"], 16) + x["byte_length"] for x in group)
    left = images["GT-1 v1.09"][lo:hi]
    right = images[target][lo+delta:hi+delta]
    equal = sum(a == b for a, b in zip(left, right))
    mismatch_offsets = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
    runs = []
    i = 0
    while i < len(left):
        if left[i] != right[i]:
            i += 1
            continue
        start = i
        while i < len(left) and left[i] == right[i]:
            i += 1
        if i-start >= 16:
            runs.append({"GT-1_start": f"0x{lo+start:X}", "length": i-start})
    aligned_windows.append({
        "target": target,
        "delta_target_minus_GT1": f"{delta:+#x}",
        "GT-1_interval": [f"0x{lo:X}", f"0x{hi:X}"],
        "target_interval": [f"0x{lo+delta:X}", f"0x{hi+delta:X}"],
        "byte_count": len(left),
        "equal_bytes": equal,
        "equal_fraction": round(equal / max(1, len(left)), 6),
        "mismatch_count": len(mismatch_offsets),
        "mismatch_positions_mod_9_from_window_start": {
            str(i): sum(offset % 9 == i for offset in mismatch_offsets) for i in range(9)
        },
        "first_mismatch_GT1_offsets": [f"0x{lo+i:X}" for i in mismatch_offsets[:20]],
        "exact_runs_at_least_16_bytes": runs,
        "exact_run_count": len(runs),
        "exact_run_bytes": sum(x["length"] for x in runs),
        "longest_exact_run": max((x["length"] for x in runs), default=0),
        "scope_note": "Window is bounded by first and last matched candidate chain in this delta group; it is not a claim that the entire interval is one section.",
    })

report = {
    "read_only": True,
    "inputs": inputs,
    "method": "Within the bounded GT-1 v1.09 app payload, identify chains of 0xFF markers every 9 bytes, interpret the following 8 bytes per record as two little-endian float32 values, retain chains with at least 12 records, at least 95% finite values of absolute magnitude <=100 and at least 25% non-near-zero values, then search each complete chain byte-for-byte in bounded comparator app payloads.",
    "candidate_chain_count_GT1": len(chains),
    "exact_comparator_match_count": len(matches),
    "matches": matches,
    "aligned_windows_from_repeated_deltas": aligned_windows,
    "limits": [
        "A float32 interpretation is heuristic; finite, small values and regular marker cadence do not establish intended type or semantic role.",
        "Exact byte recurrence supports shared structured data or common firmware components, not execution, relocation, amp-model meaning, or processor ISA.",
        "Only complete candidate chains meeting the stated filter were searched; no match does not show that other related data is absent.",
        "All inputs are preserved firmware images; no device access or firmware modification occurred.",
    ],
}
OUT.write_text(json.dumps(report, indent=2) + "\n")
print(OUT)
