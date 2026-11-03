#!/usr/bin/env python3
"""Quantify local and cross-release shifted byte correspondence in GT-1 images."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PATHS = {
    "105": ROOT / "firmware/extracted/v105/gt1_sys_v105/GT1ROM.BIN",
    "107": ROOT / "firmware/extracted/v107/gt1_sys_v107/GT1ROM.BIN",
    "108": ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN",
    "109": ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN",
}
images = {version: path.read_bytes() for version, path in PATHS.items()}
for version, image in images.items():
    if len(image) != 0x400000:
        raise ValueError(f"unexpected image size for v{version}: {len(image):#x}")

def ratio(start: int, size: int, delta: int) -> dict:
    a = images["108"][start:start + size]
    b_start = start + delta
    b = images["109"][b_start:b_start + size]
    if len(a) != size or len(b) != size:
        raise ValueError(f"comparison out of bounds: {start:#x}, {size:#x}, {delta:+#x}")
    equal = sum(x == y for x, y in zip(a, b))
    return {
        "v108_start": f"0x{start:X}",
        "v109_start": f"0x{b_start:X}",
        "size": size,
        "delta": f"{delta:+#x}",
        "equal_bytes": equal,
        "equal_fraction": round(equal / size, 8),
        "v108_sha256": hashlib.sha256(a).hexdigest(),
        "v109_sha256": hashlib.sha256(b).hexdigest(),
    }

# A local delta sweep tests whether +0x1180 is a distinct alignment peak.
anchor, size = 0xD8290, 0x1000
delta_sweep = []
for earlier, later in (("105", "107"), ("107", "108"), ("108", "109")):
    for delta in range(-0x2000, 0x2001, 0x10):
        a_start = anchor
        b_start = a_start + delta
        if b_start < 0 or b_start + size > len(images[later]):
            continue
        a = images[earlier][a_start:a_start + size]
        b = images[later][b_start:b_start + size]
        equal = sum(x == y for x, y in zip(a, b))
        delta_sweep.append({
            "earlier_version": earlier,
            "later_version": later,
            "earlier_start": f"0x{a_start:X}",
            "later_start": f"0x{b_start:X}",
            "size": size,
            "delta": f"{delta:+#x}",
            "equal_bytes": equal,
            "equal_fraction": round(equal / size, 8),
        })
delta_sweep.sort(key=lambda item: (-item["equal_fraction"], item["delta"]))

# Exact-equality runs at the candidate shift, over the bounded v1.08 app span.
app_start, app_end = 0x40040, 0x15E805
delta = 0x1180
a = images["108"][app_start:app_end]
b = images["109"][app_start + delta:app_end + delta]
runs = []
run_start = None
for i, (x, y) in enumerate(zip(a, b)):
    if x == y:
        if run_start is None:
            run_start = i
    elif run_start is not None:
        if i - run_start >= 32:
            s, e = app_start + run_start, app_start + i
            chunk = images["108"][s:e]
            runs.append({
                "v108_start": f"0x{s:X}",
                "v108_end_exclusive": f"0x{e:X}",
                "v109_start": f"0x{s + delta:X}",
                "length": e - s,
                "sha256": hashlib.sha256(chunk).hexdigest(),
            })
        run_start = None
if run_start is not None and len(a) - run_start >= 32:
    s, e = app_start + run_start, app_end
    chunk = images["108"][s:e]
    runs.append({"v108_start": f"0x{s:X}", "v108_end_exclusive": f"0x{e:X}",
                 "v109_start": f"0x{s + delta:X}", "length": e - s,
                 "sha256": hashlib.sha256(chunk).hexdigest()})

bins = []
for start in range(app_start, app_end, 0x1000):
    count = min(0x1000, app_end - start)
    candidates = [ratio(start, count, d) for d in (0, delta)]
    bins.append({"v108_start": f"0x{start:X}", "size": count,
                 "same_offset": candidates[0], "plus_0x1180": candidates[1]})

result = {
    "classification": "exact byte correspondence only; does not identify code/data or prove runtime relocation",
    "inputs": {v: {"path": str(PATHS[v]), "size": len(images[v]),
                    "sha256": hashlib.sha256(images[v]).hexdigest()} for v in images},
    "delta_sweep": {"anchor_in_each_earlier_image": f"0x{anchor:X}", "size": size,
                    "tested_delta_range": ["-0x2000", "+0x2000"], "step": "0x10",
                    "note": "The same v1.08-selected anchor may not represent homologous content in older releases; interpret peaks alongside exact-run evidence.",
                    "ranked_results": delta_sweep},
    "app_comparison": {"v108_span": [f"0x{app_start:X}", f"0x{app_end:X}"],
                       "candidate_delta": "+0x1180", "equal_run_minimum": 32,
                       "equal_runs": runs, "equal_run_count": len(runs),
                       "bins_0x1000": bins},
    "limitations": [
        "A constant file-offset delta does not prove runtime relocation; it can arise from reordered/copyable data or a transformed container layout.",
        "Byte equality does not classify code, data, compression, or execution state.",
        "The delta sweep is local to one selected 4 KiB anchor and is not a global alignment search.",
    ],
}
out = ROOT / "firmware/work/gt1-shifted-segment-evidence.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
