#!/usr/bin/env python3
"""Analyze byte-exact GT-1/GT-100 app matches for 8-byte float pairs + 0xFF markers."""
from __future__ import annotations
import hashlib, json, math, struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GT1 = ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN"
GT100 = ROOT / "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN"
MATCHES = ROOT / "firmware/work/gt100-gt1-comparator-evidence.json"
OUT = ROOT / "firmware/work/gt100-float-record-islands.json"

images = {"GT-1 v1.09": GT1.read_bytes(), "GT-100 v2.12": GT100.read_bytes()}
source = json.loads(MATCHES.read_text())
results = []
for run in source["byte_exact_app_matches"]["longest_runs"]:
    aoff = int(run["GT-1_file_offset"], 16)
    boff = int(run["GT-100_file_offset"], 16)
    length = run["length"]
    a = images["GT-1 v1.09"][aoff:aoff + length]
    b = images["GT-100 v2.12"][boff:boff + length]
    assert a == b and hashlib.sha256(a).hexdigest() == run["sha256"]
    marks = [i for i, x in enumerate(a) if x == 0xFF]
    chains = []
    for start in marks:
        positions = [start]
        while positions[-1] + 9 in marks:
            positions.append(positions[-1] + 9)
        if len(positions) >= 4 and (len(positions) == 1 or start - 9 not in marks):
            chains.append(positions)
    if not chains:
        continue
    chain = max(chains, key=len)
    pair_values = [struct.unpack("<ff", a[p + 1:p + 9]) for p in chain[:-1]]
    flat = [x for pair in pair_values for x in pair]
    finite = [x for x in flat if math.isfinite(x)]
    plausible = [x for x in finite if abs(x) <= 100]
    results.append({
        "GT-1_file_offset": run["GT-1_file_offset"],
        "GT-100_file_offset": run["GT-100_file_offset"],
        "shared_run_length": length,
        "shared_run_sha256": run["sha256"],
        "marker_byte": "0xFF",
        "marker_offsets_relative_to_run": chain,
        "marker_stride": 9,
        "record_layout_candidate": "8 bytes interpreted as two little-endian IEEE-754 binary32 values, then one 0xFF marker",
        "record_count": len(pair_values),
        "pair_values_first_8": [[float(f"{x:.9g}") for x in pair] for pair in pair_values[:8]],
        "float_value_count": len(flat),
        "finite_count": len(finite),
        "finite_abs_le_100_count": len(plausible),
        "finite_abs_le_100_fraction": round(len(plausible) / max(1, len(flat)), 6),
        "plausible_min": min(plausible) if plausible else None,
        "plausible_max": max(plausible) if plausible else None,
        "GT1_GT100_record_bytes_identical": a == b,
        "interpretation": "Regular marker spacing and plausible binary32 values support a table/record-layout hypothesis; semantic role and intended CPU representation remain unidentified.",
    })

report = {
    "read_only": True,
    "inputs": {
        "GT-1 v1.09": {"path": str(GT1.relative_to(ROOT)), "size": len(images["GT-1 v1.09"]), "sha256": hashlib.sha256(images["GT-1 v1.09"]).hexdigest()},
        "GT-100 v2.12": {"path": str(GT100.relative_to(ROOT)), "size": len(images["GT-100 v2.12"]), "sha256": hashlib.sha256(images["GT-100 v2.12"]).hexdigest()},
        "match_manifest": {"path": str(MATCHES.relative_to(ROOT)), "sha256": hashlib.sha256(MATCHES.read_bytes()).hexdigest()},
    },
    "method": "For the longest shared app runs (up to 100, as retained in the comparator manifest), locate chains of 0xFF marker bytes spaced exactly 9 bytes apart; interpret the 8 intervening bytes as two little-endian float32 values; validate run bytes and hashes against both source images.",
    "limits": ["Float interpretation is a structural hypothesis, not proof that firmware loads or uses these values as floats.", "A shared data island does not establish the complete payload transform, record boundaries beyond the observed marker chains, or amp-model semantics.", "No firmware was modified and no hardware was accessed."],
    "results": sorted(results, key=lambda x:x["record_count"], reverse=True),
}
OUT.write_text(json.dumps(report, indent=2) + "\n")
print(OUT)
