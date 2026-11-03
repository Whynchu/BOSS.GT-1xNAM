#!/usr/bin/env python3
"""Compare float-pair chains while projecting out observed periodic marker bytes."""
from __future__ import annotations

import hashlib
import json
import math
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ("v1.05", "v1.07", "v1.08", "v1.09")
FILES = {
    "v1.05": ROOT / "firmware/extracted/v105/gt1_sys_v105/GT1ROM.BIN",
    "v1.07": ROOT / "firmware/extracted/v107/gt1_sys_v107/GT1ROM.BIN",
    "v1.08": ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN",
    "v1.09": ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN",
}
APP_START = 0x40040
APP_ENDS = {"v1.05": 0x15E098, "v1.07": 0x15E7A5, "v1.08": 0x15E805, "v1.09": 0x15FB3A}
# These byte values appeared as skipped periodic bytes in the runtime-string
# projection. They are exploratory candidate markers here, not established
# record delimiters.
MARKER_VALUES = {0xFF, 0xF7, 0xFD, 0xDF, 0xBF}
images = {v: FILES[v].read_bytes() for v in VERSIONS}

def chains_for(version: str) -> list[dict]:
    data = images[version][APP_START:APP_ENDS[version]]
    marker_positions = {i for i, value in enumerate(data) if value in MARKER_VALUES}
    chains = []
    for pos in sorted(marker_positions):
        if pos - 9 in marker_positions:
            continue
        last = pos
        while last + 9 in marker_positions:
            last += 9
        records = (last - pos) // 9
        if records < 12:
            continue
        data_bytes = b"".join(data[pos + 1 + i * 9:pos + 9 + i * 9] for i in range(records))
        pairs = [struct.unpack_from("<ff", data_bytes, i * 8) for i in range(records)]
        values = [value for pair in pairs for value in pair]
        plausible = [value for value in values if math.isfinite(value) and abs(value) <= 100]
        nonzero = sum(abs(value) > 1e-6 for value in plausible)
        if len(plausible) < len(values) * 0.95 or nonzero < len(values) * 0.25:
            continue
        separators = bytes(data[pos + i * 9] for i in range(records + 1))
        chains.append({
            "first_data_offset": APP_START + pos + 1,
            "marker_offset": APP_START + pos,
            "records": records,
            "data": data_bytes,
            "separators": separators,
            "pairs": pairs,
        })
    return chains

candidate_chains = {v: chains_for(v) for v in VERSIONS}
adjacent = []
for earlier, later in zip(VERSIONS, VERSIONS[1:]):
    matches = []
    for source in candidate_chains[earlier]:
        for target in candidate_chains[later]:
            if source["data"] != target["data"]:
                continue
            matches.append({
                "earlier_data_offset": f"0x{source['first_data_offset']:X}",
                "later_data_offset": f"0x{target['first_data_offset']:X}",
                "offset_delta": f"{target['first_data_offset'] - source['first_data_offset']:+#x}",
                "records": source["records"],
                "projected_data_bytes": len(source["data"]),
                "projected_data_sha256": hashlib.sha256(source["data"]).hexdigest(),
                "separator_values_earlier": sorted(set(source["separators"])),
                "separator_values_later": sorted(set(target["separators"])),
                "separator_sequences_identical": source["separators"] == target["separators"],
                "first_float_pairs": [[float(f"{x:.9g}"), float(f"{y:.9g}")] for x, y in source["pairs"][:4]],
            })
    adjacent.append({
        "earlier": earlier,
        "later": later,
        "candidate_chain_counts": {earlier: len(candidate_chains[earlier]), later: len(candidate_chains[later])},
        "exact_projected_data_matches": sorted(matches, key=lambda item: (-item["records"], item["earlier_data_offset"])),
    })

result = {
    "classification": "exploratory periodic-marker projection; numeric-looking exact byte matches only",
    "inputs": {
        v: {"path": str(FILES[v].relative_to(ROOT)), "size": len(images[v]), "sha256": hashlib.sha256(images[v]).hexdigest(),
            "app_payload_candidate": [f"0x{APP_START:X}", f"0x{APP_ENDS[v]:X}"]}
        for v in VERSIONS
    },
    "method": {
        "candidate_marker_values": [f"0x{x:02X}" for x in sorted(MARKER_VALUES)],
        "marker_basis": "values observed as periodic skipped bytes in separate runtime-string scans; their role as delimiters is unverified",
        "record_shape_tested": "one candidate marker byte followed by eight bytes parsed as two little-endian float32 values; next candidate marker exactly nine bytes later",
        "filters": {"minimum_records": 12, "finite_abs_le_100_fraction": 0.95, "non_near_zero_fraction_of_plausible_values": 0.25},
        "comparison": "exact equality of concatenated eight-byte record payloads after omitting each candidate marker; separator bytes and phase alignment are recorded separately",
    },
    "candidate_counts_by_version": {v: len(candidate_chains[v]) for v in VERSIONS},
    "adjacent_comparisons": adjacent,
    "interpretation_limit": "The projection can find candidate structured numeric data but cannot establish float use, record semantics, executable status, runtime loading, relocation, or an encoding/normalization mechanism. The fixed marker set and plausibility filters can produce false positives.",
}
out = ROOT / "firmware/work/periodic-float-chain-projection-evidence.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(f"wrote {out.relative_to(ROOT)}")
for pair in adjacent:
    print(f"{pair['earlier']}→{pair['later']}: {len(pair['exact_projected_data_matches'])} exact projected matches")
