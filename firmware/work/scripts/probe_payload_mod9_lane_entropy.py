#!/usr/bin/env python3
"""Test whether stored ESC2 app payloads show a globally special modulo-9 lane.

The probe is motivated by local 9-byte cadence observations around encoded
strings and candidate float records. Similar entropy across the nine lanes
argues against a simple whole-payload 8+1 interleave; it cannot rule out local
records, encryption, or other transformations.
"""
from __future__ import annotations

import collections
import hashlib
import json
import math
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FILES = {
    "GT-1 v1.05": ROOT / "firmware/extracted/v105/gt1_sys_v105/GT1ROM.BIN",
    "GT-1 v1.07": ROOT / "firmware/extracted/v107/gt1_sys_v107/GT1ROM.BIN",
    "GT-1 v1.08": ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN",
    "GT-1 v1.09": ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN",
    "GT-100 v2.12": ROOT / "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN",
}
HEADER = 0x40000
PERIOD = 9


def entropy(data: bytes) -> float:
    counts = collections.Counter(data)
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values())


def main() -> None:
    result = {
        "question": "Does a stored application payload have one consistently distinctive byte lane modulo 9?",
        "read_only": True,
        "method": "Partition each bounded application payload by offset modulo 9 and compare byte-frequency entropy, unique-byte count, and top byte frequencies.",
        "period_bytes": PERIOD,
        "interpretation_limit": "Equal lane statistics do not disprove local 9-byte records; they only weaken a simple global 8+1 lane format. High entropy does not prove encryption.",
        "images": {},
    }
    for name, path in FILES.items():
        image = path.read_bytes()
        stored = struct.unpack_from("<I", image, HEADER + 0x30)[0]
        start = HEADER + 0x40
        payload = image[start:start + stored]
        lanes = []
        for phase in range(PERIOD):
            lane = payload[phase::PERIOD]
            counts = collections.Counter(lane)
            lanes.append({
                "phase": phase,
                "bytes": len(lane),
                "entropy_bits_per_byte": round(entropy(lane), 9),
                "unique_byte_values": len(counts),
                "top_5_byte_counts": [
                    {"byte": f"0x{byte:02X}", "count": count}
                    for byte, count in counts.most_common(5)
                ],
            })
        values = [x["entropy_bits_per_byte"] for x in lanes]
        result["images"][name] = {
            "path": str(path.relative_to(ROOT)),
            "image_sha256": hashlib.sha256(image).hexdigest(),
            "payload_offset": hex(start),
            "payload_length": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "lane_entropy_min": min(values),
            "lane_entropy_max": max(values),
            "lane_entropy_range": round(max(values) - min(values), 9),
            "lanes": lanes,
        }
    out = ROOT / "firmware/work/payload-mod9-lane-entropy.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(out.relative_to(ROOT))
    for name, item in result["images"].items():
        print(name, "entropy range", item["lane_entropy_range"],
              "min/max", item["lane_entropy_min"], item["lane_entropy_max"])


if __name__ == "__main__":
    main()
