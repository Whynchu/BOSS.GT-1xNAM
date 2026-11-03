#!/usr/bin/env python3
"""Search bounded GT-1 updater/application payloads for direct Cortex-M vector heads."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = {
    "v1.05": (ROOT / "firmware/extracted/v105/gt1_sys_v105/GT1ROM.BIN", 0x15E098),
    "v1.07": (ROOT / "firmware/extracted/v107/gt1_sys_v107/GT1ROM.BIN", 0x15E7A5),
    "v1.08": (ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN", 0x15E805),
    "v1.09": (ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN", 0x15FB3A),
}
BLOCKS = {
    "GT1Upd": (0x2040, 0x235A7),
    "GT1Appli": (0x40040, None),
}
RESERVED_ZERO_INDEXES = (7, 8, 9, 10, 13)
HEAD_WORDS = 16
FULL_WORDS = 176
OUT = ROOT / "firmware/work/gt1-payload-vector-scan.json"

images = {}
report = {
    "analysis": "Direct Cortex-M-style vector-head scan of bounded GT-1 payloads",
    "read_only": True,
    "method": {
        "alignment": "Scan 4-byte-aligned file offsets inside each stored payload span.",
        "head_candidate": "A 16-word window must have zero words at vector indices 7-10 and 13 and odd (Thumb-bit-set) values at every other handler index 1-15. Word 0 is retained but not range-filtered because the RAM map is unknown.",
        "full_candidate": "A 176-word window must have zero words at indices 7-10 and 13 and at least 90% of all other handler entries at indices 1-175 odd. This is a broad signature probe, not a required table length.",
    },
    "reserved_zero_indexes": list(RESERVED_ZERO_INDEXES),
    "images": {},
    "limits": [
        "No hit only argues against a directly stored, 4-byte-aligned vector table matching these Cortex-M slot conventions in the tested payload spans.",
        "A failed search does not rule out ARM code, another vector-table shape, a differently aligned/relocated table, or content hidden by compression, encryption, interleaving, or another transform.",
        "The full-table probe uses 176 words as a comparison length from the ESC91.000 bootstrap; it is not an assertion about GT-1 hardware interrupt count.",
        "No device was accessed and no firmware was modified.",
    ],
}

for version, (path, app_end) in VERSIONS.items():
    image = path.read_bytes()
    images[version] = image
    version_data = {
        "path": str(path.relative_to(ROOT)),
        "size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
        "blocks": {},
    }
    for block, (start, fixed_end) in BLOCKS.items():
        end = app_end if fixed_end is None else fixed_end
        span_size = end - start
        result = {
            "payload_range": [f"0x{start:X}", f"0x{end:X}"],
            "payload_size": span_size,
            "head_candidate_count": 0,
            "head_candidates": [],
            "full_candidate_count": 0,
            "full_candidates": [],
        }
        begin = (start + 3) & ~3
        for offset in range(begin, end - 4 * HEAD_WORDS + 1, 4):
            words = struct.unpack_from("<16I", image, offset)
            if any(words[i] != 0 for i in RESERVED_ZERO_INDEXES):
                continue
            handlers = [words[i] for i in range(1, HEAD_WORDS) if i not in RESERVED_ZERO_INDEXES]
            if all(word & 1 for word in handlers):
                result["head_candidate_count"] += 1
                if len(result["head_candidates"]) < 20:
                    result["head_candidates"].append({
                        "file_offset": f"0x{offset:X}",
                        "initial_word": f"0x{words[0]:08X}",
                        "handler_words": [f"0x{w:08X}" for w in words[1:]],
                    })
        for offset in range(begin, end - 4 * FULL_WORDS + 1, 4):
            words = struct.unpack_from("<176I", image, offset)
            if any(words[i] != 0 for i in RESERVED_ZERO_INDEXES):
                continue
            handlers = [words[i] for i in range(1, FULL_WORDS) if i not in RESERVED_ZERO_INDEXES]
            odd_count = sum(bool(word & 1) for word in handlers)
            if odd_count >= 0.90 * len(handlers):
                result["full_candidate_count"] += 1
                if len(result["full_candidates"]) < 20:
                    result["full_candidates"].append({
                        "file_offset": f"0x{offset:X}",
                        "initial_word": f"0x{words[0]:08X}",
                        "odd_handler_count": odd_count,
                        "handler_count": len(handlers),
                    })
        version_data["blocks"][block] = result
    report["images"][version] = version_data

OUT.write_text(json.dumps(report, indent=2) + "\n")
print(OUT)
