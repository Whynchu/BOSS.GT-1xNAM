#!/usr/bin/env python3
"""Compare exact payload prefixes across GT-1, GT-100, and KATANA v4.00."""
from __future__ import annotations

import hashlib
import json
import math
import struct
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
IMAGES = {
    "GT-1 v1.05": ROOT / "firmware/extracted/v105/gt1_sys_v105/GT1ROM.BIN",
    "GT-1 v1.07": ROOT / "firmware/extracted/v107/gt1_sys_v107/GT1ROM.BIN",
    "GT-1 v1.08": ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN",
    "GT-1 v1.09": ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN",
    "GT-100 v2.12": ROOT / "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN",
    "KATANA v4.00": ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN",
}
SECTIONS = {"updater": 0x2000, "application": 0x40000}
HEADER_SIZE = 0x40
PROBE_SIZE = 0x200


def common_prefix_length(chunks: list[bytes]) -> int:
    limit = min(map(len, chunks))
    idx = 0
    while idx < limit and len({chunk[idx] for chunk in chunks}) == 1:
        idx += 1
    return idx


def shannon_entropy(data: bytes) -> float:
    counts = Counter(data)
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


images = {name: path.read_bytes() for name, path in IMAGES.items()}
payloads: dict[str, dict[str, bytes]] = {}
result = {
    "read_only": True,
    "probe_size": PROBE_SIZE,
    "inputs": {},
    "payloads": {},
    "groups": {},
    "interpretation_limit": (
        "Shared bytes establish an exact common payload prefix only; they do not prove that it is executable code, "
        "a loader, a codec preamble, or shared runtime behavior."
    ),
}

for image_name, image in images.items():
    result["inputs"][image_name] = {
        "path": str(IMAGES[image_name].relative_to(ROOT)),
        "size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
    }
    payloads[image_name] = {}
    for section, header in SECTIONS.items():
        stored_length = struct.unpack_from("<I", image, header + 0x30)[0]
        expanded_length = struct.unpack_from("<I", image, header + 0x3C)[0]
        start = header + HEADER_SIZE
        end = start + stored_length
        payload = image[start:end]
        payloads[image_name][section] = payload
        result["payloads"][f"{image_name} {section}"] = {
            "header_offset": f"0x{header:06X}",
            "payload_start": f"0x{start:06X}",
            "payload_end_exclusive": f"0x{end:06X}",
            "stored_length": stored_length,
            "field_0x28": f"0x{struct.unpack_from('<I', image, header + 0x28)[0]:08X}",
            "field_0x38": f"0x{struct.unpack_from('<I', image, header + 0x38)[0]:08X}",
            "field_0x3c": f"0x{expanded_length:08X}",
            "expanded_length_candidate_bytes": expanded_length,
            "expanded_length_candidate_MiB": round(expanded_length / (1024 * 1024), 6),
            "fits_24MiB_nominal_GT1_external_SDRAM_capacity": (
                expanded_length <= 24 * 1024 * 1024 if image_name.startswith("GT-1") else None
            ),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "prefix_probe_sha256": hashlib.sha256(payload[:PROBE_SIZE]).hexdigest(),
            "prefix_probe_hex": payload[:64].hex(" "),
            "entropy_bits_per_byte": {
                "common_prefix_194": round(shannon_entropy(payload[:194]), 6),
                "first_512_bytes": round(shannon_entropy(payload[:PROBE_SIZE]), 6),
                "full_payload": round(shannon_entropy(payload), 6),
            },
        }

groups = {
    "all_twelve_payloads": [(name, section) for name in images for section in SECTIONS],
    "all_updaters": [(name, "updater") for name in images],
    "all_applications": [(name, "application") for name in images],
    "GT-1 v1.05-v1.09 all sections": [
        (name, section) for name in list(images)[:4] for section in SECTIONS
    ],
}
for group_name, members in groups.items():
    chunks = [payloads[name][section][:PROBE_SIZE] for name, section in members]
    length = common_prefix_length(chunks)
    result["groups"][group_name] = {
        "members": [f"{name} {section}" for name, section in members],
        "common_prefix_length": length,
        "common_prefix_sha256": hashlib.sha256(chunks[0][:length]).hexdigest(),
        "first_divergence_payload_relative_offset": f"0x{length:X}",
        "bytes_at_divergence": {
            f"{name} {section}": chunk[length : length + 16].hex(" ")
            for (name, section), chunk in zip(members, chunks)
        },
    }

out = ROOT / "firmware/work/section-prefix-evidence.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
