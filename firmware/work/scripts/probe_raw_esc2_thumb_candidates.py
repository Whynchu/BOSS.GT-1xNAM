#!/usr/bin/env python3
"""Record a bounded, read-only ARM/Thumb probe of GT-1 section prefixes.

This is a falsification-oriented probe, not an ISA detector. It tries raw and
one-byte-shifted Thumb alignment at the updater/application payload starts and
records Capstone's contiguous decode before its first undecodable bytes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import capstone
from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_MCLASS, CS_MODE_THUMB, Cs

ROOT = Path(__file__).resolve().parents[3]
IMAGE = ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN"
IMAGE_SHA256 = "412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf"
SPANS = {"updater": 0x2040, "application": 0x40040}
WINDOW = 0x100

image = IMAGE.read_bytes()
actual_sha256 = hashlib.sha256(image).hexdigest()
if actual_sha256 != IMAGE_SHA256:
    raise SystemExit(f"unexpected input image hash: {actual_sha256}")

results = {
    "read_only": True,
    "question": "Does direct ARM Thumb decoding of the section payload prefix produce a coherent instruction stream?",
    "image": str(IMAGE.relative_to(ROOT)),
    "image_sha256": actual_sha256,
    "capstone_version": capstone.__version__,
    "window_size": WINDOW,
    "section_starts": {},
    "interpretation_limit": (
        "A few valid-looking Thumb instructions do not establish the ISA. These starts are identical section data, "
        "the payload transform and runtime mapping are unknown, and Capstone stops at the first undecodable bytes."
    ),
}

prefixes = {name: image[start : start + WINDOW] for name, start in SPANS.items()}
common = 0
while common < min(map(len, prefixes.values())) and len({data[common] for data in prefixes.values()}) == 1:
    common += 1
results["common_prefix_length"] = common
results["common_prefix_sha256"] = hashlib.sha256(next(iter(prefixes.values()))[:common]).hexdigest()

for name, start in SPANS.items():
    samples = []
    for shift in (0, 1):
        for mode_name, mode in (
            ("thumb", CS_MODE_THUMB),
            ("thumb_mclass", CS_MODE_THUMB | CS_MODE_MCLASS),
        ):
            decoder = Cs(CS_ARCH_ARM, mode | CS_MODE_LITTLE_ENDIAN)
            decoder.detail = True
            sample_start = start + shift
            raw = image[sample_start : start + WINDOW]
            instructions = list(decoder.disasm(raw, sample_start))
            decoded = sum(item.size for item in instructions)
            samples.append(
                {
                    "alignment_shift": shift,
                    "decoder_mode": mode_name,
                    "bytes_offered": len(raw),
                    "decoded_bytes_before_stop": decoded,
                    "instruction_count": len(instructions),
                    "coverage_fraction": round(decoded / len(raw), 6) if raw else 0,
                    "instructions": [
                        {
                            "file_offset": f"0x{item.address:06X}",
                            "bytes": item.bytes.hex(" "),
                            "mnemonic": item.mnemonic,
                            "operands": item.op_str,
                        }
                        for item in instructions
                    ],
                }
            )
    results["section_starts"][name] = {
        "file_offset": f"0x{start:06X}",
        "prefix_hex": image[start : start + 64].hex(" "),
        "probes": samples,
    }

out = ROOT / "firmware/work/raw-esc2-thumb-probe.json"
out.write_text(json.dumps(results, indent=2) + "\n")
print(out)
