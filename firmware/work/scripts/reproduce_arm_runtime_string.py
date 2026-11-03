#!/usr/bin/env python3
"""Reproduce the interleaved ARM-runtime diagnostic string in both GT-1 images."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = b"SIGPVFN: Pure virtual fn called"
WINDOWS = {
    "v108": (0x9786C, 0x9788E),
    "v109": (0x98899, 0x988BC),
}

results = {}
for version, (start, end) in WINDOWS.items():
    path = ROOT / "firmware" / "extracted" / version / f"gt1_sys_{version}" / "GT1ROM.BIN"
    image = path.read_bytes()
    raw = image[start:end]
    normalized = bytes(value for value in raw if value not in (0xFF, 0xDF))
    assert normalized == TARGET, (version, normalized)
    results[version] = {
        "path": str(path.relative_to(ROOT)),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "offset_start": f"0x{start:06X}",
        "offset_end_exclusive": f"0x{end:06X}",
        "raw_hex": raw.hex(" "),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "normalization": "Remove interspersed bytes 0xFF and 0xDF from this exact bounded span.",
        "reconstructed_ascii": normalized.decode("ascii"),
    }

runtime_tokens = (
    b"SIGRTMEM", b"Out of heap memory", b"Heap memory corrupted", b"SIGPVFN",
    b"Pure virtual fn called", b"SIGSEGV", b"Bad memory access", b"SIGFPE",
    b"SIGILL", b"default_signal_handler", b"__pvfn", b"__cxa_pure_virtual",
)
for version in WINDOWS:
    path = ROOT / "firmware" / "extracted" / version / f"gt1_sys_{version}" / "GT1ROM.BIN"
    image = path.read_bytes()
    printable = bytearray()
    positions = []
    for offset, value in enumerate(image):
        if 32 <= value < 127:
            printable.append(value)
            positions.append(offset)
    hits = []
    for token in runtime_tokens:
        i = printable.find(token)
        if i >= 0:
            hits.append({"token": token.decode("ascii"), "offset": f"0x{positions[i]:06X}"})
    results[version]["naive_printable_projection_runtime_token_hits"] = hits

report = {
    "analysis": "Interleaved ARM runtime diagnostic string clue",
    "read_only": True,
    "projection_limit": "The supplementary whole-image search removes every non-printable byte before searching, so offsets are the first mapped raw offset and matches are leads only. The bounded exact phrase windows above are the reproducible normalization evidence.",
    "interpretation_limit": "The text matches an ARM Compiler C++ runtime diagnostic, but this alone does not prove the application ISA or that the referenced routine is reachable/executed.",
    "images": results,
}
out = ROOT / "firmware" / "work" / "arm-runtime-string-evidence.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
