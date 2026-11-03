#!/usr/bin/env python3
"""Capture bounded raw/disassembly context around periodic SIGPVFN recoveries."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "firmware/work/runtime-string-version-evidence.json"
OUT = ROOT / "firmware/work/runtime-string-context-probe.json"
WINDOW_BEFORE = 0x20
WINDOW_AFTER = 0x40
DECODER = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
DECODER.detail = False

source = json.loads(EVIDENCE.read_text())
results = {}
for version, item in source["versions"].items():
    image_path = ROOT / f"firmware/extracted/v{version}/gt1_sys_v{version}/GT1ROM.BIN"
    image = image_path.read_bytes()
    hit = item["periodic_nonprintable_skip_hits"][0]
    phrase_start = int(hit["start"], 16)
    phrase_end = int(hit["end_exclusive"], 16)
    before_start = phrase_start - WINDOW_BEFORE
    after_end = phrase_end + WINDOW_AFTER
    windows = {
        "before": (before_start, phrase_start),
        "after": (phrase_end, after_end),
    }
    context = {}
    for label, (start, end) in windows.items():
        raw = image[start:end]
        aligned = {}
        for shift in (0, 2, 4, 6):
            instructions = [
                {
                    "file_offset": f"0x{i.address:06X}",
                    "bytes": i.bytes.hex(" "),
                    "mnemonic": i.mnemonic,
                    "operands": i.op_str,
                }
                for i in DECODER.disasm(raw[shift:], start + shift)
            ]
            aligned[str(shift)] = instructions
        context[label] = {
            "file_range": [f"0x{start:06X}", f"0x{end:06X}"],
            "raw_hex": raw.hex(" "),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_thumb_decode_at_halfword_shifts": aligned,
        }
    results[version] = {
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "diagnostic_raw_range": [hit["start"], hit["end_exclusive"]],
        "periodic_phase_relative_to_payload": hit["phase_relative_to_payload_start_mod_9"],
        "skipped_nonprintable_bytes": hit["skipped_nonprintable_bytes"],
        "context": context,
    }

report = {
    "analysis": "Raw Thumb context probe around recovered SIGPVFN diagnostic",
    "read_only": True,
    "method": "For each GT-1 firmware release, capture 32 raw bytes before and 64 raw bytes after the normalized phrase span. Decode each bounded context from halfword shifts 0, 2, 4, and 6 using Capstone Thumb-M, without separator removal or a runtime address mapping.",
    "interpretation": "The local byte and decode windows are exploratory. Different starts can yield plausible instructions by chance; no entry point, branch target, or cross-version instruction alignment is established by this probe.",
    "images": results,
    "limits": [
        "File offsets are used as decoder addresses solely to enumerate local instruction boundaries; they are not a proposed application load map.",
        "No separator normalization is applied to these windows; this avoids propagating the phrase-specific periodic skip rule without independent evidence.",
        "No runtime reachability, executable status, ISA attribution, or MB8AA4181 execution is established.",
    ],
}
OUT.write_text(json.dumps(report, indent=2) + "\n")
print(OUT)
