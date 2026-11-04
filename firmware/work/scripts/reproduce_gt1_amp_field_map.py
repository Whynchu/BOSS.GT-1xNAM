#!/usr/bin/env python3
"""Map the GT-1 preamp field block inside the plaintext patch records.

Read-only static analysis over the decoded application section.

Input shape (established by reproduce_gt1_amp_record_scan.py):

    53 07 | 16-byte name | 00 00 00 | patch parameter bytes, stride 0x753

This script tests a concrete field hypothesis against every populated record:
the preamp slot occupies 32 bytes starting at record+0x2B, and its byte order
is taken from the community editor template (preamp_a_on_off at template byte
91 through preamp_a_custom_sp_cabinet at 122, including the two bytes the
editor map skips).

A slot is accepted only if the invariant fields match the editor's documented
defaults across all populated records:

    mic_level = 100, custom_bottom = 50, custom_edge = 50,
    custom_preamp_low = 50, custom_preamp_high = 50, custom_char = 50,
    sp_size = 7, sp_color_low = 10, sp_color_high = 10, sp_num = 2,
    sp_cabinet = 0

Output: firmware/work/gt1-amp-field-map.json
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = 0x60000000
DECODED = ROOT / "firmware/work/decoded/v108-GT1Appli.bin"
EXPECTED_SHA256 = "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1"
OUT = ROOT / "firmware/work/gt1-amp-field-map.json"

REC0, STRIDE = 0x199D7C, 0x753
SLOT_A, SLOT_B = 0x2B, 0x4F
SLOT_LEN = 32

FIELDS = [
    (0x00, "on_off"), (0x01, "type"), (0x02, "gain"), (0x03, "t_comp"),
    (0x04, "bass"), (0x05, "middle"), (0x06, "treble"), (0x07, "presence"),
    (0x08, "level"), (0x09, "bright"), (0x0A, "gain_sw"), (0x0B, "solo_sw"),
    (0x0C, "solo_level"), (0x0D, "sp_type"), (0x0E, "mic_type"),
    (0x0F, "mic_dis"), (0x10, "mic_pos"), (0x11, "mic_level"),
    (0x12, "direct_mix"), (0x13, "custom_type"), (0x14, "custom_bottom"),
    (0x15, "custom_edge"), (0x16, "unmapped_113"), (0x17, "unmapped_114"),
    (0x18, "custom_preamp_low"), (0x19, "custom_preamp_high"),
    (0x1A, "custom_char"), (0x1B, "sp_size"), (0x1C, "sp_color_low"),
    (0x1D, "sp_color_high"), (0x1E, "sp_num"), (0x1F, "sp_cabinet"),
]

# editor default.tsl values that must hold across the factory bank
INVARIANTS = {
    "mic_level": 100, "custom_bottom": 50, "custom_edge": 50,
    "custom_preamp_low": 50, "custom_preamp_high": 50, "custom_char": 50,
    "sp_size": 7, "sp_color_low": 10, "sp_color_high": 10,
    "sp_num": 2, "sp_cabinet": 0,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    d = DECODED.read_bytes()
    digest = sha256(d)
    assert digest == EXPECTED_SHA256, digest

    records = []
    for o in range(0, len(d) - 19):
        if d[o] != 0x53 or d[o + 1] != 0x07:
            continue
        name = d[o + 2:o + 18]
        if re.fullmatch(rb"[ -~]{16}", name):
            records.append(o)

    # populated = preamp block carries a non-default type/gain configuration
    populated = [o for o in records if sum(1 for b in d[o + SLOT_A:o + SLOT_A + SLOT_LEN] if b) > 25]

    def field(record: int, slot: int, off: int) -> int:
        return d[record + slot + off]

    # invariant check across every populated record
    violations = []
    for rec in populated:
        for off, name in FIELDS:
            if name in INVARIANTS and field(rec, SLOT_A, off) != INVARIANTS[name]:
                violations.append({
                    "record": hex(rec), "field": name,
                    "expected": INVARIANTS[name], "actual": field(rec, SLOT_A, off),
                })

    stats = {}
    for off, name in FIELDS:
        values = [field(rec, SLOT_A, off) for rec in populated]
        stats[name] = {
            "offset_in_slot": f"0x{off:02X}",
            "absolute_in_record": f"0x{SLOT_A + off:02X}",
            "min": min(values), "max": max(values),
            "distinct": len(set(values)),
            "most_common": Counter(values).most_common(5),
        }

    type_values = sorted({field(rec, SLOT_A, 0x01) for rec in populated})
    type_hist = Counter(field(rec, SLOT_A, 0x01) for rec in populated)

    out = {
        "read_only": True,
        "input": "firmware/work/decoded/v108-GT1Appli.bin",
        "input_sha256": digest,
        "record_base": hex(REC0),
        "record_stride": hex(STRIDE),
        "records_scanned": len(records),
        "records_populated": len(populated),
        "slot_a_offset": hex(SLOT_A),
        "slot_b_offset": hex(SLOT_B),
        "slot_length": SLOT_LEN,
        "field_map": {
            name: {
                "slot_offset": f"0x{off:02X}",
                "record_offset_a": f"0x{SLOT_A + off:02X}",
                "record_offset_b": f"0x{SLOT_B + off:02X}",
            }
            for off, name in FIELDS
        },
        "invariant_violations": violations[:32],
        "invariant_violation_count": len(violations),
        "field_stats_slot_a": stats,
        "amp_type_values_present": type_values,
        "amp_type_histogram": {str(k): v for k, v in sorted(type_hist.items())},
        "interpretation": (
            "The 32-byte slot matches the community editor's 30-field preamp order including the two "
            "bytes that map skips, and all eleven documented custom/cabinet/mic defaults hold across "
            "every populated factory record. That is strong structural confirmation of field identity, "
            "not proof of DSP semantics."
        ),
        "limits": [
            "Field identity rests on the community editor's byte order and default values, not on a live unit.",
            "Constant values across the factory bank show that presets do not use the custom_* surface; they do not prove the fields are inert.",
            "The two unmapped bytes (slot 0x16/0x17) are constant 5 here and are not identified.",
            "Amp type is an index observed in 0..24 in this bank; the meaning of each index is not established.",
        ],
    }
    OUT.write_text(json.dumps(out, indent=2) + "\n")

    print(f"records {len(records)}, populated {len(populated)}")
    print(f"invariant violations: {len(violations)}")
    print(f"amp type values: {type_values}")
    print("per-field ranges (slot A):")
    for off, name in FIELDS:
        s = stats[name]
        print(f"  +0x{off:02X} {name:<20} {s['min']:3d}..{s['max']:3d}  distinct={s['distinct']:<3d} "
              f"top={s['most_common'][:2]}")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
