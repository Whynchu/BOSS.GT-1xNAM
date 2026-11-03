#!/usr/bin/env python3
"""Search GT-1 and related ESC2 images for the bounded ARM runtime diagnostic."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ("105", "107", "108", "109")
RELATED_IMAGES = {
    "GT1B_v104": ROOT / "firmware/work/reference/gt1b-comparator/gt1b_sys_v104/GT1BROM.BIN",
    "GT100_v212": ROOT / "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN",
    "Katana_v201": ROOT / "firmware/work/reference/esc2-comparators/katana_v201/extracted/katana_sys_v201/KATANARM.BIN",
    "Katana_v400": ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN",
}
PHRASE = b"SIGPVFN: Pure virtual fn called"
IGNORED = {0xFF, 0xDF}
ARM_RUNTIME_SIGNAL_TOKENS = tuple(
    f"SIG{name}".encode("ascii")
    for name in ("ABRT", "FPE", "ILL", "INT", "SEGV", "TERM", "STAK", "RTRED", "RTMEM", "USR1", "USR2", "PVFN", "CPPL", "OUTOFHEAP")
)
ARM_RUNTIME_DIAGNOSTIC_STRINGS = (
    b"SIGABRT: Abnormal termination",
    b"SIGPVFN: Pure virtual fn called",
)

def app_payload_bounds(image: bytes) -> tuple[int, int]:
    base = 0x40000
    stored_size = int.from_bytes(image[base + 0x30:base + 0x34], "little")
    start = base + 0x40
    end = start + stored_size
    if len(image) != 0x400000 or end > len(image):
        raise ValueError(f"invalid bounded app candidate: image={len(image):#x}, end={end:#x}")
    return start, end

def all_hits(data: bytes, needle: bytes, start: int, end: int) -> list[int]:
    result = []
    while (offset := data.find(needle, start, end)) >= 0:
        result.append(offset)
        start = offset + 1
    return result

def bounded_deinterleave_hits(data: bytes, start: int, end: int) -> list[dict]:
    result = []
    for offset in range(start, end):
        if data[offset] != PHRASE[0]:
            continue
        normalized = bytearray()
        pos = offset
        while pos < min(offset + len(PHRASE) + 32, end) and len(normalized) < len(PHRASE):
            if data[pos] not in IGNORED:
                normalized.append(data[pos])
            pos += 1
        if normalized == PHRASE:
            raw = data[offset:pos]
            marker_positions = [i for i, value in enumerate(raw) if value in IGNORED]
            marker_gaps = [b - a for a, b in zip(marker_positions, marker_positions[1:])]
            result.append({
                "start": f"0x{offset:06X}",
                "end_exclusive": f"0x{pos:06X}",
                "raw_hex": raw.hex(" "),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "normalized_ascii": normalized.decode("ascii"),
                "removed_bytes": [f"0x{x:02X}" for x in sorted(set(raw) & IGNORED)],
                "marker_positions_relative": marker_positions,
                "marker_stride_bytes": marker_gaps,
                "all_marker_strides_are_9": bool(marker_gaps) and all(gap == 9 for gap in marker_gaps),
                "marker_phase_mod_9": sorted({position % 9 for position in marker_positions}),
            })
    return result

def periodic_nonprintable_skip_hits(data: bytes, start: int, end: int) -> list[dict]:
    """Search each modulo-9 phase, skipping only non-ASCII bytes in that phase."""
    result = []
    for phase in range(9):
        projected = bytearray()
        raw_offsets = []
        skipped_offsets = []
        for offset in range(start, end):
            value = data[offset]
            if (offset - start) % 9 == phase and not (32 <= value < 127):
                skipped_offsets.append(offset)
                continue
            projected.append(value)
            raw_offsets.append(offset)
        pos = 0
        while (pos := projected.find(PHRASE, pos)) >= 0:
            raw_start = raw_offsets[pos]
            raw_end = raw_offsets[pos + len(PHRASE) - 1] + 1
            skipped = [off for off in skipped_offsets if raw_start <= off < raw_end]
            raw = data[raw_start:raw_end]
            # Reconstruct from the actual projection map, so any retained
            # nonprintable byte remains visible and cannot silently disappear.
            reconstructed = bytes(data[off] for off in raw_offsets[pos:pos + len(PHRASE)])
            if reconstructed != PHRASE:
                raise AssertionError("periodic projection mapping failed")
            marker_positions = [off - raw_start for off in skipped]
            result.append({
                "start": f"0x{raw_start:06X}",
                "end_exclusive": f"0x{raw_end:06X}",
                "raw_hex": raw.hex(" "),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "normalized_ascii": reconstructed.decode("ascii"),
                "skipped_nonprintable_bytes": [f"0x{data[off]:02X}" for off in skipped],
                "skipped_positions_relative": marker_positions,
                "skip_stride_bytes": [b - a for a, b in zip(marker_positions, marker_positions[1:])],
                "phase_relative_to_payload_start_mod_9": phase,
                "all_skips_at_stride_9": len(marker_positions) >= 2 and all(b - a == 9 for a, b in zip(marker_positions, marker_positions[1:])),
            })
            pos += 1
    return result

def periodic_runtime_signal_token_hits(data: bytes, start: int, end: int) -> list[dict]:
    """Search ARM C runtime signal names under the same modulo-9 projection."""
    found: dict[tuple[bytes, int], set[int]] = {}
    for phase in range(9):
        projected = bytearray()
        raw_offsets = []
        for offset in range(start, end):
            value = data[offset]
            if (offset - start) % 9 == phase and not (32 <= value < 127):
                continue
            projected.append(value)
            raw_offsets.append(offset)
        for token in ARM_RUNTIME_SIGNAL_TOKENS:
            pos = 0
            while (pos := projected.find(token, pos)) >= 0:
                key = (token, raw_offsets[pos])
                found.setdefault(key, set()).add(phase)
                pos += 1
    return [
        {"token": token.decode("ascii"), "raw_file_offset": f"0x{offset:06X}", "matching_phases": sorted(phases)}
        for (token, offset), phases in sorted(found.items(), key=lambda x: (x[0][1], x[0][0]))
    ]

def periodic_runtime_diagnostic_hits(data: bytes, start: int, end: int) -> list[dict]:
    """Search selected exact diagnostics documented for the Arm C library."""
    result = []
    for phase in range(9):
        projected = bytearray()
        raw_offsets = []
        skipped_offsets = []
        for offset in range(start, end):
            value = data[offset]
            if (offset - start) % 9 == phase and not (32 <= value < 127):
                skipped_offsets.append(offset)
                continue
            projected.append(value)
            raw_offsets.append(offset)
        for diagnostic in ARM_RUNTIME_DIAGNOSTIC_STRINGS:
            pos = 0
            while (pos := projected.find(diagnostic, pos)) >= 0:
                raw_start = raw_offsets[pos]
                raw_end = raw_offsets[pos + len(diagnostic) - 1] + 1
                skipped = [off for off in skipped_offsets if raw_start <= off < raw_end]
                result.append({
                    "normalized_ascii": diagnostic.decode("ascii"),
                    "start": f"0x{raw_start:06X}",
                    "end_exclusive": f"0x{raw_end:06X}",
                    "phase_relative_to_payload_start_mod_9": phase,
                    "raw_hex": data[raw_start:raw_end].hex(" "),
                    "raw_sha256": hashlib.sha256(data[raw_start:raw_end]).hexdigest(),
                    "skipped_nonprintable_bytes": [f"0x{data[off]:02X}" for off in skipped],
                    "skipped_positions_relative": [off - raw_start for off in skipped],
                })
                pos += 1
    return result

def scan_image(image: bytes) -> dict:
    start, end = app_payload_bounds(image)
    return {
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_size": len(image),
        "candidate_app_payload_range": [f"0x{start:X}", f"0x{end:X}"],
        "raw_SIGPVFN_hits": [f"0x{x:06X}" for x in all_hits(image, b"SIGPVFN", start, end)],
        "raw_Pure_virtual_fn_called_hits": [f"0x{x:06X}" for x in all_hits(image, b"Pure virtual fn called", start, end)],
        "bounded_deinterleave_hits": bounded_deinterleave_hits(image, start, end),
        "periodic_nonprintable_skip_hits": periodic_nonprintable_skip_hits(image, start, end),
        "periodic_arm_runtime_signal_token_hits": periodic_runtime_signal_token_hits(image, start, end),
        "periodic_arm_runtime_diagnostic_hits": periodic_runtime_diagnostic_hits(image, start, end),
    }

result = {
    "classification": "bounded periodic nonprintable-byte search for selected Arm C library runtime diagnostics; clues only",
    "phrase": PHRASE.decode("ascii"),
    "marker_cadence_observation": "The exact phrase is recovered in all four GT-1 releases by skipping nonprintable bytes at one of nine possible modulo-9 phases; recovered raw spans contain skipped bytes at 9-byte intervals. This resembles a separate 8-data-bytes-plus-marker candidate record cadence, but is not proof of a common encoding or executable code.",
    "versions": {},
    "related_ESC2_product_images": {},
    "limitations": [
        "The diagnostic text is not proof the GT-1 or comparator application executes on ARM or on ESC2.",
        "The legacy bounded search removes only 0xFF and 0xDF. The separate periodic scan skips a nonprintable byte only when it falls at one selected modulo-9 phase; this tests a narrow record hypothesis and is not a generic decoder.",
        "The 9-byte marker cadence may reflect a record layout rather than a decoded string section; the phrase hit is not code evidence.",
        "The exact phrase is recovered in v1.05/v1.07 and GT-1B v1.04 only by the periodic nonprintable-byte scan; their legacy FF/DF-only bounded search has no hit. This method difference does not establish a firmware architecture change.",
        "The secondary SIGABRT phrase search covers only the selected documented text 'SIGABRT: Abnormal termination'; absence of other diagnostics from the selected signal-token list is not an exhaustive library fingerprint.",
        "Related-model image labels are based on preserved package paths and companion structural comparison evidence; this phrase search does not prove every app block is executed by the MB8AA4181.",
    ],
}
for version in VERSIONS:
    path = ROOT / f"firmware/extracted/v{version}/gt1_sys_v{version}/GT1ROM.BIN"
    image = path.read_bytes()
    result["versions"][version] = scan_image(image)

for label, path in RELATED_IMAGES.items():
    result["related_ESC2_product_images"][label] = {
        "path": str(path.relative_to(ROOT)),
        **scan_image(path.read_bytes()),
    }

out = ROOT / "firmware/work/runtime-string-version-evidence.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
