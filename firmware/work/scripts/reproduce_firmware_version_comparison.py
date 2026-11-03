#!/usr/bin/env python3
"""Summarize official GT-1 image versions without interpreting payload format."""
from __future__ import annotations

import hashlib
import json
import math
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ("105", "107", "108", "109")
images = {
    v: (ROOT / f"firmware/extracted/v{v}/gt1_sys_v{v}/GT1ROM.BIN").read_bytes()
    for v in VERSIONS
}

def ranges_for_changes(a: bytes, b: bytes) -> list[list[int]]:
    out: list[list[int]] = []
    start = previous = None
    for offset, (x, y) in enumerate(zip(a, b)):
        if x == y:
            continue
        if start is None:
            start = offset
        elif offset != previous + 1:
            out.append([start, previous + 1])
            start = offset
        previous = offset
    if start is not None:
        out.append([start, previous + 1])
    return out

def locate_all(blob: bytes, needle: bytes) -> list[int]:
    offsets = []
    pos = 0
    while (pos := blob.find(needle, pos)) >= 0:
        offsets.append(pos)
        pos += 1
    return offsets

def runs_where(predicate) -> list[list[int]]:
    """Return maximal half-open offset runs for which predicate(offset) is true."""
    out = []
    start = previous = None
    for offset in range(len(images[VERSIONS[0]])):
        if not predicate(offset):
            continue
        if start is None:
            start = offset
        elif offset != previous + 1:
            out.append([start, previous + 1])
            start = offset
        previous = offset
    if start is not None:
        out.append([start, previous + 1])
    return out

def summarize_ranges(ranges: list[list[int]]) -> list[dict]:
    result = []
    for start, end in ranges:
        item = {"start": f"0x{start:X}", "end_exclusive": f"0x{end:X}", "length": end-start}
        for version, image in images.items():
            data = image[start:end]
            counts = [0] * 256
            for value in data:
                counts[value] += 1
            entropy = -sum((n/len(data))*math.log2(n/len(data)) for n in counts if n)
            item.setdefault("sha256_by_version", {})[version] = hashlib.sha256(data).hexdigest()
            if version == VERSIONS[0]:
                item["v105_entropy_bits_per_byte"] = round(entropy, 6)
                item["v105_ff_fraction"] = round(counts[0xFF]/len(data), 6)
        result.append(item)
    return result

records = {}
for version, image in images.items():
    if len(image) != 4 * 1024 * 1024:
        raise ValueError(f"unexpected image size for v{version}: {len(image)}")
    records[version] = {
        "size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
        "rominfo": (ROOT / f"firmware/extracted/v{version}/gt1_sys_v{version}/ROMINFO.TXT").read_bytes().decode("ascii"),
        "markers": {
            marker.decode("ascii"): locate_all(image, marker)
            for marker in (b"ESC91.000", b"BSSESC2:GT1Upd", b"BSSESC2:GT1Appli")
        },
        "headers": {
            f"0x{offset:X}": {
                "version_field_ascii": image[offset + 0x10:offset + 0x18].decode("ascii", "replace"),
                "words_at_30_34_38_3c": [
                    f"0x{struct.unpack_from('<I', image, offset + field)[0]:08X}"
                    for field in (0x30, 0x34, 0x38, 0x3C)
                ],
            }
            for offset in (0x2000, 0x40000)
        },
    }

pairs = {}
for earlier, later in zip(VERSIONS, VERSIONS[1:]):
    changed_ranges = ranges_for_changes(images[earlier], images[later])
    changed_bytes = sum(end - start for start, end in changed_ranges)
    pairs[f"{earlier}->{later}"] = {
        "changed_bytes": changed_bytes,
        "changed_range_count": len(changed_ranges),
        "changed_ranges": [[f"0x{s:X}", f"0x{e:X}"] for s, e in changed_ranges],
        "first_changed_offset": f"0x{changed_ranges[0][0]:X}" if changed_ranges else None,
        "last_changed_offset_inclusive": f"0x{changed_ranges[-1][1]-1:X}" if changed_ranges else None,
    }

same_across_all = runs_where(lambda i: all(images[v][i] == images[VERSIONS[0]][i] for v in VERSIONS[1:]))
same_boot_area = [[s, e] for s, e in same_across_all if s < 0x2000]
same_updater_header = [[s, e] for s, e in same_across_all if s >= 0x2000 and e <= 0x2040]
application_ranges = {
    v: {
        "start": 0x40040,
        "end_exclusive": 0x40040 + struct.unpack_from("<I", images[v], 0x40030)[0],
        "length_header_candidate": struct.unpack_from("<I", images[v], 0x40030)[0],
    }
    for v in VERSIONS
}
all_ff_runs_v109 = []
image = images["109"]
start = None
for i, byte in enumerate(image):
    if byte == 0xFF and start is None:
        start = i
    elif byte != 0xFF and start is not None:
        if i-start >= 0x1000:
            all_ff_runs_v109.append([start, i])
        start = None
if start is not None and len(image)-start >= 0x1000:
    all_ff_runs_v109.append([start, len(image)])

result = {
    "classification": "read-only byte comparisons; no payload codec or semantics inferred",
    "versions": records,
    "adjacent_comparisons": pairs,
    "cross_version_stable_ranges": {
        "note": "Maximal ranges with byte-identical values in all four images; equality is not evidence of code or runtime purpose.",
        "count": len(same_across_all),
        "total_bytes": sum(e-s for s, e in same_across_all),
        "below_0x2000": summarize_ranges(same_boot_area),
        "updater_header_0x2000_to_0x2040": summarize_ranges(same_updater_header),
        "all_ranges": [[f"0x{s:X}", f"0x{e:X}"] for s, e in same_across_all],
    },
    "application_payload_candidate_ranges": {
        "note": "Ranges derived from the candidate +0x30 length word; endpoint agreement does not establish compression or field semantics.",
        "by_version": application_ranges,
        "v109_runs_of_FF_at_least_4096_bytes": summarize_ranges(all_ff_runs_v109),
    },
    "limitations": [
        "The source archives are Roland-hosted; v1.07 is not directly linked from the current BOSS page.",
        "Byte differences do not classify code, data, compression, encryption, or relocation.",
        "ROMINFO fields are recorded verbatim; their meanings are not inferred.",
    ],
}
out = ROOT / "firmware/work/firmware-version-comparison.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
