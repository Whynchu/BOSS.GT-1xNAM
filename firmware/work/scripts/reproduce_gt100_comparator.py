#!/usr/bin/env python3
"""Reproduce read-only GT-100 v2.12 vs GT-1 v1.09 container comparisons."""
from __future__ import annotations

import bz2
import collections
import gzip
import hashlib
import json
import lzma
import struct
import zlib
from collections import defaultdict
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
except ImportError:
    Cs = None

ROOT = Path(__file__).resolve().parents[3]
GT100 = ROOT / "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN"
GT1 = ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN"
SPECS = ((0x2000, "Updater"), (0x40000, "Appli"))


def section(data: bytes, base: int, name: str) -> dict:
    stored = struct.unpack_from("<I", data, base + 0x30)[0]
    expanded = struct.unpack_from("<I", data, base + 0x3C)[0]
    start, end = base + 0x40, base + 0x40 + stored
    payload = data[start:end]
    next_non_ff = end
    while next_non_ff < len(data) and data[next_non_ff] == 0xFF:
        next_non_ff += 1
    codec = {}
    for label, decode in (
        ("zlib", zlib.decompress),
        ("gzip", gzip.decompress),
        ("bzip2", bz2.decompress),
        ("lzma_auto", lzma.decompress),
    ):
        try:
            out = decode(payload)
            codec[label] = {"valid": True, "output_size": len(out), "matches_expanded_candidate": len(out) == expanded}
        except Exception as exc:
            codec[label] = {"valid": False, "error": str(exc)[:120]}
    return {
        "header_offset": f"0x{base:06X}",
        "label": data[base:base + 16].decode("ascii", "replace"),
        "version_text": data[base + 16:base + 0x28].decode("ascii", "replace"),
        "stored_length_field_0x30": f"0x{stored:X}",
        "field_0x34_unclassified": f"0x{struct.unpack_from('<I', data, base + 0x34)[0]:08X}",
        "expanded_length_candidate_0x3c": f"0x{expanded:X}",
        "payload_start": f"0x{start:06X}",
        "payload_end_exclusive": f"0x{end:06X}",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_first_32": payload[:32].hex(" "),
        "following_padding_all_ff_to_next_non_ff": data[end:next_non_ff] == b"\xff" * (next_non_ff-end),
        "next_non_ff_offset": f"0x{next_non_ff:06X}" if next_non_ff < len(data) else None,
        "codec_attempts": codec,
    }


gt100, gt1 = GT100.read_bytes(), GT1.read_bytes()
out = {
    "read_only": True,
    "scope": "Static comparison only; matching prefixes do not establish shared ISA, executable code, or firmware compatibility.",
    "images": {
        "GT-100 v2.12": {"path": str(GT100.relative_to(ROOT)), "size": len(gt100), "sha256": hashlib.sha256(gt100).hexdigest()},
        "GT-1 v1.09": {"path": str(GT1.relative_to(ROOT)), "size": len(gt1), "sha256": hashlib.sha256(gt1).hexdigest()},
    },
    "sections": {},
}
for base, name in SPECS:
    a, b = section(gt100, base, name), section(gt1, base, "GT1" + name)
    a_bytes = gt100[base + 0x40:base + 0x40 + int(a["stored_length_field_0x30"], 16)]
    b_bytes = gt1[base + 0x40:base + 0x40 + int(b["stored_length_field_0x30"], 16)]
    prefix = 0
    for x, y in zip(a_bytes, b_bytes):
        if x != y:
            break
        prefix += 1
    out["sections"][name] = {
        "GT-100": a,
        "GT-1": b,
        "stored_payload_common_prefix_bytes": prefix,
        "same_payload_length": len(a_bytes) == len(b_bytes),
        "interpretation": "Observed byte prefix only; encoding and executable status are unclassified.",
    }

# Deterministic 16-byte aligned block overlap across the bounded payloads.
# This is useful for selecting differential-analysis targets; it does not
# establish code identity or relocation.
sections = {
    "GT-1 updater": (gt1, 0x2040, 0x235A7),
    "GT-100 updater": (gt100, 0x2040, 0x2379D),
    "GT-1 app": (gt1, 0x40040, 0x15FB3A),
    "GT-100 app": (gt100, 0x40040, 0x17689C),
}
overlaps = {}
for left, right in (
    ("GT-1 updater", "GT-100 updater"),
    ("GT-1 app", "GT-100 app"),
    ("GT-1 app", "GT-1 updater"),
    ("GT-100 app", "GT-100 updater"),
):
    left_data, left_start, left_end = sections[left]
    right_data, right_start, right_end = sections[right]
    index = {}
    for offset in range(left_start, left_end - 15, 16):
        index.setdefault(left_data[offset:offset + 16], []).append(offset)
    matches = []
    for offset in range(right_start, right_end - 15, 16):
        block = right_data[offset:offset + 16]
        for left_offset in index.get(block, []):
            matches.append({"left_offset": f"0x{left_offset:06X}", "right_offset": f"0x{offset:06X}", "block_hex": block.hex(" ")})
    overlaps[f"{left} vs {right}"] = {
        "block_size": 16,
        "alignment": "absolute file offsets divisible by 16",
        "identical_block_matches": len(matches),
        "matches": matches,
        "interpretation": "Byte overlap only; matching blocks may be shared data/stubs and are not classified as executable code.",
    }
out["aligned_block_overlaps"] = overlaps

# Summarize relocation-like offset deltas without assuming that equal blocks
# are code. A repeated delta is only a candidate relationship.
app_matches = overlaps["GT-1 app vs GT-100 app"]["matches"]
delta_counts = collections.Counter(
    int(match["right_offset"], 16) - int(match["left_offset"], 16)
    for match in app_matches
)
out["app_overlap_delta_summary"] = [
    {
        "delta_gt100_minus_gt1": f"{delta:+#x}",
        "matching_blocks": count,
        "gt1_offsets": [m["left_offset"] for m in app_matches if int(m["right_offset"], 16) - int(m["left_offset"], 16) == delta],
        "gt100_offsets": [m["right_offset"] for m in app_matches if int(m["right_offset"], 16) - int(m["left_offset"], 16) == delta],
        "interpretation": "Candidate positional correspondence only; code/data and relocation are unclassified.",
    }
    for delta, count in delta_counts.most_common()
]

# Byte-exact application overlap independent of 16-byte alignment. Index
# fixed-size windows, extend every unique candidate in both directions, and
# retain maximal exact runs. Candidate hashes are checked byte-for-byte.
gt1_app_start, gt1_app_end = sections["GT-1 app"][1:]
gt100_app_start, gt100_app_end = sections["GT-100 app"][1:]
gt1_app = gt1[gt1_app_start:gt1_app_end]
gt100_app = gt100[gt100_app_start:gt100_app_end]
window = 32
gt1_index: dict[bytes, list[int]] = defaultdict(list)
for pos in range(len(gt1_app) - window + 1):
    gt1_index[gt1_app[pos:pos + window]].append(pos)
maximal_runs: set[tuple[int, int, int]] = set()
for bpos in range(len(gt100_app) - window + 1):
    key = gt100_app[bpos:bpos + window]
    for apos in gt1_index.get(key, ()):
        if gt1_app[apos:apos + window] != gt100_app[bpos:bpos + window]:
            continue
        left = 0
        while apos - left > 0 and bpos - left > 0 and gt1_app[apos-left-1] == gt100_app[bpos-left-1]:
            left += 1
        astart, bstart = apos-left, bpos-left
        right = window
        while apos+right < len(gt1_app) and bpos+right < len(gt100_app) and gt1_app[apos+right] == gt100_app[bpos+right]:
            right += 1
        run_length = left + right
        # Exclude runs that are contained in a longer exact match with same delta.
        delta = bstart - astart
        if (astart-1 >= 0 and bstart-1 >= 0 and gt1_app[astart-1] == gt100_app[bstart-1]) or \
           (astart+run_length < len(gt1_app) and bstart+run_length < len(gt100_app) and gt1_app[astart+run_length] == gt100_app[bstart+run_length]):
            continue
        maximal_runs.add((astart, bstart, run_length))
out["byte_exact_app_matches"] = {
    "method": "32-byte window index with byte-for-byte verification and bidirectional maximal extension",
    "window_size": window,
    "minimum_reported_run": window,
    "maximal_run_count": len(maximal_runs),
    "longest_runs": [
        {
            "GT-1_file_offset": f"0x{gt1_app_start+a:06X}",
            "GT-100_file_offset": f"0x{gt100_app_start+b:06X}",
            "length": n,
            "delta_GT100_minus_GT1": f"{(b-a):+#x}",
            "sha256": hashlib.sha256(gt1_app[a:a+n]).hexdigest(),
            "first_32_bytes": gt1_app[a:a+32].hex(" "),
        }
        for a,b,n in sorted(maximal_runs, key=lambda item:item[2], reverse=True)[:100]
    ],
    "interpretation": "Exact byte identity only; does not classify code/data, prove relocation, or establish ISA. Repeated/padding patterns may yield separate matches."
}

if Cs is not None:
    # Small decoder probes at the start of the dominant delta cluster. This
    # records tool output only; linear decoding is not code classification.
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    delta = int(out["app_overlap_delta_summary"][0]["delta_gt100_minus_gt1"], 16)
    probes = []
    for left_offset in out["app_overlap_delta_summary"][0]["gt1_offsets"][:4]:
        left = int(left_offset, 16)
        right = left + delta
        probe = {"GT-1_offset": f"0x{left:06X}", "GT-100_offset": f"0x{right:06X}", "decoder": "Capstone ARM Thumb, little endian"}
        for label, data, offset in (("GT-1", gt1, left), ("GT-100", gt100, right)):
            probe[label] = [
                {"address": f"0x{i.address:08X}", "bytes": i.bytes.hex(" "), "mnemonic": i.mnemonic, "operands": i.op_str}
                for i in list(decoder.disasm(data[offset:offset + 64], 0x01000000 + offset))[:16]
            ]
        probes.append(probe)
    out["dominant_delta_thumb_probes"] = {
        "delta": f"{delta:+#x}",
        "probes": probes,
        "interpretation": "Raw Capstone linear decode only; mixed or implausible instructions and data are possible. Not proof of ARM ISA or executable code.",
    }
dest = ROOT / "firmware/work/gt100-gt1-comparator-evidence.json"
dest.write_text(json.dumps(out, indent=2) + "\n")
print(dest)
