#!/usr/bin/env python3
"""Verify bootstrap references to the candidate 0x02003000 service region."""
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
IMAGE_HASHES = {
    "v105": "b1bde0410795230b4a89ee3dfbbd357700bba7020624c0ff832ae3d8539d8bb4",
    "v107": "6a3110cd42c4b129494a93bc88d4f218e2e0b9377868ca051018b28696d6c22f",
    "v108": "7219679a87e985316264544423c9940ccbcbadeb2df0b2f13711ae57194cb612",
    "v109": "412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf",
}
LITERAL_SLOTS = {0x74C: 0x14, 0x8EC: 0x0C, 0xB04: 0x18, 0xBB8: 0x58}
REPORT_PATH = ROOT / "firmware/work/ghidra-esc91-02003-refs.txt"
EXPECTED_REPORT_SHA256 = "04af7ea2707c88530f0f6fcd4e191eb4fbc39f14a63058ce5282c1942d9bc0b8"
GT1B_PATH = ROOT / "firmware/work/reference/gt1b-comparator/gt1b_sys_v104/GT1BROM.BIN"
GT1B_SHA256 = "9b6d47a2c43b12856760d135a8582acb9424e17faa66474ce3272d021a5d8646"
GT1B_REPORT_PATH = ROOT / "firmware/work/ghidra-gt1b-esc91-02003-refs.txt"
GT1B_REPORT_SHA256 = "7a09a1bf82a0d2747e7f40f9b189bf25244fc440e18303f34cb13f300bc25169"
RUNTIME_BASE = 0x00FFFFD0

images = {}
for version, expected in IMAGE_HASHES.items():
    path = ROOT / f"firmware/extracted/{version}/gt1_sys_{version}/GT1ROM.BIN"
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise SystemExit(f"{version} source image SHA-256 mismatch: {digest}")
    hits = []
    for offset, slot in LITERAL_SLOTS.items():
        value = struct.unpack_from("<I", data, offset)[0]
        if value != 0x02003000:
            raise SystemExit(f"{version} offset 0x{offset:x}: expected 0x02003000, got 0x{value:08x}")
        hits.append({
            "file_offset": f"0x{offset:x}",
            "runtime_literal_address": f"0x{RUNTIME_BASE + offset:08x}",
            "word": f"0x{value:08x}",
            "following_accessed_slot_offset": f"0x{slot:x}",
            "surrounding_16_bytes_sha256": hashlib.sha256(data[offset - 8:offset + 8]).hexdigest(),
        })
    images[version] = {"path": str(path.relative_to(ROOT)), "size": len(data), "sha256": digest, "references": hits}

report_bytes = REPORT_PATH.read_bytes()
report_sha = hashlib.sha256(report_bytes).hexdigest()
if report_sha != EXPECTED_REPORT_SHA256:
    raise SystemExit(f"Ghidra reference report SHA-256 mismatch: {report_sha}")
report_text = report_bytes.decode("utf-8")
refs = {}
for file_offset, slot in LITERAL_SLOTS.items():
    match = re.search(
        rf"literal file_offset=0x{file_offset:x} runtime=([0-9a-f]+) word=0x2003000\n"
        rf"\s+xref from=([0-9a-f]+) type=READ instruction=ldr ([^\n]+)",
        report_text,
    )
    if not match:
        raise SystemExit(f"missing Ghidra xref for literal file offset 0x{file_offset:x}")
    refs[f"0x{file_offset:x}"] = {
        "literal_runtime_address": f"0x{int(match.group(1), 16):08x}",
        "instruction_runtime_address": f"0x{int(match.group(2), 16):08x}",
        "instruction": f"LDR {match.group(3)}",
        "following_indirect_call_slot_offset": f"0x{slot:x}",
    }

call_edges = [
    {"from": "0x010009F8", "to": "0x010006D0", "evidence": "Ghidra call xref"},
    {"from": "0x010009F4", "to": "0x01000B5E", "evidence": "Ghidra call xref"},
    {"from": "0x01000B66", "to": "0x01000888", "evidence": "decoded BL in Ghidra instruction context"},
    {"from": "0x0100088A", "to": "0x01000862", "evidence": "Ghidra call xref"},
]
for edge in call_edges:
    if edge["from"].lower()[2:] not in report_text.lower() or edge["to"].lower()[2:] not in report_text.lower():
        raise SystemExit(f"missing call-edge evidence in Ghidra report: {edge}")

gt1b_data = GT1B_PATH.read_bytes()
gt1b_sha = hashlib.sha256(gt1b_data).hexdigest()
if gt1b_sha != GT1B_SHA256:
    raise SystemExit(f"GT-1B v1.04 SHA-256 mismatch: {gt1b_sha}")
gt1_data = (ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN").read_bytes()
if gt1b_data[0x700:0xC00] != gt1_data[0x700:0xC00]:
    raise SystemExit("GT-1B and GT-1 bootstrap code span 0x700–0xBFF differs")
gt1b_report_bytes = GT1B_REPORT_PATH.read_bytes()
gt1b_report_sha = hashlib.sha256(gt1b_report_bytes).hexdigest()
if gt1b_report_sha != GT1B_REPORT_SHA256:
    raise SystemExit(f"GT-1B Ghidra report SHA-256 mismatch: {gt1b_report_sha}")
gt1b_report_text = gt1b_report_bytes.decode("utf-8")
for literal_runtime, xref_runtime, slot in (
    ("0100071c", "010006e2", "0x14"),
    ("010008bc", "0100086c", "0xc"),
    ("01000ad4", "01000a64", "0x18"),
    ("01000b88", "01000b60", "0x58"),
):
    if literal_runtime not in gt1b_report_text or xref_runtime not in gt1b_report_text or slot not in gt1b_report_text:
        raise SystemExit(f"GT-1B Ghidra report missing expected reference {xref_runtime} to {literal_runtime}")

result = {
    "read_only": True,
    "mapping": "bootstrap candidate runtime = 0x00FFFFD0 + file offset; Ghidra imports only file offsets 0x0–0x1FFF",
    "target_region_candidate": "0x02003000",
    "images": images,
    "ghidra": {
        "tool": "Ghidra 12.2, ARM:LE:32:Cortex, Thumb context",
        "report": str(REPORT_PATH.relative_to(ROOT)),
        "report_sha256": report_sha,
        "reference_probe": refs,
        "loader_call_edges": call_edges,
        "loader_entry_transfer": {
            "from": "0x010002CA",
            "to": "0x010009F0",
            "evidence": "bootstrap handoff analysis resolves the current literal transfer to the loader entry",
            "source": "firmware/work/bootstrap-handoff-evidence.json and firmware/work/bootstrap-execution-map.md",
        },
        "reproduce_command": "GT1_ESC91_REF_REPORT=$PWD/firmware/work/ghidra-esc91-02003-refs.txt tools/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless firmware/work/ghidra-projects GT1_ESC91_02003_Refs -import firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN -overwrite -loader BinaryLoader -loader-baseAddr FFFFD0 -loader-fileOffset 0 -loader-length 8192 -processor ARM:LE:32:Cortex -noanalysis -scriptPath tools/ghidra_scripts -postScript GT1Esc91ReferenceProbe.java",
    },
    "same_family_comparator": {
        "model": "BOSS GT-1B v1.04",
        "image": str(GT1B_PATH.relative_to(ROOT)),
        "image_sha256": gt1b_sha,
        "identical_boot_code_span": ["0x700", "0xC00"],
        "ghidra_report": str(GT1B_REPORT_PATH.relative_to(ROOT)),
        "ghidra_report_sha256": gt1b_report_sha,
        "finding": "The four 0x02003000 literal pools, instruction xrefs, accessed slot offsets, and loader call references match the GT-1 v1.09 bounded probe.",
    },
    "interpretation": "The loader call path reaches bootstrap code that reads function pointers at offsets +0x0C, +0x14, +0x18, and +0x58 from base 0x02003000, then calls them indirectly. The same +0x58 slot is the address reached by the app's 0x020030B4-0x5C access.",
    "limits": [
        "Instruction references and indirect call shapes are verified; the contents and physical memory type of 0x02003000 remain unknown.",
        "The loader call edges are verified under the candidate bootstrap mapping; the physical path that supplies the table values before loader execution is unknown.",
        "The apparent shared service-table/API role is a hypothesis, not a documented processor ABI.",
    ],
}
out = ROOT / "firmware/work/gt1-bootstrap-02003-reference-probe.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
for offset, evidence in refs.items():
    print(offset, evidence["instruction_runtime_address"], evidence["instruction"], "slot", evidence["following_indirect_call_slot_offset"])
