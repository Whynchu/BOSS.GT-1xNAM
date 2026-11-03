#!/usr/bin/env python3
"""Extract the startup-selected initialized code segment to its link address.

The decoder output remains untouched. This writes derived flat binaries for
bounded Ghidra imports from the first copy descriptor called by the common
decoded startup stub. Requires the already reproduced/hash-checked decoded
images; see bootstrap-decoder-probe.json and bootstrap-handoff-evidence.json.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTDIR = ROOT / "firmware/work/reconstructed"
VERSIONS = ("v105", "v107", "v108", "v109")
EXPECTED_UPD = "0f247f1b94c0c9ca8e4eef1ec980e2f060f95ef494ed7fa6bd9fbaf52d93a6a4"
EXPECTED_APP = {
    "v105": "8297887084af48b04189955bbd8bdb4e0e6ff6a0e0fbcac7f85a175792775e29",
    "v107": "304b88a2c628cf47bb5091ecbc6da4fab4924f88cdea8897b44e5f474b9fb001",
    "v108": "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1",
    "v109": "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29",
}
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
sha = lambda b: hashlib.sha256(b).hexdigest()
OUTDIR.mkdir(parents=True, exist_ok=True)
rows = []
for version in VERSIONS:
    for kind in ("GT1Upd", "GT1Appli"):
        source = ROOT / f"firmware/work/decoded/{version}-{kind}.bin"
        blob = source.read_bytes()
        expected = EXPECTED_UPD if kind == "GT1Upd" else EXPECTED_APP[version]
        input_hash = sha(blob)
        assert input_hash == expected, (source, input_hash)
        destination, length, source_address = u32(blob, 0xE4), u32(blob, 0xE8), u32(blob, 0xEC)
        source_offset = source_address - 0x60000000
        assert destination == 0x01000300
        assert source_offset >= 0 and source_offset + length <= len(blob)
        segment = blob[source_offset:source_offset + length]
        assert len(segment) == length
        entry_raw = u32(blob, 0x164)
        entry = entry_raw & ~1
        assert destination <= entry < destination + length
        target_source_offset = source_offset + entry - destination
        second_entry_raw = u32(blob, target_source_offset + 0x1C)
        second_entry = second_entry_raw & ~1
        assert destination <= second_entry < destination + length
        name = f"{version}-{kind}-seg0.bin"
        outpath = OUTDIR / name
        outpath.write_bytes(segment)
        rows.append({
            "version": version,
            "kind": kind,
            "decoded_input": str(source.relative_to(ROOT)),
            "decoded_sha256": input_hash,
            "source_runtime": hex(source_address),
            "source_output_offset": hex(source_offset),
            "destination_runtime": hex(destination),
            "size": len(segment),
            "segment_sha256": sha(segment),
            "derived_file": str(outpath.relative_to(ROOT)),
            "first_entry": hex(entry_raw),
            "first_entry_offset_in_segment": hex(entry - destination),
            "second_entry": hex(second_entry_raw),
            "second_entry_offset_in_segment": hex(second_entry - destination),
            "mapping_status": "derived from output copy helper arguments and literal descriptor; physical memory type unverified",
        })
manifest = {
    "read_only_inputs": True,
    "method": "copy bytes from decoded output source pointer to destination range specified by startup copy literal triple at offsets 0xE4/0xE8/0xEC",
    "ghidra_import": {"loader": "BinaryLoader", "base_address": "0x01000300", "processor_candidate": "ARM:LE:32:v7", "context": "Thumb; bounded candidate, not exact ESC2 identification"},
    "segments": rows,
}
manifest_path = OUTDIR / "entry-segments.json"
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
print(manifest_path)
