#!/usr/bin/env python3
"""Reproduce GT-1 update image block lengths, boundaries, and basic codec checks.

Read-only. Optional lz4.frame and zstandard modules add those checks when present.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import json
import lzma
import shutil
import subprocess
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ("v108", "v109")
BLOCKS = {
    "GT1Upd": {"base": 0x2000, "next_boundary": 0x40000},
    "GT1Appli": {"base": 0x40000, "next_boundary": 0x1FC000},
}


def u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 4], "little")


def try_codec(name: str, data: bytes):
    funcs = {
        "zlib": lambda: zlib.decompress(data),
        "raw_deflate": lambda: zlib.decompress(data, -15),
        "gzip": lambda: gzip.decompress(data),
        "bzip2": lambda: bz2.decompress(data),
        "lzma_auto": lambda: lzma.decompress(data),
    }
    if name in funcs:
        return funcs[name]()
    if name == "lz4_frame":
        import lz4.frame
        return lz4.frame.decompress(data)
    if name == "zstd_frame":
        import zstandard
        return zstandard.ZstdDecompressor().decompress(data)
    raise ValueError(name)


results = {}
for version in VERSIONS:
    path = ROOT / "firmware" / "extracted" / version / f"gt1_sys_{version}" / "GT1ROM.BIN"
    image = path.read_bytes()
    version_info = {
        "path": str(path.relative_to(ROOT)),
        "image_size": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "blocks": {},
    }
    for name, spec in BLOCKS.items():
        base = spec["base"]
        stored_size = u32(image, base + 0x30)
        payload_start = base + 0x40
        payload_end = payload_start + stored_size
        expanded_size = u32(image, base + 0x3C)
        payload = image[payload_start:payload_end]
        padding = image[payload_end : spec["next_boundary"]]
        block = {
            "header_offset": f"0x{base:06X}",
            "header_marker": image[base : base + 16].decode("ascii", "replace"),
            "header_version": image[base + 0x20 : base + 0x28].decode("ascii", "replace"),
            "field_0x28_le": f"0x{u32(image, base + 0x28):08X}",
            "field_0x2c_le": f"0x{u32(image, base + 0x2C):08X}",
            "stored_length_field_0x30": f"0x{stored_size:X}",
            "field_0x34_le_unclassified": f"0x{u32(image, base + 0x34):08X}",
            "field_0x38_le": f"0x{u32(image, base + 0x38):08X}",
            "expanded_length_candidate_0x3c": f"0x{expanded_size:X}",
            "payload_start": f"0x{payload_start:06X}",
            "payload_end_exclusive": f"0x{payload_end:06X}",
            "payload_size": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "first_16_payload_bytes": payload[:16].hex(" "),
            "first_byte_after_payload": f"0x{image[payload_end]:02X}",
            "padding_to_next_boundary_all_ff": bool(padding) and padding == b"\xFF" * len(padding),
            "codec_attempts": {},
        }
        for codec in ("zlib", "raw_deflate", "gzip", "bzip2", "lzma_auto", "lz4_frame", "zstd_frame"):
            try:
                output = try_codec(codec, payload)
                block["codec_attempts"][codec] = {
                    "valid": True,
                    "output_size": len(output),
                    "matches_expanded_length_candidate": len(output) == expanded_size,
                }
            except Exception as exc:
                block["codec_attempts"][codec] = {
                    "valid": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:180],
                }
        seven_zip = shutil.which("7z")
        if seven_zip:
            with tempfile.NamedTemporaryFile(prefix="gt1-payload-", suffix=".bin") as temp:
                temp.write(payload)
                temp.flush()
                probe = subprocess.run([seven_zip, "l", temp.name], capture_output=True, text=True, timeout=30)
            block["7zip_archive_probe"] = {
                "executable": seven_zip,
                "exit_code": probe.returncode,
                "recognized_as_archive": "ERROR: " not in probe.stdout and probe.returncode == 0,
                "stdout_tail": probe.stdout[-500:],
                "stderr_tail": probe.stderr[-500:],
            }
        version_info["blocks"][name] = block
    results[version] = version_info

# Assertions validate the byte-span arithmetic and erased fill, not the encoding.
for version, data in results.items():
    for name, block in data["blocks"].items():
        assert int(block["payload_end_exclusive"], 16) - int(block["payload_start"], 16) == block["payload_size"]
        assert block["first_byte_after_payload"] == "0xFF"
        assert block["padding_to_next_boundary_all_ff"]

report = {
    "analysis": "GT-1 update block header and stored payload layout",
    "read_only": True,
    "interpretation_limit": "Offsets and byte counts are observed. 0x30 behaves as a stored byte count; 0x3c is an expanded-size candidate. No tested standard decoder validates the payload, so compression/encoding is not identified.",
    "versions": results,
}
out = ROOT / "firmware" / "work" / "container-layout.json"
out.write_text(json.dumps(report, indent=2) + "\n")
print(out)
