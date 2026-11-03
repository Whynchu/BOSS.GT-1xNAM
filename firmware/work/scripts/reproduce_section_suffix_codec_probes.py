#!/usr/bin/env python3
"""Test common codecs at candidate starts after shared GT-1/GT-100 prefixes."""
from __future__ import annotations

import bz2
import ctypes
import ctypes.util
import gzip
import hashlib
import json
import lzma
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
IMAGES = {
    "GT-1 v1.05": ROOT / "firmware/extracted/v105/gt1_sys_v105/GT1ROM.BIN",
    "GT-1 v1.07": ROOT / "firmware/extracted/v107/gt1_sys_v107/GT1ROM.BIN",
    "GT-1 v1.08": ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN",
    "GT-1 v1.09": ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN",
    "GT-100 v2.12": ROOT / "firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN",
}
SECTIONS = {"updater": 0x2000, "application": 0x40000}
COMMON_PREFIX_LEN = {"updater": 199, "application": 194}


def codec_functions():
    funcs = {
        "zlib": lambda d: zlib.decompress(d),
        "raw_deflate": lambda d: zlib.decompress(d, -15),
        "gzip": lambda d: gzip.decompress(d),
        "bzip2": lambda d: bz2.decompress(d),
        "lzma_auto": lambda d: lzma.decompress(d),
        "xz": lambda d: lzma.decompress(d, format=lzma.FORMAT_XZ),
        "lzma_alone": lambda d: lzma.decompress(d, format=lzma.FORMAT_ALONE),
    }
    try:
        import lz4.frame
        funcs["lz4_frame"] = lambda d: lz4.frame.decompress(d)
    except ImportError:
        pass
    try:
        import zstandard
        funcs["zstd_frame"] = lambda d: zstandard.ZstdDecompressor().decompress(d)
    except ImportError:
        pass
    try:
        import brotli
        funcs["brotli"] = lambda d: brotli.decompress(d)
        funcs["_brotli_version"] = getattr(brotli, "__version__", "unknown")
    except ImportError:
        pass
    return funcs


def raw_block_probes(payload: bytes, expected_size: int) -> dict:
    """Try raw LZ4 and LZO blocks using the header's output-size candidate."""
    result = {}
    try:
        import lz4.block
        try:
            output = lz4.block.decompress(payload, uncompressed_size=expected_size)
            result["lz4_block"] = {
                "available": True, "valid": True, "output_size": len(output),
                "matches_expected_size": len(output) == expected_size,
                "output_sha256": hashlib.sha256(output).hexdigest(),
            }
        except Exception as exc:
            result["lz4_block"] = {
                "available": True, "valid": False,
                "error_type": type(exc).__name__, "error": str(exc)[:180],
            }
    except ImportError:
        result["lz4_block"] = {"available": False}

    library = ctypes.util.find_library("lzo2")
    if not library:
        result["lzo1x_decompress_safe"] = {"available": False}
    else:
        try:
            lzo = ctypes.CDLL(library)
            decoder = lzo.lzo1x_decompress_safe
            decoder.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
            decoder.restype = ctypes.c_int
            source = ctypes.create_string_buffer(payload)
            destination = ctypes.create_string_buffer(expected_size)
            output_size = ctypes.c_size_t(expected_size)
            code = decoder(source, len(payload), destination,
                           ctypes.byref(output_size), None)
            valid = code == 0
            record = {
                "available": True, "library": library, "return_code": code,
                "valid": valid, "output_size": output_size.value if valid else None,
            }
            if valid:
                output = destination.raw[:output_size.value]
                record["matches_expected_size"] = len(output) == expected_size
                record["output_sha256"] = hashlib.sha256(output).hexdigest()
            result["lzo1x_decompress_safe"] = record
        except Exception as exc:
            result["lzo1x_decompress_safe"] = {
                "available": True, "library": library, "valid": False,
                "error_type": type(exc).__name__, "error": str(exc)[:180],
            }
    return result


codecs = codec_functions()
codec_versions = {name[1:]: value for name, value in list(codecs.items()) if name.startswith("_")}
for name in codec_versions:
    del codecs[f"_{name}"]
result = {
    "analysis": "Common codec probes on complete stored payloads and suffixes after common prefixes",
    "read_only": True,
    "codec_names": list(codecs),
    "codec_versions": codec_versions,
    "interpretation_limit": (
        "A decoder failure at these starts does not rule out proprietary compression, encryption, "
        "another framing layer, or non-compressed payloads. It does not prove encryption."
    ),
    "images": {},
}

for image_name, path in IMAGES.items():
    image = path.read_bytes()
    image_hash = hashlib.sha256(image).hexdigest()
    image_result = {
        "path": str(path.relative_to(ROOT)),
        "size": len(image),
        "sha256": image_hash,
        "sections": {},
    }
    for section, header in SECTIONS.items():
        stored = struct.unpack_from("<I", image, header + 0x30)[0]
        expanded = struct.unpack_from("<I", image, header + 0x3C)[0]
        payload_start = header + 0x40
        payload = image[payload_start : payload_start + stored]
        prefix_len = COMMON_PREFIX_LEN[section]
        cuts = {0, prefix_len}
        if section == "updater":
            cuts.add(194)  # first divergence across all ten payloads
        cuts = sorted(cuts)
        section_data = {
            "header_offset": f"0x{header:06X}",
            "payload_start": f"0x{payload_start:06X}",
            "stored_length": stored,
            "expanded_length_candidate": expanded,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "candidate_prefix_cut_length": prefix_len,
            "probes": [],
        }
        for cut in cuts:
            suffix = payload[cut:]
            probe = {
                "cut": cut,
                "start_offset": f"0x{payload_start + cut:06X}",
                "suffix_size": len(suffix),
                "suffix_sha256": hashlib.sha256(suffix).hexdigest(),
                "first_16_bytes": suffix[:16].hex(" "),
                "expected_output_sizes": {
                    "full_expanded_length": expanded,
                    "expanded_minus_cut_if_prefix_is_literal": max(0, expanded - cut),
                },
                "codecs": {},
            }
            for codec_name, decode in codecs.items():
                try:
                    decoded = decode(suffix)
                    probe["codecs"][codec_name] = {
                        "valid": True,
                        "output_size": len(decoded),
                        "matches_full_expanded_length": len(decoded) == expanded,
                        "matches_expanded_minus_cut": len(decoded) == max(0, expanded - cut),
                        "output_sha256": hashlib.sha256(decoded).hexdigest(),
                    }
                except Exception as exc:
                    probe["codecs"][codec_name] = {
                        "valid": False,
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:160],
                    }
            expected = expanded if cut == 0 else max(0, expanded - cut)
            probe["raw_block_candidates"] = {
                "expected_output_size_if_header_is_expanded_length": expected,
                **raw_block_probes(suffix, expected),
            }
            section_data["probes"].append(probe)
        image_result["sections"][section] = section_data
    result["images"][image_name] = image_result

out = ROOT / "firmware/work/section-suffix-codec-probes.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
