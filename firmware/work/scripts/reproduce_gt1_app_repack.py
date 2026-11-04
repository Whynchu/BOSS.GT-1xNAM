#!/usr/bin/env python3
"""Offline no-op repack of the GT-1 v1.09 application section.

Read-only with respect to the device. This script:

1. hash-checks the official v1.09 image;
2. decodes the stored GT1Appli payload with the loader's LZ-style routine;
3. re-encodes the same bytes with a simple greedy encoder for the same format;
4. verifies the re-encoded stream decodes byte-for-byte to the original app;
5. rewrites the app header's stored length and additive checksum;
6. writes a candidate 4 MiB image with 0xFF fill after the new payload.

It does not flash, validate on hardware, or claim the updater will accept the
result. It is the offline half of a future, separately authorized experiment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
IMAGE = ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN"
OUTDIR = ROOT / "firmware/work/repacked"
EXPECTED_IMAGE_SHA256 = "412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf"
APP_HEADER = 0x40000
APP_NEXT_REGION = 0x1FC000  # first non-0xFF data after the app partition


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def put_u32(data: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", data, off, value & 0xFFFFFFFF)


def decode(src: bytes, expected_output: int) -> bytes:
    """Emulate the loader's LZ routine (control bit 1 = literal, 0 = match)."""
    pos = 0
    out = bytearray()
    ring = bytearray(4096)
    write_at = 0xFEE
    flags = 0

    def read_byte() -> int:
        nonlocal pos
        if pos >= len(src):
            raise EOFError("stored payload ended early")
        value = src[pos]
        pos += 1
        return value

    while len(out) < expected_output:
        flags >>= 1
        if not flags & 0x100:
            flags = read_byte() | 0xFF00
        if flags & 1:
            value = read_byte()
            out.append(value)
            ring[write_at] = value
            write_at = (write_at + 1) & 0xFFF
        else:
            lo = read_byte()
            hi_len = read_byte()
            distance = lo | ((hi_len & 0xF0) << 4)
            count = (hi_len & 0x0F) + 3
            for i in range(count):
                value = ring[(distance + i) & 0xFFF]
                out.append(value)
                ring[write_at] = value
                write_at = (write_at + 1) & 0xFFF
    return bytes(out[:expected_output])


def encode(data: bytes) -> bytes:
    """Greedy encoder for the same LZ format.

    Tokens are grouped eight per control byte, matching the loader's
    sentinel-shift bit reader. Ring positions are absolute 12-bit indices
    starting at 0xFEE, as in the decoder.
    """
    n = len(data)
    out = bytearray()
    table: dict[bytes, deque[int]] = defaultdict(deque)

    def remember(pos: int) -> None:
        if pos + 2 < n:
            key = data[pos:pos + 3]
            dq = table[key]
            dq.append(pos)
            while dq and dq[0] < pos - 4095:
                dq.popleft()

    i = 0
    while i < n:
        controls = 0
        tokens: list[bytes] = []
        for bit in range(8):
            if i >= n:
                break
            best_len = 0
            best_pos = -1
            if i + 3 <= n:
                for p in reversed(table.get(data[i:i + 3], ())):
                    if i - p > 4095:
                        break
                    # Non-overlapping matches only; the decoder would also
                    # support overlap, but this keeps the search simple.
                    max_len = min(18, n - i, i - p)
                    length = 3
                    while length < max_len and data[p + length] == data[i + length]:
                        length += 1
                    if length > best_len:
                        best_len = length
                        best_pos = p
                        if best_len == 18:
                            break
            if best_len >= 3:
                distance = (0xFEE + best_pos) & 0xFFF
                hi_len = ((distance >> 8) << 4) | (best_len - 3)
                tokens.append(bytes((distance & 0xFF, hi_len)))
                controls |= (0 << bit)
                for k in range(best_len):
                    remember(i + k)
                i += best_len
            else:
                tokens.append(bytes((data[i],)))
                controls |= (1 << bit)
                remember(i)
                i += 1
        out.append(controls)
        for token in tokens:
            out.extend(token)
    return bytes(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTDIR / "v109-noop-repacked.bin")
    args = parser.parse_args()

    image = IMAGE.read_bytes()
    image_hash = hashlib.sha256(image).hexdigest()
    assert image_hash == EXPECTED_IMAGE_SHA256, image_hash
    assert image[APP_HEADER:APP_HEADER + 8] == b"BSSESC2:"

    source_offset = u32(image, APP_HEADER + 0x2C)
    stored_length = u32(image, APP_HEADER + 0x30)
    stored_checksum = u32(image, APP_HEADER + 0x34)
    destination = u32(image, APP_HEADER + 0x38)
    expanded_length = u32(image, APP_HEADER + 0x3C)
    payload_start = APP_HEADER + source_offset
    payload_end = payload_start + stored_length
    payload = image[payload_start:payload_end]

    assert stored_checksum == sum(payload) & 0xFFFFFFFF
    assert destination == 0x60000000

    original = decode(payload, expanded_length)
    original_hash = hashlib.sha256(original).hexdigest()
    assert original_hash == "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29"

    encoded = encode(original)
    roundtrip = decode(encoded, expanded_length)
    roundtrip_hash = hashlib.sha256(roundtrip).hexdigest()
    assert roundtrip == original, (len(roundtrip), roundtrip_hash)
    assert len(encoded) < APP_NEXT_REGION - payload_start, "re-encoded payload overruns the app partition"

    candidate = bytearray(image)
    candidate[payload_start:APP_NEXT_REGION] = b"\xFF" * (APP_NEXT_REGION - payload_start)
    candidate[payload_start:payload_start + len(encoded)] = encoded
    put_u32(candidate, APP_HEADER + 0x30, len(encoded))
    put_u32(candidate, APP_HEADER + 0x34, sum(encoded) & 0xFFFFFFFF)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(candidate)

    manifest = {
        "read_only_device": True,
        "classification": "offline no-op repack; not flashed or validated on hardware",
        "input_image": {"path": str(IMAGE.relative_to(ROOT)), "sha256": image_hash, "size": len(image)},
        "app_header": {
            "file_offset": hex(APP_HEADER),
            "source_offset_plus_2c": hex(source_offset),
            "original_stored_length": stored_length,
            "original_checksum": hex(stored_checksum),
            "expanded_length_plus_3c": expanded_length,
            "destination_plus_38": hex(destination),
        },
        "decoded_app": {"sha256": original_hash, "size": len(original)},
        "reencoded": {
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "size": len(encoded),
            "ratio": len(encoded) / len(original),
            "new_checksum": hex(sum(encoded) & 0xFFFFFFFF),
            "roundtrip_sha256": roundtrip_hash,
            "roundtrip_exact": True,
            "section_capacity_bytes": APP_NEXT_REGION - payload_start,
            "fits_section": True,
        },
        "candidate": {
            "path": str(args.output.relative_to(ROOT)) if args.output.is_absolute() else str(args.output),
            "sha256": hashlib.sha256(candidate).hexdigest(),
            "size": len(candidate),
        },
        "limits": [
            "The candidate image has not been checked by the stock updater or bootloader.",
            "The updater is known to emit sum/header/verify/compare errors, but its exact validation paths and the bootloader's runtime validator table are not fully traced.",
            "No recovery procedure has been tested. Do not flash without a serial-flash recovery plan and explicit authorization.",
        ],
    }
    manifest_path = args.output.with_suffix(".json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"input image       {image_hash}")
    print(f"decoded app       {len(original)} bytes  {original_hash}")
    print(f"re-encoded        {len(encoded)} bytes  ratio {len(encoded)/len(original):.4f}  "
          f"capacity {APP_NEXT_REGION - payload_start} bytes")
    print(f"round-trip        exact={roundtrip == original}  {roundtrip_hash}")
    print(f"new checksum      {sum(encoded) & 0xFFFFFFFF:#010x}")
    print(f"candidate         {args.output}  {hashlib.sha256(candidate).hexdigest()}")
    print(f"manifest          {manifest_path}")


if __name__ == "__main__":
    main()
