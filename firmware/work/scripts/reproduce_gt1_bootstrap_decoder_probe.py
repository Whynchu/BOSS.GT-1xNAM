#!/usr/bin/env python3
"""Trace GT-1 loader fields and emulate its bounded LZ-style routine read-only.

The script uses the instruction-derived v1.09 loader at file 0xA20 and decoder
at 0x90A. It writes evidence JSON only; it never changes firmware inputs.
"""
from __future__ import annotations
import hashlib
import json
import struct
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = {
    'v105': 'b1bde0410795230b4a89ee3dfbbd357700bba7020624c0ff832ae3d8539d8bb4',
    'v107': '6a3110cd42c4b129494a93bc88d4f218e2e0b9377868ca051018b28696d6c22f',
    'v108': '7219679a87e985316264544423c9940ccbcbadeb2df0b2f13711ae57194cb612',
    'v109': '412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf',
}
IMAGE_BASE = 0x00FFFFD0
SECTION_FILE_BASE = 0x03000000
RING_RUNTIME = 0x01010028

parser = argparse.ArgumentParser()
parser.add_argument('--export-decoded', action='store_true', help='write decoded sections under firmware/work/decoded/')
args = parser.parse_args()

def u32(data: bytes, x: int) -> int:
    return struct.unpack_from('<I', data, x)[0]

def decode_bytes(src: bytes, expected_output: int) -> bytes:
    pos = 0
    out = bytearray()
    ring = bytearray(4096)
    write_at = 0xFEE
    flags = 0

    def read_byte() -> int:
        nonlocal pos
        if pos >= len(src):
            raise EOFError('stored payload ended early')
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
            read_at = lo | ((hi_len & 0xF0) << 4)
            match_length = (hi_len & 0x0F) + 3
            for i in range(match_length):
                value = ring[(read_at + i) & 0xFFF]
                out.append(value)
                ring[write_at] = value
                write_at = (write_at + 1) & 0xFFF
    return bytes(out[:expected_output])

def decode(src: bytes, expected_output: int, cap: int, *, stop_at_output: bool) -> dict:
    """Bounded model of the Thumb routine's bit and ring operations.

    The routine has no input bound in firmware. This model enforces one and
    records truncation instead of reading past the selected stored payload.
    """
    pos = 0
    out = bytearray()
    ring = bytearray(4096)
    r7 = 0xFEE
    fp = 0
    control_reads = 0
    bit_reads = 0
    literal_reads = 0
    backref_pairs = 0
    backref_bytes = 0
    overshoot = False
    max_output = cap
    target_output = min(cap, expected_output) if stop_at_output else cap

    def read_byte() -> int:
        nonlocal pos
        if pos >= len(src):
            raise EOFError
        value = src[pos]
        pos += 1
        return value

    def emit(v: int) -> None:
        nonlocal r7, overshoot
        if len(out) < max_output:
            out.append(v & 0xFF)
            ring[r7] = v & 0xFF
            r7 = (r7 + 1) & 0xFFF
        else:
            overshoot = True

    try:
        while len(out) < target_output:
            fp >>= 1
            if not (fp & 0x100):
                control = read_byte()
                control_reads += 1
                fp = control | 0xFF00
            bit_reads += 1
            if fp & 1:
                emit(read_byte())
                literal_reads += 1
                continue
            lo = read_byte()
            hi_len = read_byte()
            distance = lo | ((hi_len & 0xF0) << 4)
            count = (hi_len & 0x0F) + 2
            backref_pairs += 1
            # The instruction computes nibble+2, initializes a zero counter,
            # and loops while counter <= length; therefore nibble+3 bytes.
            for i in range(count + 1):
                value = ring[(distance + i) & 0xFFF]
                emit(value)
                backref_bytes += 1
    except EOFError:
        pass
    return {
        'input_consumed': pos,
        'input_remaining': len(src) - pos,
        'output_produced': len(out),
        'output_sha256': hashlib.sha256(out).hexdigest(),
        'output_prefix_hex': out[:64].hex(),
        'output_suffix_hex': out[-32:].hex(),
        'control_bytes': control_reads,
        'control_bits_consumed': bit_reads,
        'literal_bytes': literal_reads,
        'backreference_pairs': backref_pairs,
        'backreference_output_bytes': backref_bytes,
        'overshoot_before_output_bound': overshoot,
        'terminated_at_declared_output_length': len(out) >= expected_output,
        'source_exhausted': pos == len(src) and len(out) < expected_output,
        'mode': 'firmware_output_bound' if stop_at_output else 'continue_until_source_exhaustion',
    }

versions = {}
for version, expected_sha in VERSIONS.items():
    image = ROOT / f'firmware/extracted/{version}/gt1_sys_{version}/GT1ROM.BIN'
    b = image.read_bytes()
    image_sha = hashlib.sha256(b).hexdigest()
    assert image_sha == expected_sha
    sections = []
    for name, header, expected_runtime in [
        ('GT1Upd', 0x2000, 0x03002000),
        ('GT1Appli', 0x40000, 0x03040000),
    ]:
        assert expected_runtime == SECTION_FILE_BASE + header
        assert b[header:header + 12].startswith(b'BSSESC2:')
        source_offset = u32(b, header + 0x2C)
        stored_length = u32(b, header + 0x30)
        checksum = u32(b, header + 0x34)
        destination = u32(b, header + 0x38)
        expanded_length = u32(b, header + 0x3C)
        start = header + source_offset
        end = start + stored_length
        payload = b[start:end]
        assert end <= len(b)
        assert checksum == (sum(payload) & 0xFFFFFFFF)
        assert destination == 0x60000000
        bounded_result = decode(payload, expanded_length, expanded_length, stop_at_output=True)
        diagnostic_result = decode(payload, expanded_length, expanded_length + 64, stop_at_output=False)
        assert bounded_result['input_consumed'] == stored_length
        assert bounded_result['output_produced'] == expanded_length
        assert diagnostic_result['input_consumed'] == stored_length
        assert diagnostic_result['output_produced'] == expanded_length
        assert diagnostic_result['input_remaining'] == 0
        decoded_bytes = decode_bytes(payload, expanded_length)
        assert hashlib.sha256(decoded_bytes).hexdigest() == bounded_result['output_sha256']
        decoded_artifact = None
        if args.export_decoded:
            output_dir = ROOT / 'firmware/work/decoded'
            output_dir.mkdir(parents=True, exist_ok=True)
            decoded_path = output_dir / f'{version}-{name}.bin'
            decoded_path.write_bytes(decoded_bytes)
            decoded_artifact = {
                'path': str(decoded_path.relative_to(ROOT)),
                'size': len(decoded_bytes),
                'sha256': hashlib.sha256(decoded_bytes).hexdigest(),
            }
        sections.append({
            'name': name,
            'header_file_offset': hex(header),
            'header_runtime_address': hex(expected_runtime),
            'runtime_to_file_relation': f'file_offset = runtime - 0x{SECTION_FILE_BASE:08X}',
            'header_hex': b[header:header + 0x40].hex(),
            'source_offset_field_plus_2c': hex(source_offset),
            'stored_length_field_plus_30': hex(stored_length),
            'checksum_field_plus_34': hex(checksum),
            'computed_additive_byte_sum': hex(sum(payload) & 0xFFFFFFFF),
        'destination_field_plus_38': hex(destination),
        'post_decode_header_field_plus_28': hex(u32(b, header + 0x28)),
            'expanded_length_field_plus_3c': hex(expanded_length),
            'payload_file_range': [hex(start), hex(end)],
            'payload_sha256': hashlib.sha256(payload).hexdigest(),
            'decoder_result': bounded_result,
            'continue_to_source_end_diagnostic': diagnostic_result,
            'decoded_artifact': decoded_artifact,
        })
    versions[version] = {
        'image': str(image.relative_to(ROOT)),
        'image_size': len(b),
        'image_sha256': image_sha,
        'sections': sections,
    }

report = {
    'read_only': True,
    'versions': versions,
    'loader': {
        'file_offset': '0xA20',
        'runtime_address': hex(IMAGE_BASE + 0xA20),
        'decoder_entry_runtime': '0x010008DA',
        'decoder_entry_file_offset': '0x90A',
        'call_args': 'r0=section base+[0x2C]; r1=[0x38]; r2=[0x3C]',
        'copy_path_when_plus_3c_zero': 'copy [0x2C] source to [0x38] destination for [0x30] bytes, in 4-byte units',
        'section_base_constants': ['0x03002000', '0x03040000'],
        'section_base_to_file_mapping': 'file_offset = runtime_address - 0x03000000; verified for both headers by exact signature and field match',
    },
    'decoder': {
        'reader_runtime': '0x010008C0',
        'reader_file_offset': '0x8F0',
        'algorithm_observation': 'Control-bit stream: 1 means literal; 0 means two-byte backreference; 12-bit ring; the disassembly computes low nibble + 2 and then uses an inclusive counter, producing low nibble + 3 bytes. Both output-bounded and source-exhaustion modes consume all stored bytes and produce exactly +0x3C across all eight sections; this is strong multi-version format validation, pending independent output mapping/entry validation.',
        'ring_runtime': hex(RING_RUNTIME),
        'ring_file_offset_under_candidate_image_map': hex(RING_RUNTIME - IMAGE_BASE),
        'ring_initialized_bytes': '0xFEE',
        'model_limits': ['Exact bounded source span from header stored length.', 'Firmware-bound mode starts tokens while output is below +0x3C and can complete a back-reference beyond that boundary; output is safely captured to the declared length in that mode.', 'Diagnostic mode ignores the output bound and continues only within the stored payload to report consumed input and excess output.', 'No firmware or device state is modified.'],
    },
}
out = ROOT / 'firmware/work/bootstrap-decoder-probe.json'
out.write_text(json.dumps(report, indent=2) + '\n')
print(out)
for version, result in versions.items():
    for s in result['sections']:
        r = s['decoder_result']
        d = s['continue_to_source_end_diagnostic']
        print(f"{version} {s['name']}: bounded input={r['input_consumed']}/{int(s['stored_length_field_plus_30'], 16)} output={r['output_produced']}/{int(s['expanded_length_field_plus_3c'], 16)}; source-end input={d['input_consumed']}/{int(s['stored_length_field_plus_30'], 16)} output={d['output_produced']} sha256={r['output_sha256']}")
