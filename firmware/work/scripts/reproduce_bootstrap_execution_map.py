#!/usr/bin/env python3
"""Reproduce static GT-1 bootstrap control-flow and literal-table facts.

Read-only analysis of the bounded ESC91.000 block. This does not execute or
emulate firmware and does not infer runtime-populated values for erased tables.
"""
from __future__ import annotations
import hashlib, json, struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
IMAGE = ROOT / 'firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN'
BASE = 0x00FFFFD0
b = IMAGE.read_bytes()
sha = hashlib.sha256(b).hexdigest()
assert len(b) == 0x400000
assert sha == '412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf'
word = lambda o: struct.unpack_from('<I', b, o)[0]
fileoff = lambda addr: addr - BASE
# Literal operands are decoded from the actual 16-bit Thumb LDR instructions.
def thumb_ldr_literal(insn_off: int) -> tuple[int, int]:
    insn = struct.unpack_from('<H', b, insn_off)[0]
    assert insn & 0xF800 == 0x4800, (hex(insn_off), hex(insn))
    pc = (BASE + insn_off + 4) & ~3
    literal_addr = pc + ((insn & 0xFF) << 2)
    return literal_addr, word(fileoff(literal_addr))

# Startup record walker at file 0xBE0 uses literal at 0xBBC (LDR r5,[PC,#0x1c]).
transform_table_start_literal_addr, transform_table_runtime = thumb_ldr_literal(0xBE0)
transform_table_end_literal_addr, transform_table_end_runtime = thumb_ldr_literal(0xBE2)
assert transform_table_start_literal_addr - BASE == 0xBFC
assert transform_table_end_literal_addr - BASE == 0xC00
transform_table_file = fileoff(transform_table_runtime)
# The pointers differ by 0x20; loop increments by 0x10, so it visits two records.
assert transform_table_end_runtime - transform_table_runtime == 0x20
transform_records = []
for i in range(2):
    off = transform_table_file + i * 16
    transform_records.append({'file_offset': hex(off), 'words_le': [hex(word(off + 4*j)) for j in range(4)]})

# Callback table validator at file 0x9BC loads literal at 0x9C4 (LDR r1,[PC,#0x20]).
validation_literal_addr, validation_table_runtime = thumb_ldr_literal(0x9C4)
assert validation_literal_addr - BASE == 0x9E8
validation_table_file = fileoff(validation_table_runtime)
# This address is in the full image's candidate linear mapping, though runtime
# initialization may populate it before the validator reads the entries.
validation_entries = []
assert validation_table_runtime == 0x01010028
assert validation_table_file == 0x10058

assert word(0x2FC) == 0x010009F1 and word(0x300) == 0x01028000
assert word(0x30) == 0x01011240 and word(0x34) == 0x01000AE5
# The independent table calculations are explicit invariants.
assert transform_table_file == 0xC94
assert transform_table_end_runtime - BASE == 0xCB4
assert b[transform_table_file:transform_table_file + 32] == bytes.fromhex('840c00010000010128000000d40b0001ac0c00012800010118120000e40b0001')
assert b[transform_table_file:transform_table_file + 32] != b'\xff' * 32
assert validation_table_runtime >= 0x01000000 and validation_table_runtime - BASE == validation_table_file

# Container bounds are arithmetic candidates from the known 0x40-byte headers.
sections = []
for header, name in [(0x2000, 'GT1Upd'), (0x40000, 'GT1Appli')]:
    length = word(header + 0x30)
    start = header + 0x40
    sections.append({'name': name, 'header': hex(header), 'payload_start': hex(start),
                     'stored_length': hex(length), 'payload_end_exclusive': hex(start + length),
                     'checksum_field': hex(word(header + 0x34)),
                     'byte_sum_mod32': hex(sum(b[start:start + length]) & 0xFFFFFFFF)})
    # The decoder loader passes source base+[0x2C], destination [+0x38], and
    # output length [+0x3C]. These constants independently match the headers.
    assert 0x03000000 + header in (0x03002000, 0x03040000)
    assert word(header + 0x2C) == 0x40
    assert word(header + 0x38) == 0x60000000

report = {
    'read_only': True,
    'image': str(IMAGE.relative_to(ROOT)), 'size': len(b), 'sha256': sha,
    'mapping': 'runtime_address = 0x00FFFFD0 + file_offset is supported for bootstrap code; section bases separately map as runtime_address = 0x03000000 + file_offset at the two headers',
    'reset_vector': {'sp': hex(word(0x30)), 'pc': hex(word(0x34))},
    'trampoline': {'file_offset': '0x2f0',
                   'sequence': 'load SP from file 0x300; BL runtime 0x01000BB0 (file 0xBE0); load entry from 0x2FC; BX entry',
                   'stack_value': hex(word(0x300)), 'entry_value': hex(word(0x2FC))},
    'loader_entry': {'file_offset': '0xA20', 'runtime': hex(BASE + 0xA20), 'selected_by_literal': hex(word(0x2FC)), 'validator_call_runtime': '0x010009BC', 'decoder_call_runtime': '0x010008DA', 'decoder_entry_file_offset': '0x90A', 'reader_entry_runtime': '0x010008C0', 'reader_entry_file_offset': '0x8F0', 'section_base_candidates': ['0x03002000', '0x03040000'], 'section_base_file_offsets': ['0x2000', '0x40000'], 'header_arguments': {'+0x2c': 'source offset from header; added to section base', '+0x30': 'stored byte count on zero-expanded-size copy path', '+0x34': 'additive byte-sum checksum candidate', '+0x38': 'destination address', '+0x3c': 'expanded output length / decoder bound'}, 'section_base_to_file_relation': 'runtime_address = 0x03000000 + header_file_offset'},
    'transform_record_table': {
        'derived_from': 'routine at file 0xBE0 loads two literal bounds and walks two 16-byte records; only separate reachability should be claimed where caller evidence exists',
        'start_literal_file_offset': hex(transform_table_start_literal_addr - BASE),
        'end_literal_file_offset': hex(transform_table_end_literal_addr - BASE),
        'start_runtime': hex(transform_table_runtime), 'end_runtime_exclusive': hex(transform_table_end_runtime),
        'first_record_runtime': hex(transform_table_runtime), 'first_record_file_offset': hex(transform_table_file),
        'stride': 16, 'count': len(transform_records), 'records': transform_records,
        'all_ff': b[transform_table_file:transform_table_file + 32] == b'\xff' * 32,
        'sha256': hashlib.sha256(b[transform_table_file:transform_table_file + 32]).hexdigest()},
    'validation_callback_table': {
        'derived_from': 'LDR literal at 0x9C4; validator indexes four entries with stride 8',
        'literal_file_offset': hex(validation_literal_addr - BASE),
        'table_runtime': hex(validation_table_runtime), 'table_file_offset': hex(validation_table_file),
        'stride': 8, 'count': 4, 'entries': validation_entries,
        'inside_full_image_candidate_map': validation_table_runtime >= BASE and validation_table_file + 32 <= len(b),
        'candidate_full_image_file_offset': hex(validation_table_file),
        'bytes_at_candidate_offset': b[validation_table_file:validation_table_file + 32].hex()},
    'containers': sections,
    'interpretation_limits': [
        'Routine at 0xBE0 walks two records and is called from its local startup sequence; exact record semantics are inferred from register use.',
        'If the records are interpreted as source/destination/length/callback tuples, callback runtime values 0x01000BD4 and 0x01000BE4 map to file offsets 0xC04 and 0xC14.',
        'Loader at file 0xA20 calls decoder entry at runtime 0x010008DA (file 0x90A). Its section-base constants exactly equal 0x03000000 plus the respective header file offsets; an instruction-derived bounded decoder probe is separately recorded.',
        'Decoder entry at file 0x90A uses reader runtime 0x010008C0 (file 0x8F0) and initializes a ring at runtime 0x01010028; the ring address falls in the full image candidate mapping at file 0x10058, but runtime placement is still an interpretation.',
        'Byte recurrence across versions does not prove a shared runtime role.'
    ]
}
out = ROOT / 'firmware/work/bootstrap-execution-map.json'
out.write_text(json.dumps(report, indent=2) + '\n')
print(out)
