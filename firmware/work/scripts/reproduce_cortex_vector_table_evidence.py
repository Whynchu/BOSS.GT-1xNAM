#!/usr/bin/env python3
"""Inventory Cortex-M-style vector tables in bounded ESC91.000 blocks."""
from __future__ import annotations

import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs

ROOT = Path(__file__).resolve().parents[3]
BASE = 0x00FFFFD0
BLOCK_SIZE = 0x2000
VECTOR_OFFSET = 0x30
VECTOR_WORDS = 176
IMAGES = {
    "GT-1 v1.08": ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN",
    "GT-1 v1.09": ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN",
    "KATANA v2.01": ROOT / "firmware/work/reference/esc2-comparators/katana_v201/extracted/katana_sys_v201/KATANARM.BIN",
    "KATANA v4.00": ROOT / "firmware/work/reference/esc2-comparators/katana_v400/extracted/katana_sys_v400/KATANARM.BIN",
}
OUT = ROOT / "firmware/work/cortex-vector-table-evidence.json"
DISASM = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)

results = {}
for name, path in IMAGES.items():
    image = path.read_bytes()
    words = [struct.unpack_from("<I", image, VECTOR_OFFSET + 4 * i)[0] for i in range(VECTOR_WORDS)]
    handlers = words[1:]
    mapped_thumb = [w for w in handlers if w & 1 and BASE <= (w & ~1) < BASE + BLOCK_SIZE]
    zeros = [i + 1 for i, w in enumerate(handlers) if w == 0]
    invalid_nonzero = [
        {"vector_index": i + 1, "word": f"0x{w:08X}"}
        for i, w in enumerate(handlers)
        if w != 0 and not (w & 1 and BASE <= (w & ~1) < BASE + BLOCK_SIZE)
    ]
    freq = Counter(w for w in mapped_thumb)
    unique_targets = []
    for address, occurrences in freq.items():
        target_off = (address & ~1) - BASE
        raw = image[target_off:target_off + 16]
        decoded = [
            {"address": f"0x{i.address:08X}", "bytes": i.bytes.hex(" "), "mnemonic": i.mnemonic, "operands": i.op_str}
            for i in DISASM.disasm(raw, address & ~1)
        ]
        unique_targets.append({
            "address": f"0x{address:08X}",
            "vector_occurrences": occurrences,
            "target_file_offset": f"0x{target_off:06X}",
            "first_16_bytes": raw.hex(" "),
            "thumb_disassembly_bounded_16_bytes": decoded,
        })
    results[name] = {
        "path": str(path.relative_to(ROOT)),
        "image_size": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "first_8k_sha256": hashlib.sha256(image[:BLOCK_SIZE]).hexdigest(),
        "candidate_runtime_base": f"0x{BASE:08X}",
        "vector_table_file_offset": f"0x{VECTOR_OFFSET:04X}",
        "vector_table_runtime_address": f"0x{BASE + VECTOR_OFFSET:08X}",
        "vector_word_count": VECTOR_WORDS,
        "vector_table_sha256": hashlib.sha256(image[VECTOR_OFFSET:VECTOR_OFFSET + VECTOR_WORDS * 4]).hexdigest(),
        "initial_stack_pointer": f"0x{words[0]:08X}",
        "reserved_zero_handler_indices": zeros,
        "nonzero_handler_count": len(handlers) - len(zeros),
        "thumb_handler_count_mapped_inside_first_8k": len(mapped_thumb),
        "invalid_nonzero_handler_entries": invalid_nonzero,
        "unique_mapped_handler_count": len(freq),
        "most_common_mapped_handlers": [
            {"address": f"0x{address:08X}", "occurrences": count, "target_file_offset": f"0x{(address & ~1) - BASE:06X}"}
            for address, count in freq.most_common(12)
        ],
        "unique_handler_target_samples": unique_targets,
        "first_16_handler_words": [f"0x{w:08X}" for w in handlers[:15]],
        "vector_15_handler_probe": {
            "vector_index": 15,
            "vector_word": f"0x{words[15]:08X}",
            "target_file_offset": f"0x{((words[15] & ~1) - BASE):06X}" if words[15] else None,
            "target_bytes_16": image[((words[15] & ~1) - BASE):((words[15] & ~1) - BASE) + 16].hex(" ") if words[15] else None,
            "GT1_literal_words_file_0x71c_0x720": [f"0x{struct.unpack_from('<I', image, off)[0]:08X}" for off in (0x71C, 0x720)] if name.startswith("GT-1") else None,
            "behavior_note": "GT-1 vector 15 targets code at 0x604 that reads a word through literal 0x01010000, increments it, and writes it through literal 0x40005000; this is a code-flow observation, not a known memory-map definition. KATANA's vector 15 points to its default self-branch stub.",
        },
        "external_interrupt_slot_count": VECTOR_WORDS - 16,
        "external_interrupt_slots_all_same_default_handler": len(set(words[16:])) == 1,
        "external_interrupt_default_handler": f"0x{words[16]:08X}",
    }

report = {
    "analysis": "Cortex-M-style vector-table structural comparison",
    "read_only": True,
    "method": "Parse 176 little-endian words beginning at file offset 0x30 in the bounded ESC91.000 block. Treat word 0 as initial stack pointer and words 1 onward as handler entries; test nonzero entries for Thumb bit and target within the candidate 0x00FFFFD0 + file_offset first-block map.",
    "images": results,
    "interpretation": "The vector slot layout (initial stack pointer, core exception/reserved slots, and external interrupt slots), odd Thumb handler pointers, and repeated default interrupt handler strongly support Cortex-M-style bootstrap code. This does not identify the ESC2 silicon, prove the bootstrap executes on MB8AA4181, or classify the later updater/application payload ISA.",
    "limits": [
        "The 176-word extent is a bounded structural probe, not a claim that the hardware implements exactly 160 external IRQ lines.",
        "A vector-table pattern identifies a Cortex-M-like code format in this bootstrap region; it does not establish the identity of the executing processor.",
        "No inference about GT1Upd or GT1Appli ISA/load map follows from this table.",
        "No device was accessed and no firmware was modified.",
    ],
}
OUT.write_text(json.dumps(report, indent=2) + "\n")
print(OUT)
