#!/usr/bin/env python3
"""Reproduce the bounded v1.09 callback-10 optional-handler observation."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs

ROOT = Path(__file__).resolve().parents[3]
BASE = 0x01000300
SEGMENT = ROOT / "firmware/work/reconstructed/v109-GT1Appli-seg0.bin"
SEGMENT_SHA256 = "019adcf28e4a12444d48699b0b2a386a1a5feb2e43b59d465c696ee42540b9f9"
REPORT = ROOT / "firmware/work/ghidra-combined-v109-app-init-callbacks.txt"
REPORT_SHA256 = "1aefc2a76e433be5dd1d319aec2414c84e32a1d28b481e0b11fa787114728e50"

data = SEGMENT.read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != SEGMENT_SHA256:
    raise SystemExit(f"reconstructed segment SHA-256 mismatch: {digest}")
report_bytes = REPORT.read_bytes()
report_digest = hashlib.sha256(report_bytes).hexdigest()
if report_digest != REPORT_SHA256:
    raise SystemExit(f"Ghidra report SHA-256 mismatch: {report_digest}")

def read_at(runtime_address: int, length: int) -> bytes:
    offset = runtime_address - BASE
    return data[offset:offset + length]

def u32_at(runtime_address: int) -> int:
    return struct.unpack("<I", read_at(runtime_address, 4))[0]

handler = 0x01001550
handler_code = read_at(handler, 10)
expected_code = bytes.fromhex("0349097880f826107047")
if handler_code != expected_code:
    raise SystemExit(f"optional-handler instruction bytes changed: {handler_code.hex()}")
literal = 0x01001560
global_byte_address = u32_at(literal)
callback_literal = 0x01001564
callback_pointer = u32_at(callback_literal)
if callback_pointer != (handler | 1):
    raise SystemExit(f"handler pointer mismatch: 0x{callback_pointer:x}")

required_report_fragments = (
    "0100151a  bl  0x0100155a",
    "0100152c  bl  0x01002060",
    "010020bc  blx  r1",
)
report_text = report_bytes.decode("utf-8", errors="replace")
for fragment in required_report_fragments:
    if fragment not in report_text:
        raise SystemExit(f"missing expected Ghidra dispatcher evidence: {fragment}")

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
instructions = [
    {"address": f"0x{i.address:x}", "bytes": i.bytes.hex(), "instruction": f"{i.mnemonic} {i.op_str}".strip()}
    for i in md.disasm(handler_code, handler)
]
if len(instructions) != 4:
    raise SystemExit(f"expected four handler instructions, got {len(instructions)}")

out = {
    "read_only": True,
    "method": "verify reconstructed segment and Ghidra report hashes; decode the candidate handler and resolve its literal words",
    "interpretation": "The optional callback selected from the v1.09 callback-10 path copies one global byte into an object field at +0x26 and returns. It is initialization bookkeeping; this trace does not identify any audio processing path.",
    "input": {"path": str(SEGMENT.relative_to(ROOT)), "sha256": digest},
    "ghidra_report": {"path": str(REPORT.relative_to(ROOT)), "sha256": report_digest},
    "callback_context": {
        "startup_callback": "0x010014A4",
        "optional_handler_thunk": "0x0100155A",
        "generic_dispatcher": "0x01002060",
        "indirect_call_site": "0x010020BC",
        "handler_pointer_literal_address": f"0x{callback_literal:x}",
        "handler_pointer": f"0x{callback_pointer:x}",
    },
    "handler": {
        "address": f"0x{handler:x}",
        "instruction_bytes": handler_code.hex(),
        "instructions": instructions,
        "global_byte_pointer_literal_address": f"0x{literal:x}",
        "global_byte_address": f"0x{global_byte_address:x}",
        "destination_object_offset": "+0x26",
    },
}
out_path = ROOT / "firmware/work/gt1-callback10-helper-probe.json"
out_path.write_text(json.dumps(out, indent=2) + "\n")
print(out_path.relative_to(ROOT))
