#!/usr/bin/env python3
"""Summarize selected decoded GT-1 app literals and Thumb-2 seed disassembly.

Inputs are the four hash-verified decoded applications emitted by
reproduce_gt1_bootstrap_decoder_probe.py --export-decoded. This is a static,
read-only classification aid; pointer values are not asserted to be code.
"""
from __future__ import annotations
import hashlib, json, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
ROOT = Path(__file__).resolve().parents[3]
EXPECTED = {
 'v105': '8297887084af48b04189955bbd8bdb4e0e6ff6a0e0fbcac7f85a175792775e29',
 'v107': '304b88a2c628cf47bb5091ecbc6da4fab4924f88cdea8897b44e5f474b9fb001',
 'v108': 'c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1',
 'v109': '2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29',
}
RANGES = [(0x01000000, 0x01100000), (0x60000000, 0x64000000)]
results = {}
candidate_offsets = [0x2CC, 0x2D0, 0x2D4, 0x2D8, 0x308, 0x33C, 0x380, 0x3B4, 0x3CC, 0x3D4]
disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
for ver, expected in EXPECTED.items():
 p = ROOT / f'firmware/work/decoded/{ver}-GT1Appli.bin'; data=p.read_bytes(); sha=hashlib.sha256(data).hexdigest(); assert sha==expected
 words=[]
 for off in range(0, min(len(data)-3, 0x200), 4):
  v=struct.unpack_from('<I',data,off)[0]
  cls='other'
  if any(lo <= (v & ~1) < hi for lo,hi in RANGES): cls='address_candidate'
  words.append({'offset':hex(off),'value':hex(v),'classification':cls})
 ptrs=[]
 for off in range(0, min(len(data)-3, 0x400), 4):
  v=struct.unpack_from('<I',data,off)[0]
  if v&1 and any(lo <= (v&~1) < hi for lo,hi in RANGES):
   ptrs.append({'offset':hex(off),'value':hex(v),'target':hex(v&~1),'region':'bootstrap' if v<0x60000000 else 'candidate_app'})
 target_probe=[]
 for off in candidate_offsets:
  value=struct.unpack_from('<I',data,off)[0]
  target=(value & ~1)-0x60000000
  ins=list(disassembler.disasm(data[target:target+32],0x60000000+target)) if value&1 and 0<=target<len(data)-1 else []
  consumed=(ins[-1].address+ins[-1].size-(0x60000000+target)) if ins else 0
  target_probe.append({'pointer_word_offset':hex(off),'pointer_value':hex(value),'target_offset_under_candidate_base':hex(target) if target>=0 else None,'thumb_tagged':bool(value&1),'target_inside_candidate_image':bool(value&1 and 0<=target<len(data)-1),'decoded_bytes_first_32':consumed,'cross_version_stability':'pointer words at 0x2CC/0x2D0 are stable, but target bytes/semantics vary' if off in (0x2CC,0x2D0) else 'secondary probe; not promoted without data-flow evidence','first_instructions':[{'offset':hex(i.address-0x60000000),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins[:8]]})
 results[ver]={'path':str(p.relative_to(ROOT)),'size':len(data),'sha256':sha,'initial_words':words,'thumb_tagged_address_candidates_first_0x400':ptrs,'selected_pointer_target_probes':target_probe,'notable_fixed_literal_offset_0xe4':hex(struct.unpack_from('<I',data,0xe4)[0])}
report={'read_only':True,'candidate_app_base':'0x60000000 (hypothesis from section header and coherent Ghidra ARMv7/Thumb probe)','candidate_pointer_probe_offsets':[hex(x) for x in candidate_offsets],'versions':results,'interpretation_limits':['Only odd values whose cleared targets fall inside the decoded image are listed as in-image Thumb pointer candidates; other aligned words are not pointers by this test.','The repeated values at offsets 0x2CC and 0x2D0 are stable across releases, but target bytes and apparent behavior vary; they are not established function entry points.','A short Thumb decode is not proof a target is callable or reachable; control/data-flow and relocation analysis are still required.','The first word at output offset 0xE4 is a fixed 0x01000300 address candidate, potentially bootstrap ROM.','No physical memory placement or app entry is asserted.']}
out=ROOT/'firmware/work/decoded-app-pointer-probe.json';out.write_text(json.dumps(report,indent=2)+'\n');print(out)
for v,r in results.items(): print(v,'size',r['size'],'thumb_ptr_candidates_first_0x400',len(r['thumb_tagged_address_candidates_first_0x400']),'literal_e4',r['notable_fixed_literal_offset_0xe4'])
