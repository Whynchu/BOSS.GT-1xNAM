#!/usr/bin/env python3
"""Compare pinned NAM A2-Lite storage with candidate GT-1 numeric table islands."""
from __future__ import annotations
import hashlib, json, math, struct, zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
NAMB=ROOT/'firmware/work/reference/tone-3000-embedded/weights/a2lite.namb'
NAM_SOURCE=ROOT/'firmware/work/reference/tone-3000-embedded/namb/namb_reader.c'
GT1=ROOT/'firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN'
GT100=ROOT/'firmware/work/reference/esc2-comparators/gt100_v212/extracted/gt100_sys_v212/GT100ROM.BIN'
OUT=ROOT/'firmware/work/namb-gt1-numeric-format-comparison.json'

def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()

def inspect_namb(data:bytes):
 total,weights_off,weight_count,model_size,stored_crc=struct.unpack_from('<IIIII',data,8)
 crc=0xffffffff
 for i,x in enumerate(data[:total]):
  if 24<=i<28: continue
  c=(crc^x)&0xff
  for _ in range(8): c=(c>>1)^0xedb88320 if c&1 else c>>1
  crc=c^(crc>>8)
 crc ^= 0xffffffff
 weights_blob=data[weights_off:weights_off+weight_count*4]
 weights=struct.unpack('<%df'%weight_count,weights_blob)
 return {
  'magic_bytes':data[:4].decode('ascii'), 'version':struct.unpack_from('<H',data,4)[0],
  'total_size':total,'header_bytes':32,'metadata_bytes':48,'model_block_offset':80,
  'model_architecture_id':data[80],'model_block_size':model_size,
  'weights_offset':weights_off,'weight_count':weight_count,'weight_element':'little-endian IEEE-754 binary32',
  'weights_alignment_bytes':weights_off%4,'weights_size_bytes':len(weights_blob),
  'weights_end_exclusive':weights_off+len(weights_blob),'sample_rate_hz':struct.unpack_from('<d',data,36)[0],
  'stored_crc32':f'0x{stored_crc:08X}','computed_crc32_skip_bytes_24_to_27':f'0x{crc:08X}',
  'crc_valid':crc==stored_crc,'all_weights_finite':all(math.isfinite(x) for x in weights),
  'weight_min':min(weights),'weight_max':max(weights),'weight_mean':sum(weights)/len(weights),
  'weights_sha256':sha(weights_blob),
 }

namb=NAMB.read_bytes(); g1=GT1.read_bytes(); g100=GT100.read_bytes()
# Exact shared islands whose marker/float pattern was found in prior verified evidence.
islands=[
 {'GT1_offset':0x0D2929,'GT100_offset':0x0DB8F0,'length':311,'complete_records':32,'values':64},
 {'GT1_offset':0x0D2A8B,'GT100_offset':0x0DBA52,'length':229,'complete_records':23,'values':46},
 {'GT1_offset':0x0D2400,'GT100_offset':0x0DB3D1,'length':201,'complete_records':21,'values':42},
]
rows=[]
for s in islands:
 a=g1[s['GT1_offset']:s['GT1_offset']+s['length']]
 b=g100[s['GT100_offset']:s['GT100_offset']+s['length']]
 assert a==b
 markers={i for i,x in enumerate(a) if x==0xff}
 chains=[]
 for p in sorted(markers):
  if p-9 in markers: continue
  chain=[p]
  while chain[-1]+9 in markers: chain.append(chain[-1]+9)
  if len(chain)>=4: chains.append(chain)
 chain=max(chains,key=len)
 pairs=[struct.unpack('<ff',a[p+1:p+9]) for p in chain[:-1]]
 vals=[x for pair in pairs for x in pair]
 rows.append({
  'GT1_file_offset':f"0x{s['GT1_offset']:06X}",'GT100_file_offset':f"0x{s['GT100_offset']:06X}",
  'byte_length':s['length'],'sha256':sha(a),'identical_in_both_images':True,
  'observed_marker_byte':'0xFF','marker_stride_bytes':9,'parsed_complete_pairs':len(pairs),
  'pairs':[[float(f'{x:.9g}') for x in pair] for pair in pairs],
  'all_parsed_values_finite':all(math.isfinite(x) for x in vals),
  'values_min':min(vals),'values_max':max(vals),
 })
report={
 'read_only':True,
 'inputs':{
  'A2-Lite sample':{'path':str(NAMB.relative_to(ROOT)),'size':len(namb),'sha256':sha(namb)},
  'pinned upstream reader':{'path':str(NAM_SOURCE.relative_to(ROOT)),'sha256':sha(NAM_SOURCE.read_bytes())},
  'GT-1 v1.09':{'path':str(GT1.relative_to(ROOT)),'size':len(g1),'sha256':sha(g1)},
  'GT-100 v2.12':{'path':str(GT100.relative_to(ROOT)),'size':len(g100),'sha256':sha(g100)},
 },
 'nam_file_structure':inspect_namb(namb),
 'candidate_firmware_numeric_islands':rows,
 'comparison':{
  'A2Lite_weights_layout':'1,871 contiguous 4-byte float32 values at an aligned offset; no 1-byte delimiter between adjacent values.',
  'candidate_firmware_islands_layout':'observed 8 bytes interpreted as two float32 values plus a recurring 0xFF byte at 9-byte spacing in the listed spans.',
  'conclusion':'The observed GT-1 spans are not laid out as a direct contiguous A2-Lite .namb weight array. This format difference does not rule out a different internal model/table encoding or establish what the firmware data represents.',
  'semantic_limit':'No amp-model or NAM semantics are assigned to the candidate spans; plausible float decoding is not proof of use as float values by firmware.',
 },
 'validation':{
  'namb_crc_algorithm':'CRC-32/IEEE, initial 0xFFFFFFFF, reflected polynomial 0xEDB88320, final XOR 0xFFFFFFFF, bytes 24..27 excluded; reproduced from pinned namb_reader.c.',
  'hardware_accessed':False,'firmware_modified':False,
 }
}
assert report['nam_file_structure']['crc_valid']
assert report['nam_file_structure']['weight_count']==1871
assert report['nam_file_structure']['weights_end_exclusive']==len(namb)
OUT.write_text(json.dumps(report,indent=2)+'\n');print(OUT)
