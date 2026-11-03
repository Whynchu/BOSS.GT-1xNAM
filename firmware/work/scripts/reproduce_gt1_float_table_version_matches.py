#!/usr/bin/env python3
"""Find exact cross-release 9-byte float-pair table chains in GT-1 app payloads."""
from __future__ import annotations
import hashlib, json, math, struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
VERSIONS={
 'v1.05':ROOT/'firmware/extracted/v105/gt1_sys_v105/GT1ROM.BIN',
 'v1.07':ROOT/'firmware/extracted/v107/gt1_sys_v107/GT1ROM.BIN',
 'v1.08':ROOT/'firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN',
 'v1.09':ROOT/'firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN',
}
APP_START=0x40040
APP_ENDS={'v1.05':0x15E098,'v1.07':0x15E7A5,'v1.08':0x15E805,'v1.09':0x15FB3A}
OUT=ROOT/'firmware/work/gt1-float-table-version-matches.json'
images={v:p.read_bytes() for v,p in VERSIONS.items()}

def chains_for(version:str):
 data=images[version][APP_START:APP_ENDS[version]]
 marker_positions={i for i,x in enumerate(data) if x==0xff}
 chains=[]
 for p in sorted(marker_positions):
  if p-9 in marker_positions: continue
  q=p; marks=1
  while q+9 in marker_positions:
   q+=9; marks+=1
  records=marks-1
  if records<12: continue
  start=p+1; end=p+1+records*9
  blob=data[start:end]
  pairs=[struct.unpack('<ff',blob[i:i+8]) for i in range(0,len(blob),9)]
  flat=[v for pair in pairs for v in pair]
  plausible=[v for v in flat if math.isfinite(v) and abs(v)<=100]
  nonzero=sum(abs(v)>1e-6 for v in plausible)
  if len(plausible)<len(flat)*0.95 or nonzero < len(flat)*0.25: continue
  chains.append({'version':version,'file_offset':APP_START+start,'records':records,'blob':blob,'pairs':pairs,'plausible_count':len(plausible),'value_count':len(flat)})
 return chains

chains={v:chains_for(v) for v in VERSIONS}
# Full-table exact matches; a match confirms byte identity, while differing file
# offsets are reported as a relocation-like shift, not interpreted as loader relocation.
results=[]
for source,items in chains.items():
 for c in items:
  matches=[]
  for target,im in images.items():
   if target==source: continue
   start=APP_START; end=APP_ENDS[target]
   p=im.find(c['blob'],start,end)
   hits=[]
   while p>=0 and p+len(c['blob'])<=end:
    hits.append(p); p=im.find(c['blob'],p+1,end)
   for hit in hits:
    matches.append({'version':target,'file_offset':hit,'delta_target_minus_source':hit-c['file_offset']})
  if matches:
   results.append({'source_version':source,'source_file_offset':c['file_offset'],'records':c['records'],'byte_length':len(c['blob']),'sha256':hashlib.sha256(c['blob']).hexdigest(),'float_value_count':c['value_count'],'finite_abs_le_100_count':c['plausible_count'],'first_pairs':[[float(f'{x:.9g}') for x in pair] for pair in c['pairs'][:6]],'exact_matches':matches})

report={
 'read_only':True,
 'inputs':{v:{'path':str(p.relative_to(ROOT)),'size':len(images[v]),'sha256':hashlib.sha256(images[v]).hexdigest(),'app_payload_range':[f'0x{APP_START:X}',f'0x{APP_ENDS[v]:X}']} for v,p in VERSIONS.items()},
 'method':'Within each bounded app payload, identify chains of 0xFF bytes at 9-byte intervals; parse the 8 bytes after each marker as two little-endian float32 values. Retain chains >=12 records with >=95% finite abs(value)<=100 and >=25% non-near-zero values. Search each full byte chain exactly in every other release app span.',
 'candidate_chain_counts_by_version':{v:len(chains[v]) for v in VERSIONS},
 'matched_full_chain_count':len(results),
 'matches':sorted(results,key=lambda x:(x['byte_length'],x['source_version']),reverse=True),
 'interpretation':'Exact matching chains demonstrate repeated structured numeric-looking byte regions across releases. They do not prove runtime float use, table semantics, or a specific relocation mechanism. Absence of a full-chain match does not imply the values are absent or transformed beyond recognition.',
}
OUT.write_text(json.dumps(report,indent=2)+'\n');print(OUT)
