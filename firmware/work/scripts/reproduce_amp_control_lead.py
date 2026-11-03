#!/usr/bin/env python3
"""Extract amp-control fields and chain ordering from preserved Fx FloorBoard files."""
from __future__ import annotations
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
base=ROOT/'firmware/work/reference/gt-1'
writer=(base/'sysxWriter.cpp').read_bytes().decode('utf-8',errors='replace')
bulk=(base/'bulkSaveDialog.cpp').read_bytes().decode('utf-8',errors='replace')
patch=json.loads((base/'default.tsl').read_text())['patchList'][0]['params']
files=['sysxWriter.cpp','bulkSaveDialog.cpp','default.tsl','midi.xml']
sha={name:hashlib.sha256((base/name).read_bytes()).hexdigest() for name in files}
def fields(prefix):
 return {k:v for k,v in sorted(patch.items()) if k.startswith(prefix)}
source_offsets={}
for block,src in [('preamp_a',writer),('preamp_b',writer)]:
 hits=[]
 for m in re.finditer(r'AppendTSL\(temp\.mid\((\d+),\s*1\),\s*"('+block+r'_[^"]+)"\)',src):
  hits.append({'patch_field':m.group(2),'template_byte_index_decimal':int(m.group(1)),'line':src.count('\n',0,m.start())+1})
 source_offsets[block]=hits
order_match=re.search(r'"chainParams"\s*:\s*\{([^}]+)\}',(base/'default.tsl').read_text())
chain=json.loads('{'+order_match.group(1)+'}') if order_match else {}
# capture statements showing assignment to GT100-derived template, distinguish from hardware SysEx addresses
conversion_lines=[]
for i,line in enumerate(writer.splitlines(),1):
 if 'GT100_default_replace' in line and ('amp' in line.lower() or 'preamp' in line.lower()):
  conversion_lines.append({'line':i,'text':line.strip()})
result={
 'classification':'community-editor source evidence; not independently validated against live hardware',
 'read_only':True,
 'source_file_sha256':sha,
 'preamp_fields_in_default_tsl':{'preamp_a':fields('preamp_a_'),'preamp_b':fields('preamp_b_')},
 'source_mapping':source_offsets,
 'effect_chain_example':chain,
 'conversion_template_assignments':conversion_lines,
 'limitations':['temp.mid() indices are patch-template byte positions, not proven GT-1 SysEx memory addresses.','The GT-1 editor contains a GT-100-derived template/conversion path; those indices must not be treated as confirmed GT-1 firmware or hardware addresses.','The editor patch schema does not reveal the runtime audio graph, scheduling, or amp-model implementation.']
}
out=ROOT/'firmware/work/amp-control-lead-evidence.json';out.write_text(json.dumps(result,indent=2)+'\n');print(out)
