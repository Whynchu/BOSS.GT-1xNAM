#!/usr/bin/env python3
"""Reproduce read-only FA-08 v2.03 ESC2 image comparisons with GT-1 v1.09."""
from __future__ import annotations
import hashlib, json, tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
ARCHIVE=ROOT/'firmware/work/reference/esc2-comparators/fa08_v203/fa060708_sys_v203.zip'
TAR=ROOT/'firmware/work/reference/esc2-comparators/fa08_v203/extracted/fa060708_sys_v203/FA_UPA.BIN'
MEMBER_DIR=ROOT/'firmware/work/reference/esc2-comparators/fa08_v203/extracted/_tmp'
GT1=ROOT/'firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN'

def sha(b): return hashlib.sha256(b).hexdigest()
def common_prefix(a,b):
 n=0
 for x,y in zip(a,b):
  if x!=y: break
  n+=1
 return n
archive=ARCHIVE.read_bytes(); fa_tar=TAR.read_bytes(); gt1=GT1.read_bytes()
fa=MEMBER_DIR/'fantom_e_up.bin'; fb=fa.read_bytes()
sections={}
for label,fa_off,gt_off in [('GT1Upd payload',0x2044,0x2040),('GT1Appli payload',0x2044,0x40040)]:
 g=gt1[gt_off:]
 n=common_prefix(fb[fa_off:],g)
 sections[label]={'FA_file_offset':f'0x{fa_off:06X}','GT1_file_offset':f'0x{gt_off:06X}','common_prefix_bytes':n,'FA_bytes_sha256':sha(fb[fa_off:fa_off+n]),'GT1_bytes_sha256':sha(g[:n]),'equal':fb[fa_off:fa_off+n]==g[:n]}
# The first differing byte in the larger FA file and the exact shared run.
sections['cross_section_note']='GT-1 updater and application begin with identical stored payload bytes; the FA shared run is not evidence of executable status or decompression.'
strings={}
for key in [b'ESC90.000',b'ESC2 Firmware']:
 i=fb.find(key); strings[key.decode('ascii')]={'offset':f'0x{i:X}' if i>=0 else None,'bytes_before_20':fb[max(0,i-20):i].hex(' ') if i>=0 else None,'bytes_after_64':fb[i+len(key):i+len(key)+64].hex(' ') if i>=0 else None}
with tarfile.open(fileobj=__import__('io').BytesIO(fa_tar),mode='r:') as t:
 members=[{'name':m.name,'size':m.size,'sha256':sha(t.extractfile(m).read())} for m in t.getmembers() if m.isfile()]
report={'read_only':True,'sources':{'official_FA_package_archive':{'path':str(ARCHIVE.relative_to(ROOT)),'size':len(archive),'sha256':sha(archive)},'FA_UPA_tar':{'path':str(TAR.relative_to(ROOT)),'size':len(fa_tar),'sha256':sha(fa_tar)},'GT1_v109_image':{'path':str(GT1.relative_to(ROOT)),'size':len(gt1),'sha256':sha(gt1)}},'tar_members':members,'fa_esc2_member':{'path':str(fa.relative_to(ROOT)),'size':len(fb),'sha256':sha(fb),'marker_offsets':{'ESC90.000':hex(fb.find(b'ESC90.000')),'ESC2 Firmware':hex(fb.find(b'ESC2 Firmware'))},'string_evidence':strings},'comparisons':sections,'interpretation':'The FA ESC2 member contains a bounded byte-identical run with the GT-1 stored update sections immediately after the FA wrapper/header word. This is a static format/sequence correspondence only; transform, instruction set, code/data status, processor mapping and runtime address are unclassified.'}
out=ROOT/'firmware/work/fa08-gt1-esc2-comparison.json'; out.write_text(json.dumps(report,indent=2)+'\n'); print(out)
