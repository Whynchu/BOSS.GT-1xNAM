#!/usr/bin/env python3
"""Reassemble 10-chunk patches from a documented GT-1 bulk backup."""
from pathlib import Path
import argparse,csv,json,hashlib

HEADER=bytes.fromhex('41 00 00 00 00 30 12')
PATCH_BASE=0x10000000
PATCH_STRIDE=0x10000
PATCH_COUNT=99
CHUNK_OFFSETS=[0]+[0x171+i*0x1F1 for i in range(8)]+[0x1079]
CHUNK_LENGTHS=[241]*9+[33]

def read_frames(data):
 out=[];i=0
 while i<len(data):
  try:s=data.index(0xF0,i);e=data.index(0xF7,s)+1
  except ValueError:break
  out.append(data[s:e]);i=e
 return out

def main():
 ap=argparse.ArgumentParser();ap.add_argument('capture',type=Path);ap.add_argument('outdir',type=Path);a=ap.parse_args();a.outdir.mkdir(parents=True,exist_ok=True)
 raw=a.capture.read_bytes(); frames=read_frames(raw); slots={}
 for m in frames:
  if len(m)<14 or m[1:8]!=HEADER or ((sum(m[8:-2])+m[-2])&127):continue
  addr=int.from_bytes(m[8:12],'big')
  if PATCH_BASE<=addr<PATCH_BASE+PATCH_COUNT*PATCH_STRIDE:
   n=(addr-PATCH_BASE)//PATCH_STRIDE+1;slots.setdefault(n,[]).append(m)
 rows=[]
 for n,ms in sorted(slots.items()):
  ms.sort(key=lambda x:int.from_bytes(x[8:12],'big'))
  if len(ms)!=10: raise SystemExit(f'U{n:02d}: expected 10 chunks, got {len(ms)}')
  expected=[PATCH_BASE+(n-1)*PATCH_STRIDE+x for x in CHUNK_OFFSETS]
  actual=[int.from_bytes(m[8:12],'big') for m in ms]
  lengths=[len(m)-14 for m in ms]
  if actual!=expected: raise SystemExit(f'U{n:02d}: unexpected chunk address sequence: {[hex(x) for x in actual]}')
  if lengths!=CHUNK_LENGTHS: raise SystemExit(f'U{n:02d}: unexpected payload lengths: {lengths}')
  # DT1 payload is bytes 12..checksum-1; skip frame header/checksum/footer.
  patch=b''.join(m[12:-2] for m in ms)
  dest=a.outdir/f'U{n:02d}.bin';dest.write_bytes(patch)
  name=''.join(chr(c) if 32<=c<127 else ' ' for c in patch[:16]).strip()
  rows.append({'patch':f'U{n:02d}','name':name,'chunks':len(ms),'assembled_bytes':len(patch),'sha256':hashlib.sha256(patch).hexdigest()})
 with (a.outdir/'patches.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
 (a.outdir/'patches.json').write_text(json.dumps(rows,indent=2)+'\n')
 expected_slots=set(range(1,PATCH_COUNT+1))
 if set(slots)!=expected_slots: raise SystemExit(f"expected slots U01-U99; got {len(slots)} slots")
 print(f"reassembled {len(rows)} patches to {a.outdir}; input sha256 {hashlib.sha256(raw).hexdigest()}")
if __name__=='__main__':main()
