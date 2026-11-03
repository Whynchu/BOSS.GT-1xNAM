#!/usr/bin/env python3
"""Reproduce FA-06/07/08 ESC2 member header and version comparisons."""
from __future__ import annotations
import bz2,gzip,hashlib,json,lzma,tarfile,io,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
VERSIONS=('201','202','203')
GT1=ROOT/'firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN'
def sha(b): return hashlib.sha256(b).hexdigest()
def common_prefix(a,b):
 n=0
 for x,y in zip(a,b):
  if x!=y:break
  n+=1
 return n
results={}; blobs={}
for ver in VERSIONS:
 base=ROOT/f'firmware/work/reference/esc2-comparators/fa08_v{ver}'
 archive=base/f'fa060708_sys_v{ver}.zip'
 tarpath=base/f'extracted/fa060708_sys_v{ver}/FA_UPA.BIN'
 member=base/'extracted/_tmp/fantom_e_up.bin'
 ab=archive.read_bytes(); tb=tarpath.read_bytes(); b=member.read_bytes(); blobs[ver]=b
 with tarfile.open(fileobj=io.BytesIO(tb),mode='r:') as t:
  tar_members=[{'name':m.name,'size':m.size,'sha256':sha(t.extractfile(m).read())} for m in t.getmembers() if m.isfile()]
 header=0x2000; length=int.from_bytes(b[header+0x34:header+0x38],'little'); checksum=int.from_bytes(b[header+0x38:header+0x3c],'little'); start=header+0x44; end=start+length
 payload=b[start:end]
 results[ver]={'package':{'path':str(archive.relative_to(ROOT)),'size':len(ab),'sha256':sha(ab)},'tar':{'path':str(tarpath.relative_to(ROOT)),'size':len(tb),'sha256':sha(tb)},'members':tar_members,'esc2_member':{'path':str(member.relative_to(ROOT)),'size':len(b),'sha256':sha(b),'header_offset':'0x002000','header_marker':b[header+4:header+17].decode('ascii','replace'),'build_text':b[header+17:header+0x30].split(b'\0')[0].decode('ascii','replace'),'field_0x30_le':f'0x{int.from_bytes(b[header+0x30:header+0x34],"little"):08X}','payload_length_offset':'0x002034','payload_length':length,'checksum_offset':'0x002038','checksum_field':f'0x{checksum:08X}','payload_start':f'0x{start:06X}','payload_end_exclusive':f'0x{end:06X}','payload_sha256':sha(payload),'payload_byte_sum_mod32':f'0x{sum(payload)&0xffffffff:08X}','checksum_matches_additive_sum':checksum==(sum(payload)&0xffffffff),'field_0x3c_le':f'0x{int.from_bytes(b[header+0x3c:header+0x40],"little"):08X}','expanded_length_candidate_offset':'0x002040','expanded_length_candidate':f'0x{int.from_bytes(b[header+0x40:header+0x44],"little"):08X}','trailing_bytes_after_declared_payload':len(b)-end,'trailing_bytes_hex':b[end:].hex(' '),'trailing_version_marker_offset':f'0x{b.find(b"Roland MI073ESC2VER."):06X}' if b.find(b'Roland MI073ESC2VER.')>=0 else None,'trailing_version_marker':b[b.find(b'Roland MI073ESC2VER.'):].split(b'\0')[0].decode('ascii','replace') if b.find(b'Roland MI073ESC2VER.')>=0 else None,'codec_attempts':{}}}
 codecs=[('zlib',zlib.decompress),('gzip',gzip.decompress),('bzip2',bz2.decompress),('lzma_auto',lzma.decompress),('raw_deflate',lambda d:zlib.decompress(d,-15))]
 try:
  import lz4.frame
  codecs.append(('lz4_frame',lz4.frame.decompress))
 except ImportError: pass
 try:
  import zstandard
  codecs.append(('zstd_frame',lambda d:zstandard.ZstdDecompressor().decompress(d)))
 except ImportError: pass
 for name,fn in codecs:
  try:
   out=fn(payload); result={'valid':True,'output_size':len(out),'matches_expanded_candidate':len(out)==int(results[ver]['esc2_member']['expanded_length_candidate'],16)}
  except Exception as e:result={'valid':False,'error':str(e)[:120]}
  results[ver]['esc2_member']['codec_attempts'][name]=result
# Exact difference ranges for versioned ESC2 files.
diffs={}
for a,b in [('201','202'),('202','203'),('201','203')]:
 left,right=blobs[a],blobs[b]; offsets=[i for i,(x,y) in enumerate(zip(left,right)) if x!=y]; groups=[]
 for o in offsets:
  if not groups or o>groups[-1][-1]+1:groups.append([o])
  else:groups[-1].append(o)
 diffs[f'{a}_to_{b}']={'changed_byte_count':len(offsets),'ranges':[{'start':f'0x{g[0]:06X}','end_exclusive':f'0x{g[-1]+1:06X}','bytes':len(g),'from_hex':left[g[0]:g[-1]+1].hex(' '),'to_hex':right[g[0]:g[-1]+1].hex(' ')} for g in groups]}
# Compare the shared FA sequence across versions with GT-1 updater/application.
gt=GT1.read_bytes(); prefix={}
for v,b in blobs.items():
 for label,off in [('GT1Upd payload',0x2040),('GT1Appli payload',0x40040)]:
  n=common_prefix(b[0x2044:],gt[off:])
  prefix[f'FA_v{v}_vs_{label}']={'fa_offset':'0x002044','gt1_offset':f'0x{off:06X}','common_prefix_bytes':n,'fa_prefix_sha256':sha(b[0x2044:0x2044+n]),'gt1_prefix_sha256':sha(gt[off:off+n]),'equal':b[0x2044:0x2044+n]==gt[off:off+n]}
# Across FA releases, find common prefix and shared prefix against GT-1.
fa_version_prefix={}
for a,b in [('201','202'),('202','203'),('201','203')]:
 n=common_prefix(blobs[a],blobs[b]);pa=blobs[a][0x2044:0x2044+int.from_bytes(blobs[a][0x2034:0x2038],'little')];pb=blobs[b][0x2044:0x2044+int.from_bytes(blobs[b][0x2034:0x2038],'little')];pn=common_prefix(pa,pb);payload_changed=sum(x!=y for x,y in zip(pa,pb))
 fa_version_prefix[f'{a}_vs_{b}']={'whole_member_common_prefix_bytes':n,'whole_member_first_difference_offset':f'0x{n:06X}' if n<min(len(blobs[a]),len(blobs[b])) else None,'whole_member_prefix_sha256':sha(blobs[a][:n]),'payload_start_offset':'0x002044','payload_common_prefix_bytes':pn,'payload_first_difference_offset':f'0x{0x2044+pn:06X}' if pn<min(len(pa),len(pb)) else None,'payload_changed_byte_count':payload_changed,'payload_prefix_sha256':sha(pa[:pn])}
report={'read_only':True,'interpretation':'The FA ESC2 member has a 0x44-byte pre-payload header. Field at header+0x34 is a stored payload length and field at +0x38 equals the additive byte sum of that payload in all three versions. +0x40 is an expanded-length candidate; tested standard codecs do not validate it. The header layout is similar in function, but not byte-offset-identical, to the GT-1 container. Cross-product identical bytes do not identify executable status or ISA.','versions':results,'version_differences':diffs,'fa_version_common_prefixes':fa_version_prefix,'gt1_prefix_comparisons':prefix}
out=ROOT/'firmware/work/fa08-esc2-version-evidence.json';out.write_text(json.dumps(report,indent=2)+'\n');print(out)
