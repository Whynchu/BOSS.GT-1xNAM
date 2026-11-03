#!/usr/bin/env python3
"""Compare bounded ESC90/ESC91 Thumb bootstrap sequences (read-only)."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_LITTLE_ENDIAN,CS_MODE_MCLASS,CS_MODE_THUMB
ROOT=Path(__file__).resolve().parents[3]
SOURCES={
 'FA ESC90 v2.01':(ROOT/'firmware/work/reference/esc2-comparators/fa08_v201/extracted/_tmp/fantom_e_up.bin',0x2F4,0xA18),
 'FA ESC90 v2.02':(ROOT/'firmware/work/reference/esc2-comparators/fa08_v202/extracted/_tmp/fantom_e_up.bin',0x2F4,0xA18),
 'FA ESC90 v2.03':(ROOT/'firmware/work/reference/esc2-comparators/fa08_v203/extracted/_tmp/fantom_e_up.bin',0x2F4,0xA18),
 'GT-1 ESC91 v1.09':(ROOT/'firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN',0x2F0,0xBE0),
}
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
def sha(b):return hashlib.sha256(b).hexdigest()
def decode(data,off,n):
 return [{'runtime_address':f'0x{i.address:08X}','file_offset':f'0x{off+i.address-(0x00FFFFD0+off):06X}','bytes':i.bytes.hex(' '),'mnemonic':i.mnemonic,'operands':i.op_str} for i in md.disasm(data[off:off+n],0x00FFFFD0+off)]
records={}; bytesets={}
for label,(path,entry,loop) in SOURCES.items():
 b=path.read_bytes(); entry_bytes=b[entry:entry+12]; loop_bytes=b[loop:loop+24]; bytesets[label]=(entry_bytes,loop_bytes)
 records[label]={'path':str(path.relative_to(ROOT)),'image_size':len(b),'image_sha256':sha(b),'candidate_runtime_mapping':'0x00FFFFD0 + file_offset','entry_file_offset':f'0x{entry:06X}','entry_window_hex':entry_bytes.hex(' '),'entry_instructions':decode(b,entry,12),'table_loop_file_offset':f'0x{loop:06X}','table_loop_window_size':24,'table_loop_window_hex':loop_bytes.hex(' '),'table_loop_sha256':sha(loop_bytes),'table_loop_instructions':decode(b,loop,24)}
reference=bytesets['GT-1 ESC91 v1.09']
comparisons={}
for label,(entry_bytes,loop_bytes) in bytesets.items():
 comparisons[label]={'entry_first_4_bytes_match_gt1':entry_bytes[:4]==reference[0][:4],'entry_branch_and_literal_bytes_equal_gt1':entry_bytes[4:]==reference[0][4:],'init_loop_24_bytes_equal_gt1':loop_bytes==reference[1],'init_loop_common_sha256':sha(loop_bytes) if loop_bytes==reference[1] else None}
report={'read_only':True,'scope':'Bounded bootstrap code candidates only; does not classify the later FA/GT-1 application payloads.','interpretation':'The ARM Thumb decoder finds the same startup instruction shape in ESC90 and ESC91. The 24-byte init-table loop at FA file 0xA18 is byte-identical to GT-1 file 0xBE0 across all three FA releases. FA Ghidra headless output independently decodes the ESC90 entry and loop in ARM:LE:32:Cortex with Thumb context. This is strong evidence that these bounded bootstrap regions contain ARM Thumb code, but not proof that the MB8AA4181 application core runs ARM, that the rest of the section uses this ISA, or that the candidate mapping is the complete runtime map.','images':records,'cross_image_comparisons':comparisons,'ghidra_cross_check':{'program':'FA ESC90 bootstrap first 8 KiB','language':'ARM:LE:32:Cortex','context':'TMode=1','script':'tools/ghidra_scripts/FAESC90ThumbBlock.java','runner':'firmware/work/scripts/run_ghidra_fa_esc90.sh','output_path':'firmware/work/ghidra-fa-esc90-thumb-analysis.txt'}}
out=ROOT/'firmware/work/esc90-esc91-bootstrap-evidence.json';out.write_text(json.dumps(report,indent=2)+'\n');print(out)
