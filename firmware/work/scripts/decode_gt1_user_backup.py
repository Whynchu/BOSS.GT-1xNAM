#!/usr/bin/env python3
"""Validate and summarize a raw GT-1 bulk user-data SysEx backup.

This script does not write to the pedal and does not infer firmware or model code.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

HEADER=bytes.fromhex('41 00 00 00 00 30 12')
PATCH_BASE=0x10000000
PATCH_STRIDE=0x10000
PATCH_COUNT=99
PATCH_CHUNK_OFFSETS=[0]+[0x171+i*0x1F1 for i in range(8)]+[0x1079]
PATCH_PAYLOAD_LENGTHS=[241]*9+[33]


def frames(data: bytes):
    out=[]; i=0
    while i < len(data):
        try: start=data.index(0xF0, i); end=data.index(0xF7, start)+1
        except ValueError: break
        out.append(data[start:end]); i=end
    return out, data[i:]


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('input', type=Path)
    ap.add_argument('--json', type=Path, help='write machine-readable report')
    args=ap.parse_args()
    raw=args.input.read_bytes(); msgs, tail=frames(raw)
    report={'input':str(args.input),'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
      'message_count':len(msgs),'trailing_bytes':len(tail),'all_gt1_dt1':True,'all_checksums_valid':True,
      'system_message_count':0,'patch_message_count':0,'patch_slots':[],'messages':[],
      'patch_frame_layout_valid':True,'system_frame_addresses':[]}
    slots={}; seen_patch_addrs=set()
    for ix,m in enumerate(msgs):
        is_gt1=len(m)>=14 and m[1:8]==HEADER
        cs_ok=is_gt1 and ((sum(m[8:-2])+m[-2]) & 0x7f)==0
        addr=int.from_bytes(m[8:12],'big') if is_gt1 else None
        data_len=max(0,len(m)-14)
        is_patch=is_gt1 and PATCH_BASE <= addr < PATCH_BASE+PATCH_COUNT*PATCH_STRIDE
        name=''.join(chr(c) if 32<=c<127 else ' ' for c in m[12:28]).strip() if is_patch else ''
        report['all_gt1_dt1'] &= is_gt1
        report['all_checksums_valid'] &= cs_ok
        report['patch_message_count'] += bool(is_patch)
        if is_patch:
            delta=addr-PATCH_BASE; slot,within=divmod(delta,PATCH_STRIDE)
            expected_offsets=PATCH_CHUNK_OFFSETS
            expected_lengths=PATCH_PAYLOAD_LENGTHS
            if within not in expected_offsets or data_len != expected_lengths[expected_offsets.index(within)]:
                report['patch_frame_layout_valid']=False
            if addr in seen_patch_addrs: report['patch_frame_layout_valid']=False
            seen_patch_addrs.add(addr)
            slots.setdefault(slot, {'patch_number':slot+1,'name':name,'message_count':0,'first_address':addr,'last_address':addr,'chunk_addresses':[]})
            slots[slot]['message_count']+=1; slots[slot]['last_address']=addr
            slots[slot]['chunk_addresses'].append(addr)
            if name and not slots[slot]['name']: slots[slot]['name']=name
        elif is_gt1:
            report['system_frame_addresses'].append(f'0x{addr:08X}')
            report['system_message_count']+=1
        report['messages'].append({'index':ix,'length':len(m),'address':f'0x{addr:08X}' if addr is not None else None,'name_field':name,'checksum_valid':bool(cs_ok)})
    for slot in range(PATCH_COUNT):
        row=slots.get(slot)
        if row is None:
            report['patch_frame_layout_valid']=False
            continue
        actual=sorted(row['chunk_addresses'])
        expected=[PATCH_BASE+slot*PATCH_STRIDE+x for x in PATCH_CHUNK_OFFSETS]
        if actual != expected or row['message_count'] != 10:
            report['patch_frame_layout_valid']=False
        row['chunk_addresses']=[f'0x{x:08X}' for x in actual]
        row['first_address']=f'0x{actual[0]:08X}'
        row['last_address']=f'0x{actual[-1]:08X}'
    report['patch_slots']=list(slots.values())
    report['patch_slots_present']=len(slots)
    report['patch_slots_missing']=[n for n in range(1,PATCH_COUNT+1) if n-1 not in slots]
    print(json.dumps({k:v for k,v in report.items() if k!='messages'},indent=2))
    if args.json: args.json.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__': main()
