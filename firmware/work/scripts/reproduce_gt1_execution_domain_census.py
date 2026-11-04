#!/usr/bin/env python3
"""Census the recovered GT-1 application execution domain.

Read-only static analysis over already reproduced, hash-pinned artifacts.

What this checks
----------------
1. The v1.08 decoded application and its startup-copied code segment match the
   recorded SHA-256 values.
2. A bounded strict-linear prefix and a narrow recursive Thumb disassembly
   seeded from startup entries and pinned callback targets are censused for
   VFP/NEON, Armv7E-M DSP, system, and divide instructions.
3. The decoded application is searched for exact CPACR/CPUID address literals.
   Literal absence does not prove that no code path enables CP10/CP11.
4. The decoded application carries a literal table of ESC2 DSP program/data
   windows (0x4014E000/0x40150000/0x40160000/0x40170000 and friends).
5. The upstream A2-Lite published rate is restated against the board's 48 MHz
   CKCPU reference as a *conditional* bound, not as an ESC2 measurement.

It does not measure ESC2, identify the internal DSP ISA, or prove that the DSP
executes the amp models. Those remain open and are labelled as such in the
JSON output.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_MCLASS, CS_MODE_THUMB, Cs
from capstone.arm import ARM_GRP_DPVFP, ARM_GRP_NEON, ARM_GRP_THUMB2DSP, ARM_GRP_VFP2, ARM_GRP_VFP3, ARM_GRP_VFP4, ARM_OP_IMM

ROOT = Path(__file__).resolve().parents[3]
DECODED = ROOT / "firmware/work/decoded/v108-GT1Appli.bin"
IMAGE = ROOT / "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN"
CALLBACK_MANIFEST = ROOT / "firmware/work/gt1-app-init-callbacks.json"
OUT = ROOT / "firmware/work/gt1-execution-domain-census.json"

EXPECTED_DECODED_SHA256 = "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1"
EXPECTED_IMAGE_SHA256 = "7219679a87e985316264544423c9940ccbcbadeb2df0b2f13711ae57194cb612"
EXPECTED_SEG0_SHA256 = "5691f04c08e52373973725ede20ff9de0bc3fc0e77a160e856a11342701168a0"
EXPECTED_CALLBACK_MANIFEST_SHA256 = "d80df86d0ae5355835a9395ec6d9a852b75d75c9fed9d7d9ec881f5358af5f1d"
SEG0_BASE = 0x01000300
SEG0_DEST, SEG0_LEN_OFF, SEG0_SRC_OFF = 0xE4, 0xE8, 0xEC

# Upstream A2-Lite facts (pinned by nam-source-evidence.json / README.md).
M7_CYCLES_PER_SAMPLE = 4059
NAM_RATE = 48_000
GT1_RATE = 44_100
A2LITE_WEIGHTS = 1871
CKCPU_MHZ = 48.0

DSP_MNEMONICS = {
    "smulbb", "smulbt", "smultb", "smultt",
    "smlabb", "smlabt", "smlatb", "smlatt",
    "smlalbb", "smlalbt", "smlaltb", "smlaltt",
    "smulwb", "smulwt", "smlawb", "smlawt", "smlalwb", "smlalwt",
    "smuad", "smuadx", "smusd", "smusdx", "smmul", "smmulr",
    "smmla", "smmlar", "smmls", "smmlsr", "umaal",
    "usad8", "usada8", "qadd", "qsub", "qdadd", "qdsub",
    "ssat", "usat", "ssat16", "usat16", "pkhbt", "pkhtb",
    "sxtb16", "uxtb16", "sxtab", "sxtah", "uxtab", "uxtah",
    "sel", "rbit", "clz",
    "sadd8", "sadd16", "ssub8", "ssub16", "sasx", "ssax",
    "uadd8", "uadd16", "usub8", "usub16", "uasx", "usax",
    "uhadd8", "uhadd16", "uhsub8", "uhsub16", "uhasx", "uhsax",
    "uqadd8", "uqadd16", "uqsub8", "uqsub16", "uqasx", "uqsax",
    "shadd8", "shadd16", "shsub8", "shsub16", "shasx", "shsax",
}
SYSTEM_MNEMONICS = {
    "mrs", "msr", "cpsid", "cpsie", "dmb", "dsb", "isb", "svc",
    "bkpt", "wfi", "wfe", "sev", "pld", "pldw", "ldrex", "strex", "clrex",
}

u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
sha256 = lambda b: hashlib.sha256(b).hexdigest()


def strict_linear_disasm(seg: bytes, base: int) -> list:
    """Linear decode that stops at the first undecodable byte.

    This deliberately does not resynchronise, so it cannot turn a literal pool
    into plausible-looking instructions. It therefore covers the contiguous
    reachable prologue region, not the whole segment.
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN | CS_MODE_MCLASS)
    md.detail = True
    return list(md.disasm(seg, base))


def recursive_disasm(seg: bytes, base: int, seeds: list[int]) -> list:
    """Follow direct calls and unconditional branches from fixed seeds.

    Conditional branch edges and indirect calls/branches are not resolved, so
    this is a narrow corroborating walk, not a complete reachability scan.
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN | CS_MODE_MCLASS)
    md.detail = True
    visited: set[int] = set()
    work = list(seeds)
    out = []
    end = base + len(seg)
    while work:
        addr = work.pop() & ~1
        pc = addr
        steps = 0
        while base <= pc < end and pc not in visited and steps < 8000:
            off = pc - base
            ins = next(md.disasm(seg[off:off + 4], pc), None)
            if ins is None:
                break
            visited.add(pc)
            out.append(ins)
            steps += 1
            m = ins.mnemonic
            if m in ("bl", "blx"):
                for op in ins.operands:
                    if op.type == ARM_OP_IMM:
                        tgt = op.imm & ~1
                        if base <= tgt < end:
                            work.append(tgt)
            if m in ("b", "b.w") and len(ins.operands) == 1 and ins.operands[0].type == ARM_OP_IMM:
                tgt = ins.operands[0].imm & ~1
                if base <= tgt < end:
                    work.append(tgt)
                break
            if "pc" in ins.op_str and m in ("bx", "pop", "pop.w", "ldm", "ldm.w", "ldmia", "ldmia.w"):
                break
            if m in ("udf", "bkpt", "svc"):
                break
            pc += len(ins.bytes)
    out.sort(key=lambda i: i.address)
    return out


decoded = DECODED.read_bytes()
image = IMAGE.read_bytes()
assert sha256(decoded) == EXPECTED_DECODED_SHA256, sha256(decoded)
assert EXPECTED_IMAGE_SHA256 and sha256(image) == EXPECTED_IMAGE_SHA256, sha256(image)

assert u32(decoded, SEG0_DEST) == SEG0_BASE
seg0_len = u32(decoded, SEG0_LEN_OFF)
seg0_src = u32(decoded, SEG0_SRC_OFF) - 0x60000000
seg0 = decoded[seg0_src:seg0_src + seg0_len]
assert sha256(seg0) == EXPECTED_SEG0_SHA256, sha256(seg0)

callback_manifest_bytes = CALLBACK_MANIFEST.read_bytes()
assert sha256(callback_manifest_bytes) == EXPECTED_CALLBACK_MANIFEST_SHA256, sha256(callback_manifest_bytes)
callback_manifest = json.loads(callback_manifest_bytes)
callback_seeds = [
    int(row["thumb_entry"], 16)
    for row in callback_manifest["versions"]["v108"]["callbacks"]
]
seeds = [SEG0_BASE, 0x010010AE, 0x0100465C, *callback_seeds]
linear = strict_linear_disasm(seg0, SEG0_BASE)
recursive = recursive_disasm(seg0, SEG0_BASE, seeds)
instructions = linear  # the contiguous bounded census is the primary count


def census(rows):
    fpu_groups = (ARM_GRP_DPVFP, ARM_GRP_VFP2, ARM_GRP_VFP3, ARM_GRP_VFP4, ARM_GRP_NEON)
    is_fpu = lambda ins: any(ins.group(group) for group in fpu_groups)
    is_dsp = lambda ins: ins.group(ARM_GRP_THUMB2DSP) or ins.mnemonic in DSP_MNEMONICS
    mnemonics = {}
    for ins in rows:
        mnemonics[ins.mnemonic] = mnemonics.get(ins.mnemonic, 0) + 1
    return {
        "instructions": len(rows),
        "byte_coverage": sum(len(i.bytes) for i in rows),
        "coverage_percent": sum(len(i.bytes) for i in rows) / len(seg0) * 100,
        "vfp_neon_count": sum(1 for i in rows if is_fpu(i)),
        "vfp_neon_examples": [(hex(i.address), i.mnemonic, i.op_str) for i in rows if is_fpu(i)][:10],
        "armv7e_m_dsp_count": sum(1 for i in rows if is_dsp(i)),
        "armv7e_m_dsp_examples": [(hex(i.address), i.mnemonic, i.op_str) for i in rows if is_dsp(i)][:10],
        "system_instruction_count": sum(1 for i in rows if i.mnemonic in SYSTEM_MNEMONICS),
        "system_instruction_examples": [(hex(i.address), i.mnemonic, i.op_str) for i in rows if i.mnemonic in SYSTEM_MNEMONICS][:10],
        "hardware_divide_count": sum(1 for i in rows if i.mnemonic in ("udiv", "sdiv")),
        "hardware_divide_examples": [(hex(i.address), i.mnemonic, i.op_str) for i in rows if i.mnemonic in ("udiv", "sdiv")][:10],
        "top_mnemonics": sorted(mnemonics.items(), key=lambda kv: -kv[1])[:20],
    }


linear_census = census(linear)
recursive_census = census(recursive)

# Exact literal search only; computed or helper-mediated MMIO accesses are not
# detected by this byte-string scan.
absent_literals = {}
for name, value in (("CPACR", 0xE000ED88), ("CPUID", 0xE000ED00)):
    pat = struct.pack("<I", value)
    hits, start = [], 0
    while True:
        idx = decoded.find(pat, start)
        if idx < 0:
            break
        hits.append(idx)
        start = idx + 1
    absent_literals[name] = [hex(h) for h in hits]

# NAM-specific signatures. A native NAM path would need at least a .namb
# container parser or a generated WaveNet/conv1d kernel; absence is a bounded
# negative for the recovered image, not a whole-universe proof.
nam_signatures = {}
for label, needle in {
    "BMAN (.namb magic)": b"BMAN",
    ".namb extension": b".namb",
    "WaveNet": b"WaveNet",
    "wavenet": b"wavenet",
    "conv1d": b"conv1d",
    "Neural": b"Neural",
    "neural": b"neural",
    "TONE3000": b"TONE3000",
    "tone3000": b"tone3000",
}.items():
    hits, start = [], 0
    while True:
        idx = decoded.find(needle, start)
        if idx < 0:
            break
        hits.append(idx)
        start = idx + 1
    nam_signatures[label] = [hex(h) for h in hits]

# ESC2 DSP window table recovered from the version-specific literal pool.
# These are observed constants, not proven physical-memory semantics.
dsp_pool_off = {"v108": 0x47DB0, "v109": 0x467B0}["v108"]
dsp_pool = [u32(decoded, dsp_pool_off + 4 * i) for i in range(12)]
dsp_windows = [f"0x{v:08X}" for v in dsp_pool if 0x40000000 <= v < 0x50000000]

m7_cycles_per_second = M7_CYCLES_PER_SAMPLE * NAM_RATE
cpu_cycles_per_sample_at_48k = CKCPU_MHZ * 1_000_000 / NAM_RATE
compute_bound = {
    "classification": "conditional arithmetic from the published M7 benchmark and the board's 48 MHz CKCPU reference; not an ESC2 measurement",
    "published_M7_cycles_per_sample": M7_CYCLES_PER_SAMPLE,
    "published_M7_core_MHz": 480,
    "published_M7_core_load_percent": M7_CYCLES_PER_SAMPLE * NAM_RATE / 480_000_000 * 100,
    "nam_cycles_per_second_at_48k": m7_cycles_per_second,
    "minimum_MHz_at_100_percent_M7_efficiency": m7_cycles_per_second / 1_000_000,
    "minimum_MHz_at_50_percent_M7_efficiency": m7_cycles_per_second / 500_000,
    "gt1_ckcpu_reference_MHz": CKCPU_MHZ,
    "gt1_cycles_per_sample_at_48k": cpu_cycles_per_sample_at_48k,
    "over_budget_factor_at_100_percent_M7_efficiency": m7_cycles_per_second / (CKCPU_MHZ * 1_000_000),
    "a2lite_weight_macs_per_sample_lower_bound": A2LITE_WEIGHTS,
    "single_mac_per_cycle_minimum_MHz_at_48k": A2LITE_WEIGHTS * NAM_RATE / 1_000_000,
    "single_mac_per_cycle_utilization_at_48MHz": A2LITE_WEIGHTS * NAM_RATE / (CKCPU_MHZ * 1_000_000),
    "note": "The 48 MHz CKCPU label is a board clock reference, not a verified post-PLL core clock. The MAC bound is a lower bound on the WaveNet weight work and ignores activations, head, resampling, and the rest of the effect chain.",
}

report = {
    "read_only": True,
    "inputs": {
        "decoded": {"path": str(DECODED.relative_to(ROOT)), "size": len(decoded), "sha256": sha256(decoded)},
        "image": {"path": str(IMAGE.relative_to(ROOT)), "size": len(image), "sha256": sha256(image)},
        "callback_manifest": {"path": str(CALLBACK_MANIFEST.relative_to(ROOT)), "sha256": sha256(callback_manifest_bytes)},
        "startup_copied_segment": {
            "destination": hex(SEG0_BASE),
            "source_output_offset": hex(seg0_src),
            "size": len(seg0),
            "sha256": sha256(seg0),
        },
    },
    "isa_census": {
        "segment_size": len(seg0),
        "strict_linear": {
            "method": "linear M-profile Thumb decode from segment start; stops at the first undecodable byte and deliberately does not resynchronise",
            "start_address": hex(SEG0_BASE),
            "end_exclusive": hex(SEG0_BASE + linear_census["byte_coverage"]),
            **linear_census,
        },
        "recursive": {
            "method": "narrow recursive M-profile Thumb walk from the v1.08 startup entries and hash-pinned callback targets; follows immediate BL/BLX calls and unconditional B only, not conditional edges or indirect calls/branches",
            "seeds": [hex(s) for s in seeds],
            **recursive_census,
        },
    },
    "whole_image_fpu_evidence": {
        "description": "exact byte-literal occurrences of the CPACR and CPUID addresses anywhere in the decoded v1.08 application",
        "literals": absent_literals,
        "interpretation": "No exact CPACR or CPUID address literal is present in the decoded application. This literal search does not exclude computed addresses, helper-mediated access, boot-stage configuration, or paths outside the instruction census.",
    },
    "esc2_dsp_windows": {
        "literal_pool_output_offset": hex(dsp_pool_off),
        "values": dsp_windows,
        "related_strings": [
            "CPrmESC2DT1 Error: PRG Set without DSP Halt!",
            "CPrmESC2DT1 Error: DRP Set without DSP Halt!",
            "NG (IRAM0)", "NG (PRAM0)", "NG (IRAM1)", "NG (PRAM1)",
        ],
        "interpretation": "The v1.08 application contains an address table and register-level transfer facility associated with ESC2 DSP program/data windows, plus IRAM/PRAM diagnostics. This supports a distinct DSP program/data control domain, but does not prove a separate CPU, physical memory map, amp-model ownership, or boot-time DSP load. Current traced callers are SysEx/control and diagnostic tests.",
    },
    "firmware_nam_signature_scan": {
        "description": "byte-string scan of the decoded v1.08 application for NAM-specific container or engine signatures",
        "hits": nam_signatures,
        "interpretation": "No NAM-specific byte-string signatures were found. This does not rule out a generic model interpreter, nor does it show that one exists.",
    },
    "compute_bound": compute_bound,
    "conclusions": {
        "recovered_cpu": "The inspected v1.08 application slices decode as Thumb/Thumb-2 integer code and include UDIV. No VFP/NEON or listed Armv7E-M DSP mnemonic was observed in the strict-linear prefix or narrow direct-edge walk. The prefix and direct-edge coverage are reported below; neither characterizes the full application or silicon.",
        "audio_domain": "The application exposes a distinct ESC2 DSP program/data control domain through IRAM/PRAM diagnostics and transfer controls. It is not established whether this is a separate core, whether it executes amp algorithms, or whether firmware loads it at boot.",
        "nam_fit": "This evidence does not establish native NAM fit or impossibility. The published optimized A2-Lite result is an M7 benchmark, not a GT-1 measurement; the board's 48 MHz CKCPU label is not a confirmed core clock. The DSP domain has no demonstrated compatible toolchain or amp-stage contract. No NAM-specific byte-string signature was found, which does not rule out a generic interpreter or a future port.",
        "practical_route": "Host-side NAM can run over the GT-1 USB audio path as an external post-effect stage; it is not a firmware-level amp-stage replacement and the return is mixed at the final stage.",
    },
    "limitations": [
        "The strict-linear scan stops at the first undecodable halfword; its coverage and the direct-edge coverage are reported below. The direct-edge walk omits conditional branch edges, indirect calls/branches, and computed tables.",
        "The strict-linear prefix contains BASEPRI/system instructions; a known SVC instruction occurs beyond its end. These findings do not characterize all system instructions in the segment.",
        "This census covers only a prefix and narrow walk in one v1.08 startup-copied segment; the in-place code region at 0x60000000 and other copied segments were not exhaustively censused.",
        "The in-place code region at 0x60000000 and other copied segments exist and were not exhaustively censused for FPU/DSP instructions.",
        "Absence of exact CPACR/CPUID byte literals does not prove the silicon has no FPU or that no earlier boot stage configures it.",
        "The 48 MHz CKCPU label is a board clock reference; the post-PLL core clock is not established.",
        "The DSP windows are observed constants and strings, not a proven physical memory map, ISA, or audio call path.",
        "No target benchmark was run; all cycle figures are upstream M7 references or arithmetic bounds.",
    ],
}

OUT.write_text(json.dumps(report, indent=2) + "\n")
print(f"wrote {OUT.relative_to(ROOT)}")
print(f"segment {len(seg0)} bytes")
print(f"strict linear: {linear_census['instructions']} instructions, "
      f"{linear_census['coverage_percent']:.1f}% byte coverage, "
      f"VFP/NEON {linear_census['vfp_neon_count']}, DSP {linear_census['armv7e_m_dsp_count']}, "
      f"system {linear_census['system_instruction_count']}, divide {linear_census['hardware_divide_count']}")
print(f"recursive:     {recursive_census['instructions']} instructions, "
      f"{recursive_census['coverage_percent']:.1f}% byte coverage, "
      f"VFP/NEON {recursive_census['vfp_neon_count']}, DSP {recursive_census['armv7e_m_dsp_count']}, "
      f"system {recursive_census['system_instruction_count']}, divide {recursive_census['hardware_divide_count']}")
print(f"CPACR literals: {absent_literals['CPACR']}  CPUID literals: {absent_literals['CPUID']}")
print(f"NAM signatures: {sum(len(v) for v in nam_signatures.values())} hit(s)")
print(f"ESC2 DSP windows: {dsp_windows}")
print(f"48 MHz, 48 kHz budget: {cpu_cycles_per_sample_at_48k:.1f} cycles/sample; "
      f"M7-equivalent work is {compute_bound['over_budget_factor_at_100_percent_M7_efficiency']:.2f}x the core; "
      f"1 MAC/cycle alone needs {compute_bound['single_mac_per_cycle_minimum_MHz_at_48k']:.1f} MHz")
