#!/usr/bin/env python3
"""Classify the GT-1 application's ESC2 DSP program-load reachability.

Read-only static analysis. Requires Capstone (`python -m pip install capstone`)
and the hash-pinned official packages plus their decoded sections.

What it does, per version v105/v107/v108/v109:

1. hash-checks the decoded GT1Appli section;
2. reconstructs the startup copy map (file offset -> runtime address) from the
   tracked `bootstrap-handoff-evidence.json`, so relocations are modelled
   instead of assuming address = 0x60000000 + file offset everywhere;
3. finds every literal occurrence of the ten ESC2 DSP window addresses and
   every PC-relative load that references one;
4. groups those loads by enclosing function (nearest preceding Thumb prologue);
5. resolves incoming BL/branch edges into each enclosing function and into its
   callers, including targets of `movw`/`movt` address construction and aligned
   pointer literals;
6. reports the live command-register sites (`0x50000`/`0x70000` bank select,
   `0x40100000` write window) as the contrasting parameter path.

The output is `firmware/work/gt1-dsp-load-reachability.json`.

Scope and limits are stated in the JSON. This script does not prove absence of
every possible indirect dispatch: dispatch through the runtime-provided
`0x02003xxx` service table, RAM-resident tables, and any boot stage outside
GT1Appli remain outside it.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "firmware/work/gt1-dsp-load-reachability.json"
HANDOFF = ROOT / "firmware/work/bootstrap-handoff-evidence.json"
BASE = 0x60000000

IMAGES = {
    "v105": "firmware/extracted/v105/gt1_sys_v105/GT1ROM.BIN",
    "v107": "firmware/extracted/v107/gt1_sys_v107/GT1ROM.BIN",
    "v108": "firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN",
    "v109": "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN",
}
IMAGE_SHA = {
    "v105": "b1bde0410795230b4a89ee3dfbbd357700bba7020624c0ff832ae3d8539d8bb4",
    "v107": "6a3110cd42c4b129494a93bc88d4f218e2e0b9377868ca051018b28696d6c22f",
    "v108": "7219679a87e985316264544423c9940ccbcbadeb2df0b2f13711ae57194cb612",
    "v109": "412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf",
}
APP_SHA = {
    "v105": "8297887084af48b04189955bbd8bdb4e0e6ff6a0e0fbcac7f85a175792775e29",
    "v107": "304b88a2c628cf47bb5091ecbc6da4fab4924f88cdea8897b44e5f474b9fb001",
    "v108": "c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1",
    "v109": "2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29",
}
WINDOWS = (0x40100000, 0x40100600, 0x40140000, 0x40144000, 0x4014E000,
           0x40150000, 0x40160000, 0x40164000, 0x4016E000, 0x40170000)
PRAM = (0x40150000, 0x40170000)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def load_regions(version: str) -> list[tuple[int, int, int]]:
    """(file_start, file_end, runtime_base) for every non-empty startup copy."""
    manifest = json.loads(HANDOFF.read_text(encoding="utf-8"))
    for out in manifest["loader_to_selected_image"]["decoded_outputs"]:
        if out["version"] != version:
            continue
        ops = out["sections"]["application"]["copy_operations_from_startup_literals"]
        regions = []
        for op in ops:
            length = int(op["length"], 16)
            if length == 0:
                continue
            start = int(op["source_output_offset"], 16)
            regions.append((start, start + length, int(op["destination"], 16)))
        return sorted(regions)
    raise AssertionError(f"no copy map for {version}")


def make_runtime(regions):
    def runtime(off: int) -> int:
        for start, end, base in regions:
            if start <= off < end:
                return base + (off - start)
        return BASE + off
    return runtime


def prologue_back(d: bytes, addr: int, limit: int = 0x800) -> int:
    o = addr - BASE
    for back in range(0, limit, 2):
        p = o - back
        if p < 0:
            break
        hw = u16(d, p)
        if hw == 0xE92D or (hw & 0xFF00) == 0xB500:
            return BASE + p
    return addr


def next_prologue(d: bytes, addr: int, runtime, limit: int = 0x1000) -> int:
    o = addr - BASE
    for fwd in range(2, limit, 2):
        p = o + fwd
        if p + 2 > len(d):
            break
        if runtime(p) != addr + fwd:
            continue
        hw = u16(d, p)
        if hw == 0xE92D or (hw & 0xFF00) == 0xB500:
            return BASE + p
    return addr + limit


def literal_loads(d: bytes) -> dict[int, list[int]]:
    """resolved literal address -> list of LDR sites"""
    out: dict[int, list[int]] = {}
    for o in range(0, len(d) - 4, 2):
        hw1 = u16(d, o)
        target = None
        if (hw1 & 0xF800) == 0x4800:                      # LDR  Rt,[pc,#imm8*4]
            target = ((BASE + o + 4) & ~3) + (hw1 & 0xFF) * 4
        elif hw1 == 0xF8DF and (u16(d, o + 2) & 0xF000) == 0xF000:   # LDR.W
            target = ((BASE + o + 4) & ~3) + (u16(d, o + 2) & 0xFFF)
        if target is not None:
            out.setdefault(target, []).append(BASE + o)
    return out


def control_flow(d: bytes, runtime) -> list[tuple[int, str, int]]:
    """(site, mnemonic, target) for BL and all direct branches."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    edges = []
    for o in range(0, len(d) - 4, 2):
        hw1 = u16(d, o)
        if (hw1 & 0xF800) != 0xF000 and (hw1 & 0xF000) != 0xD000:
            continue
        site = runtime(o)
        for ins in md.disasm(d[o:o + 4], site):
            m, ops = ins.mnemonic, ins.operands
            if ops and ops[0].type == 2 and (m.startswith("b") or m in ("cbz", "cbnz")):
                edges.append((site, m, ops[0].imm))
            break
    return edges


def analyse(version: str) -> dict:
    image = (ROOT / IMAGES[version]).read_bytes()
    assert sha256(image) == IMAGE_SHA[version], (version, "image hash")
    app = (ROOT / f"firmware/work/decoded/{version}-GT1Appli.bin").read_bytes()
    assert sha256(app) == APP_SHA[version], (version, "app hash")

    regions = load_regions(version)
    runtime = make_runtime(regions)

    # 1. literal occurrences of DSP window addresses
    literal_offsets: dict[int, list[int]] = {}
    for o in range(0, len(app) - 4, 4):
        value = u32(app, o)
        if value in WINDOWS:
            literal_offsets.setdefault(value, []).append(o)

    loads = literal_loads(app)
    edges = control_flow(app, runtime)

    # 2. literal-load sites referencing those literals, grouped by function
    functions: dict[int, dict] = {}
    for value in WINDOWS:
        for off in literal_offsets.get(value, []):
            for site in loads.get(BASE + off, []):
                fn = prologue_back(app, site)
                entry = functions.setdefault(fn, {"windows": set(), "load_sites": []})
                entry["windows"].add(value)
                entry["load_sites"].append(site)
            # a literal may also be consumed by the linker-stripped table only;
            # record occurrences even when no LDR references them
            functions.setdefault(0, {"windows": set(), "load_sites": []})

    # 3. incoming edges per function, and per caller (one level of unwind)
    def edges_into(fn: int, end: int):
        """Edges whose target lies in [fn, end). Intra-function edges are kept
        separate because a loop back-edge is not a call."""
        return [(s, m, t) for (s, m, t) in edges
                if fn <= t < end and s != t]

    def external_edges_into(fn: int, end: int):
        return [(s, m, t) for (s, m, t) in edges_into(fn, end)
                if not (fn <= s < end)]

    report_functions = []
    for fn in sorted(f for f in functions if f):
        end = next_prologue(app, fn, runtime)
        entry = functions[fn]
        incoming = external_edges_into(fn, end)
        callers = []
        for site, mnemonic, _ in incoming[:40]:
            caller = prologue_back(app, site)
            caller_end = next_prologue(app, caller, runtime)
            callers.append({
                "call_site": hex(site),
                "mnemonic": mnemonic,
                "enclosing_function": hex(caller),
                "caller_external_incoming_edges": len(external_edges_into(caller, caller_end)),
            })
        report_functions.append({
            "entry": hex(fn),
            "end_exclusive_estimate": hex(end),
            "dsp_windows_referenced": [hex(w) for w in sorted(entry["windows"])],
            "load_sites": [hex(s) for s in sorted(entry["load_sites"])],
            "intra_function_edges_into_range": len(edges_into(fn, end)) - len(incoming),
            "external_incoming_edges": len(incoming),
            "callers_truncated_to": 40,
            "callers": callers,
            "touches_pram": bool(entry["windows"] & set(PRAM)),
        })

    # 4. target of movw/movt construction for each function entry
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    movw_imms: dict[int, list[int]] = {}
    movt_imms: dict[int, list[int]] = {}
    bank_sites = []
    for ins in md.disasm(app, BASE):
        if ins.id == 0 or not ins.operands:
            continue
        if ins.mnemonic == "movw" and ins.operands[1].type == 2:
            movw_imms.setdefault(ins.operands[1].imm, []).append(ins.address)
        elif ins.mnemonic == "movt" and ins.operands[1].type == 2:
            movt_imms.setdefault(ins.operands[1].imm, []).append(ins.address)
        else:
            for op in ins.operands:
                if op.type == 2 and op.imm in (0x50000, 0x70000):
                    bank_sites.append((ins.address, ins.mnemonic, ins.op_str))
                    break

    for row in report_functions:
        fn = int(row["entry"], 16)
        lo, hi = fn & 0xFFFF, (fn >> 16) & 0xFFFF
        row["movw_movt_construction"] = {
            "movw_imm16": hex(lo),
            "movt_imm16": hex(hi),
            "movw_sites": [hex(a) for a in movw_imms.get(lo, [])[:8]],
            "movt_sites": [hex(a) for a in movt_imms.get(hi, [])[:8]],
        }
        row["aligned_pointer_literals"] = [
            hex(o) for o in range(0, len(app) - 4, 4) if u32(app, o) in (fn, fn | 1)
        ][:8]

    # 5. reachability verdict for the PRAM block-transfer function
    pram_rows = [r for r in report_functions if r["touches_pram"]]
    verdict = "pram_load_path_referenced"
    if pram_rows and all(r["external_incoming_edges"] == 0 for r in pram_rows):
        verdict = "pram_load_path_unreferenced"
    elif pram_rows and all(
        r["external_incoming_edges"]
        and all(c["caller_external_incoming_edges"] == 0 for c in r["callers"])
        for r in pram_rows
    ):
        verdict = "pram_load_path_reachable_only_from_entryless_functions"

    return {
        "version": version,
        "image": IMAGES[version],
        "image_sha256": IMAGE_SHA[version],
        "decoded_app": f"firmware/work/decoded/{version}-GT1Appli.bin",
        "decoded_app_sha256": APP_SHA[version],
        "startup_copy_regions": [
            {"file_start": hex(a), "file_end": hex(b), "runtime_base": hex(c)}
            for a, b, c in regions
        ],
        "dsp_window_literal_occurrences": {
            hex(k): [hex(o) for o in v] for k, v in sorted(literal_offsets.items())
        },
        "functions_referencing_dsp_windows": report_functions,
        "command_register_bank_sites": [
            {"address": hex(a), "mnemonic": m, "operands": o} for a, m, o in bank_sites
        ],
        "verdict": verdict,
    }


def main() -> None:
    results = [analyse(v) for v in IMAGES]
    out = {
        "read_only": True,
        "method": (
            "hash-pinned decode; startup copy map from bootstrap-handoff-evidence.json; "
            "literal and PC-relative-load resolution; BL/branch/pointer/movw+movt "
            "entry scan into the functions that reference ESC2 DSP windows"
        ),
        "limits": [
            "Indirect dispatch through the runtime-provided 0x02003xxx service table is not resolved.",
            "RAM-resident or table-generated function pointers outside the image are not visible.",
            "Any boot stage outside GT1Appli (mask ROM, first-stage loader) is outside this input.",
            "Function boundaries are estimated from Thumb prologues, not from a full call-graph analysis.",
            "Absence of a static reference is evidence of dead code in this image only, not a proof of "
            "unreachability at runtime by every conceivable mechanism.",
        ],
        "versions": results,
    }
    OUT.write_text(json.dumps(out, indent=2) + "\n")

    for r in results:
        pram = [f for f in r["functions_referencing_dsp_windows"] if f["touches_pram"]]
        print(f"{r['version']}: {r['verdict']}")
        for f in pram:
            print(f"   PRAM function {f['entry']}..{f['end_exclusive_estimate']}  "
                  f"external_incoming={f['external_incoming_edges']}  "
                  f"windows={f['dsp_windows_referenced']}")
            for c in f["callers"]:
                print(f"     caller {c['call_site']} in {c['enclosing_function']}  "
                      f"caller_external_incoming={c['caller_external_incoming_edges']}")
    print(f"\nwrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
