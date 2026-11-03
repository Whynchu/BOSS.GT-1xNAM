#!/usr/bin/env python3
"""Record local provenance for the pinned TONE3000 embedded NAM source.

Read-only analysis of the checked-out v2.0.0 release; writes only the JSON
manifest under firmware/work. It does not compile or run the NAM engine.
"""
from __future__ import annotations
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REPO = ROOT / "firmware/work/reference/tone-3000-embedded"
FILES = [
    "README.md",
    "VERSION",
    "MANIFEST.json",
    "engines/cortex-m7/a2lite/nam_a2lite.c",
    "engines/cortex-m7/a2lite/nam_a2lite.h",
    "bench/cortex-m7/daisy_seed/Makefile",
    "bench/cortex-m7/daisy_seed/bench_main.cpp",
    "bench/cortex-m7/m7_bench.c",
    "bench/cortex-m7/Makefile",
    "bench/cortex-m7/host_m7_bench.c",
    "namb/namb_reader.c",
    "namb/namb_reader.h",
    "weights/a2lite.namb",
]

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(REPO), *args], text=True).strip()

def main() -> None:
    version = (REPO / "VERSION").read_text().strip()
    if version != "2.0.0":
        raise SystemExit(f"expected upstream VERSION 2.0.0, found {version!r}")
    doc = {
        "repository": "https://github.com/tone-3000/embedded",
        "tag": "v2.0.0",
        "version_file": version,
        "commit": git("rev-parse", "HEAD"),
        "tag_target_commit": git("rev-parse", "refs/tags/v2.0.0^{}"),
        "license": "MIT",
        "local_checkout": str(REPO.relative_to(ROOT)),
        "read_only": True,
        "note": "Upstream README benchmark/resource values are reported by upstream; this manifest pins source bytes but does not benchmark GT-1/ESC2.",
        "files": {},
    }
    if doc["commit"] != doc["tag_target_commit"]:
        raise SystemExit("checkout does not match peeled v2.0.0 tag target")
    for rel in FILES:
        p = REPO / rel
        doc["files"][rel] = {"size": p.stat().st_size, "sha256": sha256(p)}
    lite_c = (REPO / "engines/cortex-m7/a2lite/nam_a2lite.c").read_text()
    readme = (REPO / "README.md").read_text()
    board_make = (REPO / "bench/cortex-m7/daisy_seed/Makefile").read_text()
    host_make = (REPO / "bench/cortex-m7/Makefile").read_text()
    host_source = (REPO / "bench/cortex-m7/host_m7_bench.c").read_text()
    board_main = (REPO / "bench/cortex-m7/daisy_seed/bench_main.cpp").read_text()
    guard = "defined(__GNUC__) && defined(__ARM_ARCH_7EM__) && defined(__ARM_FEATURE_FMA) && defined(__thumb2__)"
    doc["a2lite_instruction_set_evidence"] = {
        "classification": "upstream source inspection; describes available implementations, not ESC2 compatibility or timing",
        "optimized_path": {
            "selection_condition": "GCC + __ARM_ARCH_7EM__ + __ARM_FEATURE_FMA + __thumb2__",
            "assembly_macro_default": "NAM_M7_ASM=1 when the above condition holds; otherwise 0",
            "instruction_set_notes": [
                "generated Thumb-2 tile kernels",
                "FPv5 Cortex-M7 target",
                "uses VMAXNM, which README says Cortex-M4F FPv4 lacks",
            ],
            "source_sha256": doc["files"]["engines/cortex-m7/a2lite/nam_a2lite.c"]["sha256"],
        },
        "fallback_path": {
            "selection": "C tiles are compiled when NAM_M7_ASM=0; README explicitly says use this for M4F or any target without FPv5",
            "same_output_claim": "README says the C tiles give the same output but run slower",
            "fused_multiply_add": "NAM_FMA uses __builtin_fmaf only when compiler macros indicate FMA; otherwise it expands to multiply plus add",
            "architecture_implication": "The source is not inherently limited to Thumb-2 if an appropriate C compiler/runtime and scalar floating-point implementation exist; target performance and numeric behavior require measurement/validation.",
            "source_sha256": doc["files"]["engines/cortex-m7/a2lite/nam_a2lite.c"]["sha256"],
            "readme_sha256": doc["files"]["README.md"]["sha256"],
        },
        "observed_source_conditions": {
            "NAM_M7_ASM_guard_present": guard in lite_c,
            "M7_kernel_VMAXNM_note_present": "VMAXNM" in lite_c,
            "C_fallback_guard_present": "#if !NAM_M7_ASM" in lite_c,
            "non_FMA_fallback_present": "#define NAM_FMA(a, b, c) ((a) * (b) + (c))" in lite_c,
            "README_non_FPv5_fallback_note_present": "for any core without FPv5" in readme,
            "README_same_output_fallback_note_present": "which give the same output but run slower" in readme,
        },
        "limitations": [
            "A C fallback does not establish that a vendor ESC2 compiler can build the code.",
            "A fallback compile would not establish real-time feasibility, memory placement, or equivalence under the GT-1 pipeline.",
            "The C-versus-assembly performance difference is not quantified for ESC2.",
        ],
    }
    doc["cortex_m7_benchmark_path"] = {
        "classification": "upstream source and documentation inspection; benchmark-path attribution is an inference because no board build log or compiled object is retained",
        "documented_measurement": {
            "board": "Electrosmith Daisy Seed / STM32H750 Cortex-M7 at 480 MHz",
            "compiler": "GCC 10.3",
            "optimization_flags_reported": "-O2 -ffast-math",
            "a2lite_block_48_result_cycles_per_sample": 4059,
            "source_sha256": doc["files"]["README.md"]["sha256"],
        },
        "default_board_build": {
            "block_frames": 48,
            "tuning_suffix": "empty; selects engines/cortex-m7/a2lite rather than a2lite-b16",
            "makefile_default_block_48_present": bool(re.search(r"(?m)^BLOCK\s+\?=\s*48\s*$", board_make)),
            "makefile_tunes_only_block_16_present": "filter 16,$(BLOCK)" in board_make,
            "does_not_define_NAM_M7_ASM_zero": "-DNAM_M7_ASM=0" not in board_make,
            "memory_placement": "engine code in ITCM; capture and instance in DTCM; state in AXI SRAM (per upstream README and Daisy benchmark source)",
            "board_makefile_sha256": doc["files"]["bench/cortex-m7/daisy_seed/Makefile"]["sha256"],
            "board_main_sha256": doc["files"]["bench/cortex-m7/daisy_seed/bench_main.cpp"]["sha256"],
        },
        "assembly_path_attribution": {
            "required_source_macros": guard,
            "engine_source_defaults_assembly_to_one_when_guard_holds": "#define NAM_M7_ASM 1" in lite_c,
            "readme_recommends_matching_M7_flags": all(x in readme for x in ["-mcpu=cortex-m7", "-mthumb", "-mfpu=fpv5-d16", "-mfloat-abi=hard", "-O2 -ffast-math"]),
            "interpretation": "Given the documented Cortex-M7 board and recommended ARMv7E-M/FMA/Thumb-2 flags, the 4059 cycles/sample result is strongly indicated to use the optimized Thumb-2/FPv5 assembly path. The exact preprocessor result is not independently confirmed without the original compile command, log, or object file.",
            "fallback_cycle_measurement_published": False,
            "fallback_cycle_measurement_note": "README says the C tiles produce the same output but run slower; it publishes no C-fallback cycle count.",
            "engine_source_sha256": doc["files"]["engines/cortex-m7/a2lite/nam_a2lite.c"]["sha256"],
        },
        "host_benchmark_scope": {
            "host_makefile_default_flags": "-O2",
            "host_makefile_has_ARM_target_flags": any(flag in host_make for flag in ["-mcpu=cortex-m7", "-mfpu=fpv5-d16"]),
            "host_source_says_timings_are_meaningless": "Cycle numbers are host nanoseconds and mean nothing here." in host_source,
            "interpretation": "The host build is for correctness/output checking, not the published M7 cycle figure; absent ARM target macros, its source defaults to C tiles.",
            "host_makefile_sha256": doc["files"]["bench/cortex-m7/Makefile"]["sha256"],
            "host_source_sha256": doc["files"]["bench/cortex-m7/host_m7_bench.c"]["sha256"],
            "daisy_main_identifies_STM32H750_M7": "STM32H750, Cortex-M7 @ 480 MHz" in board_main,
        },
    }
    out = ROOT / "firmware/work/nam-source-evidence.json"
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(out.relative_to(ROOT))
    print("version", version)
    print("commit", doc["commit"])
    print("files", len(doc["files"]))

if __name__ == "__main__":
    main()
