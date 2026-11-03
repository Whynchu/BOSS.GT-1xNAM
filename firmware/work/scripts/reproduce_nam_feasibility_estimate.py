#!/usr/bin/env python3
"""Reproduce A2-Lite sample-rate/cycle/memory comparison estimates.

This is arithmetic over pinned upstream README/header facts, not a GT-1
benchmark. It does not test ESC2 performance or compatibility.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
NAM = ROOT / "firmware/work/reference/tone-3000-embedded"
README = NAM / "README.md"
HEADER = NAM / "engines/cortex-m7/a2lite/nam_a2lite.h"
ENGINE = NAM / "engines/cortex-m7/a2lite/nam_a2lite.c"
WEIGHTS = NAM / "weights/a2lite.namb"
DOC = ROOT / "firmware/work/reference/boss-docs/GT-1_parameter_eng02_W.pdf"
GT1_RATE = 44100
NAM_RATE = 48000
M7_CPS = 4059
M7_B16_CPS = 4403
BLOCK = 48
PREWARM_SAMPLES = 6347
GT1_NOMINAL_EXTERNAL_SDRAM_BYTES = 24 * 1024 * 1024
M7_A2LITE_HOT_KIB = 9.2
M7_A2LITE_CODE_KIB = 12.4

readme = README.read_bytes()
header = HEADER.read_bytes()
engine = ENGINE.read_bytes()
weights = WEIGHTS.read_bytes()
text = readme.decode("utf-8")
htext = header.decode("utf-8")
etext = engine.decode("utf-8")

assert "Cortex-M7" in text and "4,059" in text and "Block size 48" in text
assert "NAM_A2LITE_SAMPLE_RATE 48000.0f" in htext
assert "NAM_A2LITE_PREWARM_SAMPLES 6347" in htext
assert "void nam_a2lite_prewarm" in etext
assert len(weights) == 7980

state_body = htext.split("typedef struct nam_a2lite_state_t {", 1)[1].split("} nam_a2lite_state_t;", 1)[0]
state_array_lengths = re.findall(r"float\s+\w+\[([^]]+)\]", state_body)
assert state_array_lengths
state_float_count = sum(
    eval(expr, {"NAM_A2LITE_MAX_BUFFER_SIZE": BLOCK}) for expr in state_array_lengths
)
# Include the trailing int _unused (32-bit target int), not just float arrays.
state_bytes_from_header = state_float_count * 4 + 4
assert state_bytes_from_header == 102472

def per_rate(cycles_per_sample: int, rate: int, block_frames: int = 48) -> dict:
    cps = cycles_per_sample * rate
    callback_ms = block_frames * 1000.0 / rate
    callback_cycles = cycles_per_sample * block_frames
    return {
        "samples_per_second": rate,
        "cycles_per_sample_upstream_M7": cycles_per_sample,
        "cycles_per_second_if_same_cost": cps,
        "callback_frames": block_frames,
        "cycles_per_callback_if_same_cost": callback_cycles,
        "callback_duration_ms": callback_ms,
        "minimum_clock_MHz_at_100_percent_if_same_cost": cps / 1_000_000,
        "minimum_clock_MHz_at_50_percent_if_same_cost": cps / 500_000,
    }

def throughput_scenarios(reference_cycles_per_sample: int, sample_rate: int, clock_mhz: float) -> list[dict]:
    """Illustrate architectural cost sensitivity; factors are scenarios, not estimates."""
    scenarios = []
    for factor in (0.25, 0.5, 1, 2, 4, 8):
        cycles_per_sample = reference_cycles_per_sample * factor
        cycles_per_second = cycles_per_sample * sample_rate
        budget = clock_mhz * 1_000_000
        scenarios.append({
            "relative_ESC2_cycles_per_sample_vs_M7_reference": factor,
            "hypothetical_ESC2_cycles_per_sample": cycles_per_sample,
            "required_cycles_per_second": cycles_per_second,
            "single_core_utilization_at_clock": cycles_per_second / budget,
            "single_core_utilization_percent": cycles_per_second / budget * 100,
            "fits_one_core_for_NAM_alone": cycles_per_second <= budget,
            "interpretation": "Sensitivity scenario only; not a measured or predicted ESC2 performance factor.",
        })
    return scenarios

result = {
    "classification": "arithmetic estimate from pinned upstream benchmarks; not measured on GT-1 or ESC2",
    "read_only": True,
    "source_files": {
        "README.md": {"sha256": hashlib.sha256(readme).hexdigest(), "path": str(README.relative_to(ROOT))},
        "nam_a2lite.h": {"sha256": hashlib.sha256(header).hexdigest(), "path": str(HEADER.relative_to(ROOT))},
        "nam_a2lite.c": {"sha256": hashlib.sha256(engine).hexdigest(), "path": str(ENGINE.relative_to(ROOT))},
        "a2lite.namb": {"sha256": hashlib.sha256(weights).hexdigest(), "size": len(weights), "path": str(WEIGHTS.relative_to(ROOT))},
        "boss_parameter_guide_pdf": {"sha256": hashlib.sha256(DOC.read_bytes()).hexdigest(), "path": str(DOC.relative_to(ROOT))},
    },
    "upstream_facts": {
        "M7_A2Lite_cycles_per_sample_block_48": M7_CPS,
        "M7_A2Lite_16_frame_tuned_cycles_per_sample": M7_B16_CPS,
        "M7_benchmark_clock_MHz": 480,
        "NAM_model_rate_Hz": NAM_RATE,
        "GT1_rate_Hz": GT1_RATE,
        "namb_file_bytes": len(weights),
        "weight_float_values": 1871,
        "weights_bytes": 1871 * 4,
        "hot_instance_plus_weights_at_48_block_KiB": 9.2,
        "state_at_48_block_KiB": 100,
        "state_at_64_block_KiB": 109,
        "engine_code_KiB": 12.4,
        "NAM_A2LITE_SAMPLE_RATE_header": "48000.0f",
        "engine_process_API": "caller supplies input/output buffers and num_frames; no resampling API documented",
        "header_derived_state_float_count_at_block48": state_float_count,
        "header_derived_state_bytes_at_block48": state_bytes_from_header,
        "header_derived_state_KiB_at_block48": state_bytes_from_header / 1024,
        "prewarm_samples_after_init_or_reset": PREWARM_SAMPLES,
        "prewarm_duration_ms_at_engine_rate": PREWARM_SAMPLES * 1000 / NAM_RATE,
        "prewarm_calls_at_block48": (PREWARM_SAMPLES + BLOCK - 1) // BLOCK,
        "prewarm_work_cycles_at_M7_block48_reference": PREWARM_SAMPLES * M7_CPS,
        "prewarm_work_cycles_is_measured_on_ESC2": False,
    },
    "memory_scenarios": {
        "gt1_documented_external_sdram_nominal_bytes": GT1_NOMINAL_EXTERNAL_SDRAM_BYTES,
        "gt1_documented_external_sdram_mib": GT1_NOMINAL_EXTERNAL_SDRAM_BYTES / (1024 * 1024),
        "gt1_free_or_realtime_usable_ram_known": False,
        "single_a2lite_instance_at_block48": {
            "state_ring_buffers_bytes_header_derived": state_bytes_from_header,
            "weights_plus_instance_kib_upstream_rounded": M7_A2LITE_HOT_KIB,
            "estimated_dynamic_working_bytes": state_bytes_from_header + round(M7_A2LITE_HOT_KIB * 1024),
            "estimated_dynamic_working_kib": (state_bytes_from_header + round(M7_A2LITE_HOT_KIB * 1024)) / 1024,
            "engine_code_kib_separate": M7_A2LITE_CODE_KIB,
            "capture_file_bytes_separate": len(weights),
            "working_ram_fraction_of_gt1_nominal_external_sdram": (state_bytes_from_header + round(M7_A2LITE_HOT_KIB * 1024)) / GT1_NOMINAL_EXTERNAL_SDRAM_BYTES,
        },
        "two_distinct_a2lite_instances_for_overlap_or_crossfade_at_block48": {
            "state_ring_buffers_bytes_header_derived": state_bytes_from_header * 2,
            "two_weights_plus_instances_kib_upstream_rounded": M7_A2LITE_HOT_KIB * 2,
            "estimated_dynamic_working_bytes": (state_bytes_from_header + round(M7_A2LITE_HOT_KIB * 1024)) * 2,
            "estimated_dynamic_working_kib": (state_bytes_from_header + round(M7_A2LITE_HOT_KIB * 1024)) * 2 / 1024,
            "engine_code_kib_shared_not_doubled": M7_A2LITE_CODE_KIB,
            "two_capture_files_bytes_if_both_retained_separately": len(weights) * 2,
            "working_ram_fraction_of_gt1_nominal_external_sdram": (state_bytes_from_header + round(M7_A2LITE_HOT_KIB * 1024)) * 2 / GT1_NOMINAL_EXTERNAL_SDRAM_BYTES,
        },
        "interpretation_limit": "Capacity ratios compare estimated NAM working data with nominal external SDRAM only; they do not establish free space, memory mapping, bus contention, bandwidth, latency, or acceptable audio-deadline performance.",
    },
    "cost_estimates": {
        "prewarm_after_init_or_reset": {
            "samples_of_silence": PREWARM_SAMPLES,
            "engine_sample_rate_Hz": NAM_RATE,
            "audio_equivalent_duration_ms": PREWARM_SAMPLES * 1000 / NAM_RATE,
            "calls_at_48_frame_block": (PREWARM_SAMPLES + BLOCK - 1) // BLOCK,
            "last_call_frames_if_block48": PREWARM_SAMPLES % BLOCK or BLOCK,
            "M7_reference_cycles_per_sample": M7_CPS,
            "M7_reference_total_cycles": PREWARM_SAMPLES * M7_CPS,
            "M7_reference_core_time_ms_at_480MHz": PREWARM_SAMPLES * M7_CPS / 480_000,
            "interpretation": "State initialization requirement; separate from steady-state NAM cycles/sample. Must be scheduled or crossfaded during model load/switch if a transient is unacceptable.",
            "esc2_timing_known": False,
        },
        "supported_engine_rate_block48": {
            **per_rate(M7_CPS, NAM_RATE),
            "rate_is_supported_by_engine": True,
            "resampling_cost_included": False,
        },
        "supported_engine_rate_block16_tuned": {
            **per_rate(M7_B16_CPS, NAM_RATE, 16),
            "rate_is_supported_by_engine": True,
            "resampling_cost_included": False,
        },
        "44k1_to_48k_conversion_requirement": {
            "GT1_input_rate_Hz": GT1_RATE,
            "NAM_engine_rate_Hz": NAM_RATE,
            "rational_conversion_ratio_output_over_input": "160/147",
            "input_samples_per_common_interval": 147,
            "output_samples_per_common_interval": 160,
            "common_interval_ms": 147 * 1000 / GT1_RATE,
            "A2Lite_cycles_for_160_output_samples_at_M7_rate": M7_CPS * 160,
            "cycles_per_second_for_NAM_stage_at_M7_rate": M7_CPS * NAM_RATE,
            "conversion_filter_cost_included": False,
            "interpretation": "A real pipeline must resample or adapt the model; the embedded API documents 48 kHz only.",
        },
        "counterfactual_direct_call_at_44100_not_supported": {
            **per_rate(M7_CPS, GT1_RATE),
            "rate_is_supported_by_engine": False,
            "status": "arithmetic only; not a valid use of this engine unless adapted and revalidated",
        },
        "GT1_nominal_clock_condition_48MHz_if_same_M7_cost": {
            "utilization_at_44100_counterfactual_not_supported": M7_CPS * GT1_RATE / 48_000_000,
            "utilization_at_48000": M7_CPS * NAM_RATE / 48_000_000,
            "utilization_percent_at_48000": M7_CPS * NAM_RATE / 48_000_000 * 100,
            "note": "48 MHz is a conditional example only; GT-1 service diagram clock net is not proof of core clock.",
            "sample_budget_at_48k_block48_cycles": 48_000_000 / 48_000 * 48,
            "M7_reference_work_at_48k_block48_cycles": M7_CPS * 48,
            "M7_reference_work_over_budget_factor": M7_CPS * 48 / (48_000_000 / 48_000 * 48),
            "throughput_sensitivity_scenarios": throughput_scenarios(M7_CPS, NAM_RATE, 48),
        },
    },
    "limitations": [
        "Upstream M7 cycle counts were measured on an STM32H750 Cortex-M7 at 480 MHz; they are not ESC2 timings.",
        "The relative throughput factors in the 48 MHz scenario table are sensitivity illustrations only; they do not predict ESC2 performance.",
        "ESC2 ISA, clock, compiler support, FPU, memory latency/bandwidth, and available audio budget are unknown.",
        "Direct 44.1 kHz processing is not documented by this engine. A 44.1-to-48 kHz resampler or model adaptation is required; resampler cost and latency are excluded.",
        "External RAM capacity does not prove accessible free memory or suitable real-time bandwidth.",
        "The M7 timing configuration places hot state in DTCM and ring buffers in cached AXI SRAM; equivalent low-latency memory placement has not been established for ESC2.",
        "A2-Full values are deliberately excluded; this assessment is for A2-Lite only.",
    ],
}
out = ROOT / "firmware/work/nam-feasibility-estimate.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(out)
