#!/usr/bin/env python3
"""Compare local 8+1 float-pair hypotheses against shuffled-byte baselines.

This is a bounded, read-only negative-control experiment. It evaluates all
nine byte phases in a fixed window around the reported v1.09 looper candidate,
then compares the observed best phase with deterministic byte-shuffle
baselines. It does not infer that values are floats or that records are real.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
IMAGE = ROOT / "firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN"
CENTER = 0x0BEBE4
RADIUS = 0x90
MIN_RECORDS = 12
SHUFFLES = 256
SEED = 0xB0556


def score(window: bytes) -> dict:
    phase_scores = []
    for phase in range(9):
        start = phase
        pairs = []
        while start + 9 <= len(window):
            a, b = struct.unpack_from("<ff", window, start + 1)
            pairs.append((a, b))
            start += 9
        if len(pairs) < MIN_RECORDS:
            continue
        valid = sum(
            math.isfinite(a) and math.isfinite(b) and abs(a) <= 100 and abs(b) <= 100
            for a, b in pairs
        )
        nonzero = sum(
            math.isfinite(a) and math.isfinite(b) and abs(a) <= 100 and abs(b) <= 100
            and (abs(a) > 1e-6 or abs(b) > 1e-6)
            for a, b in pairs
        )
        phase_scores.append({
            "phase": phase,
            "records": len(pairs),
            "finite_abs_le_100_pairs": valid,
            "nonzero_plausible_pairs": nonzero,
            "valid_fraction": valid / len(pairs),
            "nonzero_fraction_of_plausible": nonzero / valid if valid else 0,
        })
    best = max(phase_scores, key=lambda x: (x["valid_fraction"], x["nonzero_fraction_of_plausible"]))
    return {"best_phase": best, "all_phases": phase_scores}


def main() -> None:
    image = IMAGE.read_bytes()
    start, end = CENTER - RADIUS, CENTER + RADIUS
    window = image[start:end]
    observed = score(window)
    rng = random.Random(SEED)
    baseline = []
    raw = list(window)
    for index in range(SHUFFLES):
        shuffled = raw.copy()
        rng.shuffle(shuffled)
        baseline.append(score(bytes(shuffled))["best_phase"])
    observed_best = observed["best_phase"]
    better_or_equal = sum(
        (x["valid_fraction"], x["nonzero_fraction_of_plausible"])
        >= (observed_best["valid_fraction"], observed_best["nonzero_fraction_of_plausible"])
        for x in baseline
    )
    result = {
        "question": "Is an 8+1 little-endian float-pair interpretation near 0x0BEBE4 more compelling than shuffled-byte nulls?",
        "read_only": True,
        "input": {
            "path": str(IMAGE.relative_to(ROOT)),
            "image_sha256": hashlib.sha256(image).hexdigest(),
            "window_start": hex(start),
            "window_end_exclusive": hex(end),
            "window_sha256": hashlib.sha256(window).hexdigest(),
            "window_hex": window.hex(" "),
            "target_offset_relative": hex(CENTER - start),
        },
        "method": {
            "candidate_record": "one skipped marker byte plus two little-endian float32 values; 9-byte cadence",
            "phases_tested": list(range(9)),
            "plausibility_filter": "both floats finite and absolute value <= 100",
            "minimum_records": MIN_RECORDS,
            "null": "uniform random permutation of the same 288 bytes; phase search repeated",
            "null_repetitions": SHUFFLES,
            "null_rng_seed": SEED,
        },
        "observed": observed,
        "null_best_phase_score_summary": {
            "valid_fraction_min": min(x["valid_fraction"] for x in baseline),
            "valid_fraction_median": sorted(x["valid_fraction"] for x in baseline)[len(baseline)//2],
            "valid_fraction_max": max(x["valid_fraction"] for x in baseline),
            "nonzero_fraction_min": min(x["nonzero_fraction_of_plausible"] for x in baseline),
            "nonzero_fraction_median": sorted(x["nonzero_fraction_of_plausible"] for x in baseline)[len(baseline)//2],
            "nonzero_fraction_max": max(x["nonzero_fraction_of_plausible"] for x in baseline),
            "observed_score_beaten_or_tied": better_or_equal,
        },
        "null_replicates": baseline,
        "interpretation_limit": "Byte shuffling is a crude null that destroys local structure; candidate thresholds and phase search are exploratory. Even an unusual score would not prove float storage, record boundaries, or looper semantics.",
    }
    out = ROOT / "firmware/work/looper-region-float-null-evidence.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(out.relative_to(ROOT))
    print("observed best", observed_best)
    print("null summary", result["null_best_phase_score_summary"])


if __name__ == "__main__":
    main()
