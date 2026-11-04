# BOSS GT-1 firmware research: NAM and custom amp voices

Static, read-only investigation of BOSS GT-1 firmware structure and ESC2 startup behaviour, aimed at two linked questions:

1. **Native NAM** — can Neural Amp Modeler A2-Lite run on the hardware the pedal already has?
2. **Custom amp voices** — can the amp engine the pedal already ships be retuned into sounds it was never sold with?

Compatibility is unproven in both cases; no firmware is modified or flashed.

## Where this stands (2026-11-03)

- **Native NAM: no demonstrated path.** The reachable M-profile application is integer-only in the scanned slices (no VFP/NEON or Armv7E-M DSP instructions) and about 4x short on cycles against A2-Lite at the labelled 48 MHz reference clock. The FA-08-style ESC2 program loader is present in the GT-1 application but unreachable in v1.05/v1.07/v1.08/v1.09, which leaves parameter and data traffic as the only application-to-DSP path and strengthens the mask-ROM hypothesis. See `docs/HANDOFF-DSP-ROUTE-C.md` and `firmware/work/gt1-dsp-load-reachability.json`.
- **Custom amp voices: active track.** Preamp voicing is carried as data, not code: 30 patch fields per slot including a full cabinet, mic and custom voicing set, plus plaintext parameter records on a uniform `0x753` stride inside the application image. See `docs/GT1-AMP-PARAMETER-TRACK.md`.

## Research documents

- `docs/GT1-FIRMWARE-ANALYSIS.md` — findings, evidence limits, offsets, hashes, and unresolved questions.
- `docs/GT1-NAM-COMPATIBILITY.md` — evidence table and current native/host-side decision.
- `docs/GT1-EXECUTION-DOMAIN-ASSESSMENT.md` — CPU ISA/DSP-domain census and NAM compute bound.
- `docs/GT1-FIRMWARE-EDITING-ASSESSMENT.md` — container repack, customization tiers, and preamp/NAM options.
- `docs/GT1-DSP-NAM-REVERSE-ENGINEERING-PLAN.md` — Route C: DSP ISA, program-load, numeric fit, and NAM port.
- `docs/GT1-AMP-PARAMETER-TRACK.md` — separate track: new amp sounds on the stock DSP by driving and editing the existing parameter surface.
- `docs/HANDOFF-DSP-ROUTE-C.md` — self-contained handoff of the Route C evidence, leads, and next moves.
- `docs/GT1-RESEARCH-PLAN.md` — current investigation sequence and stopping rules.
- `firmware/work/` — compact generated reports, source scripts, and hash manifests.
- `tools/ghidra_scripts/` — bounded Ghidra analysis scripts.

Raw firmware packages, extracted firmware images, reference-product firmware, and large Ghidra project databases are intentionally not tracked. The reports identify their source packages and hashes. To rerun probes that consume firmware images, first obtain the packages from the official sources cited in the analysis, verify them against the manifests, and reconstruct the expected local input paths.

## Canonical workspace and local inputs

This directory is the Git root. Run project commands here; there is no nested repo checkout.

The raw GT-1 packages, extracted/decoded firmware, reconstructed images, Ghidra databases, and reference corpus under firmware/ are intentionally excluded from Git by .gitignore. They remain local workspace inputs; the tracked reports and manifests record hashes and reproduction steps. The uploaded service notes are retained locally at firmware/work/reference/GT1-service-notes.pdf (SHA-256 cda284ec66877b5a418476fa53e5c4a3711edb18de066482646fdba2d1c183c6). Local Ghidra/JDK/tool downloads under tools/ are also ignored; project-specific Ghidra scripts remain tracked in tools/ghidra_scripts/.

The two documents that were previously in the visible outer docs/ folder are preserved under docs/archive/pre-root-consolidation-2026-11-03/; the current nested-repository versions are now the canonical documents.

## Repository name

This project was previously published as `BOSS.GT-1xNAM`. It is now `BOSS.GT-1xCUSTOM`, reflecting the added amp-parameter track. References to the old name in external notes, forks, or clones should be treated as this repository.
