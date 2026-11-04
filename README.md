# BOSS GT-1 NAM firmware research

Static, read-only investigation of BOSS GT-1 firmware structure, ESC2 startup behavior, and the feasibility of running Neural Amp Modeler A2-Lite on the existing hardware. Compatibility is unproven; no firmware is modified or flashed.

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
