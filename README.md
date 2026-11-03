# BOSS GT-1 NAM firmware research

Static, read-only investigation of BOSS GT-1 firmware structure, ESC2 startup behavior, and the feasibility of running Neural Amp Modeler A2-Lite on the existing hardware. Compatibility is unproven; no firmware is modified or flashed.

## Research documents

- `docs/GT1-FIRMWARE-ANALYSIS.md` — findings, evidence limits, offsets, hashes, and unresolved questions.
- `docs/GT1-RESEARCH-PLAN.md` — current investigation sequence and stopping rules.
- `firmware/work/` — compact generated reports, source scripts, and hash manifests.
- `tools/ghidra_scripts/` — bounded Ghidra analysis scripts.

Raw firmware packages, extracted firmware images, reference-product firmware, and large Ghidra project databases are intentionally not tracked. The reports identify their source packages and hashes. To rerun probes that consume firmware images, first obtain the packages from the official sources cited in the analysis, verify them against the manifests, and reconstruct the expected local input paths.
