# GT-1 firmware editing: what is mechanically possible

**Status:** offline container work only; no device has been flashed.  
**Date:** 2026-11-03.  
**Scope:** distinguish (a) editable ARM application code/data, (b) preset/parameter customization, and (c) DSP/amp-algorithm changes such as NAM.  
**Evidence:** `firmware/work/scripts/reproduce_gt1_app_repack.py`, `firmware/work/repacked/v109-noop-repacked.json`, and the existing container/decoder evidence.

## Bottom line

Firmware editing is **mechanically plausible and partially demonstrated offline**. The v1.09 application payload can be decoded, re-encoded in its own LZ format, and repacked with a corrected header and additive checksum. A no-op repack round-trips byte-for-byte: the 2,937,524-byte decoded app re-encodes to 1,181,994 bytes (original: 1,178,362), well inside the app partition.

That makes **ARM-side application edits** the realistic customization target: UI strings, defaults, MIDI/control behavior, patch-handling logic, effect-chain defaults, parameter mappings, and data tables. It does **not** establish a NAM execution path. The PREAMP is an audio algorithm, and replacing it with NAM requires identifying the actual execution domain, its audio contract, and a viable build/compute path; repacking the ARM application alone does not provide those.

## What is now established offline

| Step | Status | Evidence |
|---|---|---|
| Parse the 4 MiB image and `BSSESC2:GT1Upd` / `GT1Appli` headers | Established | `firmware/work/container-layout.json` |
| Decode the stored application payload | Established | `firmware/work/bootstrap-decoder-probe.json`; decoded SHA-256 `2028d7e1…` |
| Re-encode the decoded app in the same LZ format | Established offline | `reproduce_gt1_app_repack.py`, exact round-trip |
| Recompute the `+0x30` stored length and `+0x34` additive checksum | Established | candidate header and manifest |
| Fit the re-encoded payload in the app partition | Established | 1,181,994 bytes vs 1,818,560-byte capacity |
| Prove the stock updater accepts a re-encoded no-op image | **Not yet tested** | requires a device flash and recovery plan |
| Prove the bootloader validator accepts it | **Not yet tested** | validator table at `0x01010028` still unresolved |

The updater itself contains explicit strings for `Updater sum err`, `App sum err`, `Checksum App ERROR`, `HEADER ERROR`, `CHECKSUM ERROR`, `VERIFY ERROR`, and `COMPARE ERROR`. This is strong evidence that the update path validates headers and additive payload sums and read-back compares the written data. No cryptographic signature string or obvious signature routine has been found; that is a bounded negative, not a proof that no authentication exists.

A safe first hardware experiment, once explicitly authorized and with a recovery plan, is to flash the **no-op repacked image** (same application bytes, different container encoding). If it is accepted and the unit boots identically, the repack/checksum pipeline is proven without changing behavior. If it is rejected, the updater or bootloader has an additional check that needs tracing before any real patch.

## What kinds of customization should be possible

### Easy / high confidence (ARM app or patch data)

- Preset and parameter changes: amp type, gain, EQ, speaker/mic, effect types, chain order, footswitch/expression assignments, tuner, system settings. Most of this is already reachable through SysEx/patch editing and does not need a firmware patch.
- UI strings, patch names, boot/error text, default patch, default system settings.
- MIDI/CC behavior, controller assignments, patch-selection behavior.
- Effect-chain defaults and bypass/routing logic in the ARM control layer.
- Parameter-to-DSP mappings, display behavior, hidden/undocumented menu values.

These are ordinary code/data patches in the decoded application. The main work is finding the right table or branch, re-encoding the app, fixing the header/checksum, and validating on hardware.

### Moderate / plausible with more reverse engineering

- Looper buffer size or recording limit, if the limit is an ARM-side constant or allocation. If it is a DSP/ERAM allocation, it is much harder.
- Feature flags, disabled effects, alternate chain configurations, startup behavior.
- Cab/speaker/IR coefficient tables or amp parameter tables, if their format and consumer are identified.
- Sample/looper memory layout and patch storage limits.
- Transplanting data tables between GT-1/GT-100-family images where formats match.

These require identifying the relevant table/consumer and may interact with DSP-side assumptions. They are plausible but not yet demonstrated.

### Hard / research-grade

- New DSP effects or new amp algorithms.
- Changing the amp modeling algorithm itself.
- Replacing the PREAMP stage with a different engine.
- Changing sample rate or the codec/audio clock contract.
- Running a neural-network interpreter on the DSP.

These require the ESC2 DSP ISA, a compiler/assembler or hand-written microcode, the DSP memory map, and the real-time audio contract. None of those are publicly available in the evidence gathered so far. The ARM application can *control* the DSP, but the audio algorithms live in the DSP domain.

### No demonstrated native NAM path

- Loading a `.namb` file and having the GT-1 evaluate it. A bounded string scan found no `BMAN`/`.namb`, WaveNet/conv1d, or TONE3000 signatures; this does not rule out a generic interpreter, and no NAM loader/runtime has been identified.
- Running the published float32 A2-Lite engine on either recovered execution domain. The v1.08 CPU census covers only part of one copied segment. It does not establish the complete CPU feature set or the core clock. The published M7 work versus the 48 MHz `CKCPU` reference is a conditional compute concern, not a GT-1 benchmark.
- Dropping A2-Lite into the DSP without its ISA/toolchain and a new port.

## The "keep everything, replace the PREAMP with NAM" goal

The goal is conceptually clean: the GT-1 exposes PREAMP/SPEAKER as a distinct user-visible node, so replacing that node while keeping OD/DS, modulation, delay, reverb, and control would be the ideal integration. The obstacle is architectural, not just packaging:

1. **The stock preamp is a DSP algorithm, not a swappable model file.** The ARM application selects parameters and sends DSP commands; it does not evaluate the amp model itself. There is no generic "amp engine" slot that accepts a NAM graph.
2. **The CPU compute path is unresolved.** The partial v1.08 scan found no VFP/NEON or listed Armv7E-M DSP instructions in its inspected slices, but does not establish the full app or silicon feature set. The 48 MHz `CKCPU` label is not a verified post-PLL core clock, and no target benchmark exists.
3. **The DSP is undocumented.** The application exposes IRAM/PRAM windows and a command/data interface, but the DSP ISA, toolchain, numeric format, and real-time program-load contract are unknown. A NAM port would be a from-scratch DSP project, not a firmware patch.
4. **No NAM interpreter has been identified.** Even if NAM weights were placed in DSP memory, no evidence shows firmware evaluating a NAM model graph.

So "keep everything but replace the preamp" is not achievable by repacking the stock application. The realistic options are:

### A. Host-side NAM through USB (practical now)

The GT-1 is a USB audio interface with a documented monitor/mix path: `EFX OUT` sends the processed sound to the computer, `USB IN`/`MIX LEVEL` returns computer audio at the final stage, and `DIRECT MONITOR` can be turned off for through-monitoring. Run NAM on the host, keep the GT-1's effects and foot control, and turn the internal PREAMP off.

Caveat: the USB return is mixed at the **final stage**, not at the PREAMP node. If you want NAM *before* the GT-1's modulation/delay/reverb, the cleanest practical routing is guitar → host NAM → GT-1 input with the internal PREAMP off → GT-1 effects. That is "NAM as the front end, GT-1 effects after it", not "NAM inside the GT-1's preamp slot". It may need level matching and adds host/audio-interface latency.

### B. Hardware insertion at the codec/ESC2 boundary (hardware project)

The AK4556 codec's serial audio and clocks connect directly to ESC2. A board-level insert could tap the audio at that boundary and route it through an external NAM-capable DSP (for example a Daisy Seed/Teensy-class board), then return it. This could sit closer to the preamp point than the USB loop, but it requires board rework, I2S clock/frame handling, power, level matching, and a way to bypass the internal preamp. It is not a firmware-only change and carries hardware risk.

### C. Full DSP reverse engineering and port (research project)

Obtain primary MB8AA4181/ESC2 DSP ISA and toolchain evidence, recover the program-load and audio-callback contract, then benchmark a port against the real-time budget. This remains a research route rather than an established or exclusive native path. It is not equivalent to editing the firmware to load a NAM model.

## Risks and the recovery question

BOSS warns that interrupting an update can leave the unit unable to start normally and may require service. No recovery partition has been found. The service notes show an **unpopulated serial-flash programming footprint** (`CN2`, with `SFCLK`/`SFIO0`/`SFIO1`/`SFIO2` and boot-mode straps) and test points; that is a plausible hardware recovery route, but it has not been tested here and requires soldering/programming equipment. Treat any flash experiment as potentially destructive.

The updater's own `VERIFY ERROR` / `COMPARE ERROR` strings suggest it reads back and compares the written image, which is good for integrity but does not give you a recovery path if the bootloader rejects the result.

## Recommended order from here

1. **Trace the updater's validation paths and the bootloader validator table** (`0x01010028` / `0x020030xx`) to determine whether anything beyond the header and additive checksum is enforced.
2. **Build and inspect the no-op repacked image** (already possible offline) and, only with explicit authorization and a recovery plan, test it on hardware. This proves the container pipeline without changing behavior.
3. **Patch a low-risk ARM-side behavior** (a string, default setting, or MIDI mapping) and validate it. This establishes real customization capability.
4. **Then decide** whether the remaining goal is host-side NAM, hardware insertion, or a DSP reverse-engineering project. Do not spend more time trying to make the stock integer CPU run A2-Lite.

## Reproduction

```sh
python3 -B firmware/work/scripts/reproduce_gt1_app_repack.py
```

Outputs `firmware/work/repacked/v109-noop-repacked.bin` and a JSON manifest. The script does not flash or modify the device.
