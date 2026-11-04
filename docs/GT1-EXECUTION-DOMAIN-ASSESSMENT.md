# GT-1 execution-domain assessment: CPU, DSP, and NAM fit

**Status:** static evidence review; no device was modified or flashed.  
**Date:** 2026-11-03.  
**Scope:** determine which GT-1 execution domain could run NAM A2-Lite, and whether the recovered CPU path can meet its compute contract.  
**Companion evidence:** `firmware/work/gt1-execution-domain-census.json`, reproduced by `firmware/work/scripts/reproduce_gt1_execution_domain_census.py`.

## Bottom line

- A bounded part of the v1.08 application decodes as M-profile Thumb/Thumb-2 integer code with `UDIV`; no VFP/NEON or listed Armv7E-M DSP instructions were observed in the scanned slices. The linear sweep covers **21.0% of one 69,398-byte segment**, and the narrow direct-edge walk covers 4.8%. The decoded app has no exact CPACR literal. This evidence does **not** establish that the complete CPU application or silicon is integer-only.
- The application contains a **distinct ESC2 DSP program/data control domain**: literal tables for `0x40140000`, `0x40144000`, `0x4014E000`, `0x40150000`, `0x40160000`, `0x40164000`, `0x4016E000`, and `0x40170000`; a command/data register interface based at `0x40100000`; and `IRAM0`/`PRAM0`/`IRAM1`/`PRAM1` diagnostics. These support a DSP execution context with named program/data windows, but do not prove a separate CPU, its ISA, or that it executes the amp model. Related AD-10 and ME-80 notes are corroboration, not GT-1-specific architecture documentation.
- The published optimized A2-Lite result is a **float32 Cortex-M7 benchmark**, not a GT-1 measurement. Comparing its 194.8 million cycles/s to the board's 48 MHz `CKCPU` reference gives 4.06×, but CKCPU is not a verified core clock and the M7 cycle count cannot be transferred to ESC2. The 1,871-weight MAC arithmetic is a conditional lower bound, not a target benchmark.
- A byte-string search found no NAM-specific signatures (`BMAN`, `.namb`, `WaveNet`, `conv1d`, `Neural`, `TONE3000`). This says nothing conclusive about a generic interpreter. No native NAM loader or execution path has been identified.
- **Decision:** no native NAM path is demonstrated, and current evidence is insufficient to call integration feasible. This is a no-go for dropping the existing A2-Lite engine/model into recovered firmware as-is, not proof that a complete CPU/DSP port is impossible. Host-side NAM is an external post-effect route over USB; it does not insert NAM into the GT-1 chain.

## What was measured

The census is hash-pinned to the preserved v1.08 image and its decoded application, matching the version reported on the connected pedal:

| Input | SHA-256 |
|---|---|
| `firmware/extracted/v108/gt1_sys_v108/GT1ROM.BIN` | `7219679a87e985316264544423c9940ccbcbadeb2df0b2f13711ae57194cb612` |
| `firmware/work/decoded/v108-GT1Appli.bin` | `c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1` |
| startup-copied code segment at `0x01000300` | `5691f04c08e52373973725ede20ff9de0bc3fc0e77a160e856a11342701168a0` |

The M-profile strict linear decode covers 5,798 instructions and 14,552 bytes (21.0% of the segment), from `0x01000300` up to `0x01003BE8`, before the first undecodable byte. It deliberately does not resynchronise, so it cannot turn a literal pool into plausible instructions. Within that bounded census:

- VFP/NEON: **0**
- Armv7E-M DSP instructions (`smul*`, `smla*`, `usad8`, `qadd`, `pkh*`, `sxtb16`, `rev`, `clz`, ...): **0**
- system instructions (`MRS`/`MSR`/`CPS`/`DMB`/`DSB`/`ISB`/`SVC`/...): **0**
- hardware divide: **2** `UDIV`
- top mnemonics are integer loads/stores, moves, compares, branches, and `BL`

A narrow direct-edge walk covers 1,164 instructions (4.8%) and is dominated by veneer `BX`/`MOVW`/`MOVT` stubs. It starts from v1.08 startup entries and hash-pinned callback targets, then follows direct calls and unconditional branches. It omits conditional edges, indirect calls/branches, and table branches. It finds no VFP or DSP instructions in those sampled paths and seven system instructions. The decoded application contains **no exact byte literal for CPACR (`0xE000ED88`)** or CPUID (`0xE000ED00`); absence does not exclude computed/helper-mediated access or earlier boot-stage configuration.

**Evidence limit:** the v1.08 census covers only part of one startup-copied segment; other decoded segments and the in-place code region remain outside it. Separate startup probes establish SVC and BASEPRI behavior elsewhere in this same segment, illustrating why the linear prefix alone cannot represent the whole image. None of these slices establishes the complete CPU feature set or the audio algorithm's execution domain.

## The DSP domain

The v1.08 application's literal table at decoded offset `0x47DB0` contains the following addresses:

```
0x40100600  0x40100000  0x600A1298
0x40160000  0x40164000  0x40140000  0x40144000
0x40150000  0x40170000  0x4016E000  0x4014E000
```

The corresponding v1.08 code and transfer helpers use these constants. A transfer helper writes a selected `0x50000` or `0x70000` address, ORed with `0x20000000`, into `0x40100000`, then writes the payload to the next register. Other helpers use `0x40150000`/`0x40170000` (PRAM windows) and `0x4014E000`/`0x4016E000` (IRAM windows). The application strings include:

```
CPrmESC2DT1 Error: PRG Set without DSP Halt!
CPrmESC2DT1 Error: DRP Set without DSP Halt!
NG (IRAM0)  NG (PRAM0)  NG (IRAM1)  NG (PRAM1)
```

This is strong evidence of DSP program/data controls and named memory windows in the ESC2; it does not by itself prove a separate physical CPU or map the windows to physical RAM. The previously traced callers are the SysEx/control path and diagnostic memory tests; no boot-time audio-engine load or recurring amp dispatch has been demonstrated. The DSP evidence narrows the architecture question by showing that the firmware can address a DSP-oriented program/data domain. It does not establish whether the application CPU, that DSP domain, or another mechanism executes the amp model.

**Reachability result (2026-11-03, reproduction `firmware/work/scripts/reproduce_gt1_dsp_load_reachability.py`).** The FA-08-style program loader is present in the GT-1 application in identical structural form — a PRAM0/PRAM1 block transfer, two 12-byte descriptor walkers, and a loader entry — but it is unreachable. In v105, v107, v108, and v109 the transfer function has exactly one external caller, and that caller's enclosing function has zero external incoming edges; no direct call, branch, aligned pointer literal, or `movw`/`movt` address construction reaches the pair. Conversely, the command-register path (`0x50000`/`0x70000` bank select through `0x40100000`) is live and used by the SysEx/control family, so DSP address space *is* written at runtime — just never as a program block. This materially strengthens the hypothesis that the DSP program is supplied in mask ROM or before the application runs, and leaves parameter/data traffic as the only demonstrated application-to-DSP memory operation.


Related-product service notes corroborate the split: the AD-10 notes label ESC2 memory as "DSP external ERAM (+ Dual Port Memory)", and the ME-80 notes refer to a `DSP iram0` error. These are reported from related-product service-note text, not locally reproduced, and are not GT-1-specific, but they describe the same `MB8AA4181 (ESC2)` part family and are consistent with the GT-1's own `IRAM`/`PRAM` diagnostics.

## Conditional CPU compute concern

The pinned upstream benchmark is 4,059 cycles/sample for A2-Lite at 48 kHz on a 480 MHz Cortex-M7 with the FPv5/Thumb-2 fast path (about 41% of that core). The arithmetic is:

| Quantity | Value |
|---|---:|
| A2-Lite cycles per sample (published M7) | 4,059 |
| Cycles per second at 48 kHz | 194,832,000 |
| Minimum clock at 100% M7 efficiency | 194.8 MHz |
| Minimum clock at 50% M7 efficiency | 389.7 MHz |
| GT-1 `CKCPU` reference | 48 MHz (board label, not verified post-PLL core clock) |
| Cycles per sample available at 48 MHz / 48 kHz | 1,000 |
| Published M7 work over that budget | 4.06× |
| 1,871 weight MACs per sample at 48 kHz | 89.8 million MAC/s |
| Minimum clock for 1 MAC/cycle | 89.8 MHz |
| 1-MAC/cycle utilization at 48 MHz | 1.87× |

The 48 MHz number is a **conditional** comparison because the service-note block diagram labels a 48 MHz `CKCPU` reference, not a verified core clock. The arithmetic indicates a serious risk if the audio CPU runs near that rate and performs comparable work; it does not constitute a GT-1 performance verdict:

- The scanned slice contains no observed VFP/NEON instructions, but its coverage is incomplete. The upstream A2-Lite repository also documents a C fallback for targets without FPv5; its performance on the GT-1 is not measured. No fixed-point port or target benchmark is available.
- Even a hypothetical **perfect 1-MAC/cycle fixed-point** engine is over the weight-only bound at 48 MHz (1.87×), before activations, the head layer, resampling, and the rest of the GT-1 effect chain.
- A 2-MAC/cycle engine at 48 MHz could just cover the weight arithmetic, but that is a DSP-style machine, not the recovered ARM control core. It also would not run A2-Lite's float32 C/Thumb-2 code as published.

This supports a conditional compute warning, not a bounded negative for the whole CPU. Establishing the CPU clock and execution features, then benchmarking the relevant engine or fallback, remains necessary.

## Why the DSP is not a drop-in NAM target

The DSP domain is real, but it does not create a usable NAM path by itself:

1. **No public ISA/toolchain.** Exact-part searches have not located an MB8AA4181/ESC2 programming manual, instruction-set reference, compiler, or debugger. The chip is consistently described as an old, specialized Roland/BOSS DSP. Without the ISA, A2-Lite cannot be compiled for it.
2. **A2-Lite is not portable DSP code.** The published engine is float32 ARM/Thumb-2 with FPv5-specific kernels. A DSP port would need the DSP's numeric format, accumulator width, memory model, and a new kernel implementation; it is not a firmware "load the model" operation.
3. **No known model interpreter.** A string search did not find `.namb`/`BMAN`, WaveNet/conv1d, or TONE3000 markers. That does not rule out a generic interpreter, but no NAM runtime or loader has been identified. Loading NAM weights into DSP memory alone would not demonstrate that anything evaluates them.
4. **No proven integration point.** The transfer path is currently tied to SysEx/control and diagnostic memory tests. No boot-time DSP program load, recurring audio callback, buffer contract, or amp-stage replacement point has been demonstrated.

A DSP program replacement remains a theoretical route, but is not actionable without the ISA/toolchain and a validated real-time contract. The current evidence establishes neither drop-in support nor impossibility of a port.

## What would change the decision

The present assessment is **no demonstrated native path**, not a mathematical impossibility proof or a definitive no-go for all re-engineering. The following evidence would make a stronger decision possible:

1. Primary MB8AA4181/ESC2 DSP documentation, an instruction-set reference, and a working compiler/emulator or debug toolchain.
2. A recoverable DSP program-load path plus a demonstrated recurring audio callback, buffer format, block size, and amp-stage boundary.
3. A target benchmark (DSP or a different CPU with FPv5) showing the NAM stage, resampling, and remaining effects meet the audio deadline at the GT-1's 44.1 kHz rate with acceptable numerical error.
4. A complete target-specific ISA/clock census of the relevant v1.08 execution regions, or primary documentation showing which CPU/DSP engine executes the amp model and its clock/features.

## Practical route available now

The GT-1 is a USB audio interface with a documented monitor/mix path. The parameter guide describes:

- `EFX OUT` level: the GT-1 effect sound sent to the computer over USB.
- `USB IN` / `MIX LEVEL`: computer audio returned and mixed at the final stage.
- `DIRECT MONITOR` off when passing audio through the computer.

That supports an external setup in which NAM runs on a host, receives the GT-1's post-effect USB output, and returns audio to the GT-1's final mix. This does not insert NAM into the amp block or place later GT-1 effects after NAM; it is a post-chain arrangement that requires no firmware modification. The host path is already observable: the read-only capture `firmware/work/gt1-usb-audio-capture-2026-11-03.wav` is 15 seconds of 44.1 kHz, 2-channel signed-32-bit PCM from the device, recorded with an open input and no guitar.

## Sources

- Local GT-1 service notes `firmware/work/reference/GT1-service-notes.pdf` (SHA-256 `cda284ec66877b5a418476fa53e5c4a3711edb18de066482646fdba2d1c183c6`): block diagram (PDF p.12) labels the 48 MHz `CKCPU` reference and the 16.9344 MHz audio clock; printed p.26 (PDF p.28) identifies `MB8AA4181 (ESC2)` and the unpopulated JTAG connector; printed p.27 (PDF p.29) shows the WORK/ERAM SDRAM connections.
- Related-product AD-10 service notes (reported): “DSP external ERAM (+ Dual Port Memory)” and `MB8AA4181 (ESC2)`. ME-80 service notes (reported): `DSP iram0` error.
- Third-party GT-1 reverse-engineering thread (reported): Arm Thumb / Cortex-M3-style vector table at `0x01000000`, load base `0x00FFFFD0`, Main at `0x01000AE4`. <https://www.linux.org.ru/forum/talks/17651382>
- Pinned upstream NAM evidence: `firmware/work/reference/tone-3000-embedded/README.md`, `engines/cortex-m7/a2lite/nam_a2lite.h`, and `weights/a2lite.namb`; the existing `firmware/work/nam-feasibility-estimate.json` preserves the arithmetic and source hashes.
- Official GT-1 parameter guide `firmware/work/reference/boss-docs/GT-1_parameter_eng02_W.pdf` (SHA-256 `02dd63985b9cfc9db0761c4438ef1471193616f5cb053381824c5445891e4565`): USB audio flow, `EFX OUT`, `USB IN`/`MIX LEVEL`, and `DIRECT MONITOR`.

## Reproduction

```sh
python3 -B firmware/work/scripts/reproduce_gt1_execution_domain_census.py
```

The script hash-checks the v1.08 image, decoded application, startup-copied segment, and callback manifest before printing bounded M-profile linear/direct-edge scans, CPACR/CPUID literal-search results, the ESC2 DSP window list, and conditional compute arithmetic. Its JSON output is `firmware/work/gt1-execution-domain-census.json`.

## Evidence limits

- The strict linear census covers 21.0% of the startup-copied segment; the narrow direct-edge walk covers 4.8% and is veneer-heavy. It omits conditional edges, indirect calls/branches, and table branches. The in-place code region at `0x60000000` and other copied segments were not exhaustively censused.
- The absence of exact CPACR/CPUID byte literals does not prove the application never configures an FPU or that a boot stage did not configure it.
- The 48 MHz `CKCPU` label is a board clock reference; the post-PLL core clock is not established.
- The DSP windows are observed constants and strings, not a proven physical memory map, ISA, or audio call path.
- No target benchmark was run. All cycle figures are upstream M7 references or arithmetic bounds, not GT-1 measurements.
