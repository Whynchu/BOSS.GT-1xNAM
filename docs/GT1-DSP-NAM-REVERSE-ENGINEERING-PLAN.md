# Route C: native NAM on the ESC2 DSP

**Goal:** run NAM (or a NAM-compatible model) on the GT-1's ESC2 DSP, replace the PREAMP stage, and keep the rest of the GT-1 effect chain and control surface.

**Status:** active research plan; offline evidence only, no DSP program dump or hardware attach yet.  
**Date:** 2026-11-03.  
**Why Route C:** the recovered ARM CPU is an integer-only control core and cannot run A2-Lite at the audio rate; the DSP is the only plausible native audio-execution domain. Route C is therefore the only native path, and it is a reverse-engineering/porting program, not a firmware patch.

**Handoff:** `docs/HANDOFF-DSP-ROUTE-C.md` is the self-contained evidence/leads snapshot for the next investigator.

## The four gates

| Gate | Question | Exit evidence |
|---|---|---|
| 1. DSP core/ISA | What executes the audio algorithms, and what is its instruction set? | A documented core identity plus an instruction encoding/assembler, or a recovered DSP program that can be decoded and emulated. |
| 2. Program load + audio contract | How is DSP code/data loaded, and how does audio reach it every sample? | A traced boot/runtime load path, DSP memory map, audio buffer/callback contract, and the PREAMP stage boundary. |
| 3. Numeric/performance model | Can the DSP do the NAM arithmetic in real time? | MAC/ALU width, clock, memory bandwidth, cycles per NAM block, and a target benchmark or cycle-accurate emulator result. |
| 4. NAM port + integration | Can a NAM-compatible model run at the PREAMP point without breaking the rest of the chain? | A working DSP NAM kernel with acceptable error, real-time margin, model load/switch behavior, and a reversible integration plan. |

Do not advance a gate on a plausible-looking address or a successful host build. Each gate needs a reproducible artifact.

## What the FA-08 ESC2 firmware adds

The FA-08 package's `fantom_e_up.bin` has an `ESC2 Firmware` header at `0x2000` and a stored payload at `0x2044` (805,994 bytes, checksum `0x05C69C40`). It decodes with the **same control-bit LZ routine** as the GT-1 loader:

- decoded size: **1,925,508 bytes**
- SHA-256: `2e6a58ab96302131ab26936477e8d71734a65c2eac9685a1c6ec7b355ee959f1`
- first bytes are the same ARM startup stub as the GT-1 app (`4f f0 08 00 80 f3 11 88 …`)
- persists locally at `firmware/work/decoded/fa08-ESC2-decoded.bin`

This is a second, richer ESC2 application image with an explicit DSP interface. It is **not** the GT-1 DSP microcode, but it exposes the same class of hardware interface and gives us a much better map of the ESC2 SoC.

### ESC2 block map from the FA image's event/name table

The decoded image contains a table of hardware event names around `0xC5640–0xC6030`, including:

```
CM3D  CM3I  CM3S
PL080_1  PL080_2  ACT_PL080_1  ACT_PL080_2
HDMAC  ACT_HDMAC
DSP0  DSP1  ...
DSPFO0 ... DSPFO5
BUDO0 ... BUDO5
MACRO0 ... MACRO14
BREQ0 ... BREQ7
DREQ3 ... DREQ7
LRCKo0 ... LRCKo7
TFPU  TFPU_LE  TFPU_ACK  TFPU_BUSY  FPUACK
```

Interpretation as a working hypothesis, not a settled fact:

- `CM3D/I/S` is a Cortex-M3 with separate data/instruction/system bus views. The ARM side is confirmed.
- `PL080` is an ARM PrimeCell DMA controller; `HDMAC` is a second DMA engine.
- `DSP0…`, `DSPFO…`, `BUDO…`, `MACRO0…14`, `BREQ/DREQ`, `LRCKo0…7` indicate a **multi-unit DSP subsystem** rather than a single scalar DSP. The `MACRO` units are especially interesting: if they are parallel MAC/macro cells, NAM's conv1d layers could map well; if they are fixed microcode slots, they may not.
- `TFPU`/`FPUACK` may be a floating-point or shared FPU handshake block. This is potentially decisive for NAM's numeric format, but the naming is not yet proof of an IEEE float unit.
- `LRCKo0…7` suggests eight audio word-clock/slot domains, consistent with a multichannel audio fabric.

### DSP interface code in the FA image

The FA image contains a C++-style `CDSPIF` interface and low-level helpers:

- `0x60001C08`: builds a `0x50000` or `0x70000` DSP address, ORs a `0x60000000` tag, writes it to a command register, then reads a data register.
- `0x6000182E`: block transfer into DSP program/data windows (`0x40150000`/`0x40170000` style).
- `0x60003230`: a descriptor-driven loader. It walks 12-byte `(DSP offset, byte length, ARM source)` entries and calls the block-transfer helper. The first confirmed A35C table entry loads 0x466 bytes from FA file `0xDB2F8` to PRAM1 `0x40170020`; the source's first word selects PRAM1 vs PRAM0. See the focused section in `docs/HANDOFF-DSP-ROUTE-C.md`.
- `CDSPIF::change_dramio_rw_adrs()` and `dramio_rw_adrs()` strings show that the ARM can change DSP DRAM read/write addresses at runtime.
- The FA startup only writes 4 bytes to `0x40008000`/`0x40045000` and zero-fills `0x1000` bytes at `0x40008004`; it does **not** load a full DSP program at reset. The program is loaded later, lives in mask ROM, or is generated from a macro table.

The GT-1 app has analogous helpers at `0x60056D06`/`0x60056BFE`, so the basic DSP interface is shared across products. The FA image is useful because it has a richer DSP/event map and a clearer `CDSPIF` layer.

## Stage plan

### Stage 1 — Recover the DSP interface and loader (offline, next)

1. The FA `0x60003230` descriptor format and first transfer are now resolved (see the handoff). Next: classify the remaining FA tables and run the same trace on the GT-1 equivalents (`0x60056BFE`/`0x60056D06`) to find the GT-1 DSP payload.
2. Parse the FA event/name table and map the `DSP*`/`MACRO*`/`DSPFO*`/`BUDO*` units to registers and interrupts.
3. Locate any DSP program/data blob referenced by the loader. Check whether it is in the app image, in the FA `ESC2 Firmware` data, or absent (mask ROM).
4. Recover the audio callback/contract: which IRQ/timer/DMA drives the DSP, the buffer format, and the PREAMP dispatch.

**Exit:** a call graph from the ARM DSP interface to the DSP program load and the audio path, with concrete addresses, tables, and hashes. If the program is not in the image, record that and move to hardware.

### Stage 2 — Get the DSP program and ISA

Preferred order:

1. **JTAG/SWD read-only attach.** The GT-1 service notes show an unpopulated `TO JTAG BOARD` connector (`CN3`, TDI/TDO/TMS/TCK/TRST) and the GT-100 service notes label a `JTAG for ESC2` connector. A read-only chain scan can identify whether the DSP is on the scan chain and, if accessible, dump its program memory. Do not halt the audio core without a safe procedure.
2. **Serial-flash readback.** The 32-Mbit serial flash contains the firmware image; a SOIC-8 clip/programmer gives a full, non-invasive readback. This confirms the device image but not mask-ROM DSP code.
3. **Logic-analyzer capture.** Capture codec `LRCK`/`BCLK`/`SDATA` and any DSP bus/control lines to establish the audio contract and the DSP transaction timing. This does not reveal the ISA by itself.
4. **Primary documentation/patents.** Search for `MB8AA4181`, `ESC2`, and the `MACRO`/`DSPFO`/`BUDO` terminology in Fujitsu/Roland patents and service documentation. The event names are distinctive enough to be searchable.
5. **Donor/decapped chip.** Only if the above fail; a decap/die shot could reveal the DSP core, but it is destructive and expensive.

**Exit:** a DSP program image or a credible ISA description. Without this, Stage 3 cannot start.

### Stage 3 — Reverse the ISA and build an emulator

1. Identify instruction width, field layout, register file, memory spaces (PRAM/IRAM/DRAM), and the macro/DSPFO/BUDO control model.
2. Build a disassembler/assembler and a small emulator for the recovered program.
3. Validate the emulator against known DSP output or a hardware trace.

**Exit:** a working toolchain and a cycle/instruction model good enough to implement and benchmark a kernel.

### Stage 4 — Numeric/performance model

1. Establish fixed-point vs. floating-point, accumulator width, saturation, and rounding.
2. Measure or bound the DSP clock, MAC throughput, memory bandwidth, and audio deadline.
3. Estimate NAM A2-Lite's 1,871 weights / 23 layers against the DSP's MAC capacity and memory.

**Exit:** a defensible cycles-per-sample budget and a go/no-go on the NAM port.

### Stage 5 — Port NAM and integrate at PREAMP

1. Implement the NAM graph (conv1d layers, LeakyReLU, head) in the DSP ISA, or a numerically equivalent fixed-point/float variant.
2. Match the GT-1's 44.1 kHz audio contract (or add a DSP-side resampler).
3. Replace/route the PREAMP stage, preserve the rest of the chain, and define model load/switch/bypass behavior.
4. Validate output against the reference NAM engine and measure real-time margin.

**Exit:** a reproducible native NAM build that fits the DSP and the audio deadline, or a documented no-go.

## Hardware questions that decide the route

- Is the GT-1's `CN3` JTAG footprint populated on the actual board? The service notes mark it unpopulated; the GT-100 has a similar `JTAG for ESC2` footprint.
- Is the DSP on the JTAG scan chain, or only the Cortex-M3?
- Is the DSP program in mask ROM or loadable PRAM/DRAM? The `PRG Set`/`PRP`/`IRAM` transfer path suggests at least some program memory is writable, but the boot source is unknown.
- Do we have a read-only attach method that does not halt the audio core? If not, any JTAG work is a separate, explicitly authorized hardware experiment.

## Risks and honest expectations

- The DSP ISA may be undocumented and inaccessible; the event names are a lead, not a datasheet.
- The DSP may be fixed-function or microcoded in mask ROM; if so, a NAM port may require replacing ROM or a hardware insert, not a firmware update.
- The `MACRO0…14` units may be a good fit for conv1d, or they may be fixed audio macros that cannot express NAM. We do not know yet.
- Numeric format and accuracy are unresolved. Fixed-point NAM may need retraining/quantization and may not meet the reference error target.
- The real-time budget is unknown. Even a capable DSP may not have enough spare cycles while the rest of the GT-1 chain runs.
- The project is multi-month and may end in a documented no-go. That is still a valid outcome, but it should be treated as a research program, not a weekend patch.

## Immediate next actions

1. **Offline:** the FA `0x60003230` loader/table is resolved enough to identify a 0x466-byte payload at file `0xDB2F8` loaded to PRAM1 `0x40170020`. Next: repeat the trace for GT-1 `0x60056BFE`/`0x60056D06` and classify the remaining FA tables.
2. **Offline:** parse the FA event table and build an ESC2 block/register map.
3. **Offline:** search for the DSP program blob in the FA and GT-1 images; if absent, record the mask-ROM hypothesis.
4. **Hardware (needs authorization):** inspect the GT-1 board for `CN3`/JTAG pads, identify a safe read-only attach, and scan the chain. Do not halt the audio core or modify firmware as part of this step.
5. **Documentation:** search Fujitsu/Roland patents and service notes for `MB8AA4181`, `ESC2`, `MACRO`, `DSPFO`, `BUDO`, and `TFPU`.

## Reproduction assets

- `firmware/work/decoded/fa08-ESC2-decoded.bin` — decoded FA-08 ESC2 application image (SHA-256 `2e6a58ab…`).
- `firmware/work/fa08-esc2-decoded-manifest.json` — provenance and hashes.
- `firmware/work/scripts/reproduce_gt1_execution_domain_census.py` — GT-1 CPU/DSP-domain census.
- `firmware/work/scripts/reproduce_gt1_app_repack.py` — GT-1 container repack, for the later integration phase.
