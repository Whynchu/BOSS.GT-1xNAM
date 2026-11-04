# Handoff: Route C — native NAM on the ESC2 DSP

**For:** Codex / next investigator  
**Date:** 2026-11-03  
**Decision:** Route C is the goal. Native NAM on the ESC2 DSP, replacing the PREAMP stage, keeping the rest of the GT-1 chain.  
**Current state:** offline reverse engineering only. No JTAG, no DSP program dump, no hardware modification. The user has USB/MIDI access only for now.

## Status update — DSP program-load reachability (2026-11-03, evening)

**New evidence, all four shipped versions.** Reproduction: `firmware/work/scripts/reproduce_gt1_dsp_load_reachability.py` → `firmware/work/gt1-dsp-load-reachability.json`. Inputs are the official packages (`static.roland.com/assets/media/zip/gt1_sys_v10{5,7,8,9}.zip`); all four `GT1ROM.BIN` hashes match the pins in this repository, so v1.08 is reproducible from the vendor even though the download page only advertises v1.09.

Two corrections and one result.

**Correction 1 — the helper addresses in earlier notes are not helper entries.** `0x60056BFE` is `mov r5,r0` inside the function that starts at `0x60056BF0`; `0x60056D06` is a `pop.w {…,pc}` at the end of a function. "Trace the callers of 0x60056BFE/0x60056D06" was not answerable as written.

**Correction 2 — the FA-08 loader does exist in GT-1, byte-for-byte in structure.** At v1.08:

| Element | Address | Structure |
|---|---|---|
| PRAM0/PRAM1 block transfer | `0x60057D08` | `addeq r0, 0x40150000, off*4` / `addne r0, 0x40170000, off*4`, `0x1000`-byte staging buffer at ctx+`0xC0C` — the `FUN_6000182E` analogue |
| 12-byte descriptor walkers | `0x600595CE`, `0x6005964C` | `ip = table + 12*index`, `[ip+4]` = length (words = `1 + len/4`), `[ip+8]` = source, copied to ctx+`0xC` — the `FUN_60003230` analogue |
| Loader entry | `0x600596AA` | calls the block transfer at `0x600596BE`, then writes the `0x50000`/`0x70000`-based command word to `0x40100000` |

**Result — that loader is dead code in the GT-1.** Across all four versions, the PRAM block-transfer function has exactly **one** external caller, and that caller's enclosing function has **zero** external incoming edges. No `bl`, `b`, `bcc`, `cbz`/`cbnz`, aligned pointer literal, or `movw`/`movt` address construction targets it. Verdict per version: `pram_load_path_reachable_only_from_entryless_functions`.

Supporting facts:

- Only **two** occurrences each of `0x40150000` and `0x40170000` exist in the whole decoded application — the `0x47DB0` window table and the transfer helper's own literal pair. There is no second PRAM implementation.
- The updater (`GT1Upd`, 173,176 bytes, identical in every version) contains **zero** DSP-window literals.
- The pattern is version-stable: transfer function at v105 `0x60057AAC`, v107 `0x60057CB4`, v108 `0x60057D08`, v109 `0x6005690C`; sole caller at `+0x133` of each.

**What is *not* dead — the parameter path.** The live `0x60058xxx` family builds `0x50000`/`0x70000` bank addresses with `moveq`/`movne`, ORs `0x20000000`, and writes through `0x40100000` — the `FUN_60002E10` command-register analogue — at 26 sites in v1.08. That is the SysEx/control route that carries patch data to DSP memory. The batch stager also selects the bank (`0x60093B44` `movhi r6,#0x70000` / `0x60093B48` `movls r6,#0x50000`). So the application *does* write DSP address space at runtime; it just never loads a program block.

**Interpretation.** The `CPrmESC2DT1` program-set concept survives as halt-gated error text (`0x6007D19B` "PRG Set without DSP Halt!", `0x6007D1CF` "DRP Set without DSP Halt") but those strings have no absolute-pointer reference in the image, consistent with a logging macro whose address is computed. Nothing in the reachable firmware writes a program block. That materially strengthens the mask-ROM hypothesis: the DSP's default program is supplied before or outside `GT1Appli`, and only parameter/data traffic reaches DSP memory from the application.

**Remaining limits.** Dispatch through the runtime-provided `0x02003xxx` service table is unresolved; RAM-resident function pointers are invisible; any boot stage outside `GT1Appli` (first-stage loader, mask ROM) is outside the input. Static absence is evidence of dead code in this image, not proof of runtime unreachability by every mechanism.


## TL;DR

- The GT-1 ARM CPU is an integer-only control core; it cannot host A2-Lite at the audio rate. The DSP is the only native audio-execution target.
- I decoded a second ESC2 application image from the FA-08 `ESC2 Firmware` member. It is **1,925,508 bytes**, SHA-256 `2e6a58ab96302131ab26936477e8d71734a65c2eac9685a1c6ec7b355ee959f1`, and it exposes a much richer DSP interface than the GT-1 app.
- The FA image contains an ESC2 event/name table naming `CM3D/I/S`, `PL080`, `HDMAC`, `DSP0…`, `DSPFO0…`, `BUDO0…`, `MACRO0…14`, `BREQ/DREQ`, `LRCKo0…7`, `TFPU`. That is strong evidence for a Cortex-M3 plus a multi-unit DSP subsystem, but it is **not** proof of the DSP ISA.
- I found and resolved the ARM-side DSP memory loader: `FUN_60003230`, a table walker over 12-byte `(DSP offset, byte length, ARM source)` entries. Its callers are `FUN_6001a2be`, `FUN_6000ff3c`, and `FUN_6004e07a`. The first confirmed entry loads **0x466 bytes** from FA file offset `0xDB2F8` to DSP address **`0x40170020` (PRAM1)**; the source is not ARM code, it is a structured 16-bit-word DSP payload candidate. The exact blob is absent from GT-1 v1.09, so GT-1 has its own payload.
- The FA startup only writes 4 bytes to `0x40008000`/`0x40045000` and zero-fills `0x1000` bytes at `0x40008004`. It does **not** load a full DSP program at reset. The program is loaded later, lives in mask ROM, or is generated from a macro table.
- Fastest decisive next step if hardware becomes available: read-only JTAG/SWD attach to the GT-1 `CN3` footprint (`TDI/TDO/TMS/TCK/TRST`, marked UnPop in the service notes), or the GT-100-style `JTAG for ESC2` connector. Until then, work the FA/GT-1 loader tables and the event map offline.

## Focused pass: what `FUN_60003230` actually transfers (confirmed 2026-11-03)

**Inputs and address convention.** All runtime addresses below are in the decoded FA-08 v2.03 image `firmware/work/decoded/fa08-ESC2-decoded.bin` (size 1,925,508 bytes, SHA-256 `2e6a58ab96302131ab26936477e8d71734a65c2eac9685a1c6ec7b355ee959f1`). The project maps that decoded output at runtime base `0x60000000`; file offset = runtime address − `0x60000000`. That is a project mapping supported by the copy descriptors, not a proof of physical memory.

### `FUN_60003230` calling convention (runtime `0x60003230`)

The full disassembly shows:

- `r0` = context pointer (saved in `r5`).
- `r1` = bank selector (saved in `r7`).
- `r2` = descriptor count (read from `[sp,#0x28]`, the saved `r2`).
- `r3` = descriptor table pointer (read from `[sp,#0x2c]`, the saved `r3`).
- **The 5th stack argument at `[sp,#0x30]` is never read by this function.** The call sites pass a pointer there, but the callee ignores it. This resolves the 5th-argument question for `FUN_60003230`; it does not rule out that the callers use that pointer elsewhere.

Stack proof: after `push {r0,r1,r2,r3}` and `push {r1,r2,r3,r4,r5,r6,r7,lr}`, saved `r0/r1/r2/r3` are at `[sp+0x20/0x24/0x28/0x2c]`; the function reads only `[sp+0x28]` and `[sp+0x2c]`.

### Descriptor format

Each entry is 12 bytes:

| Offset | Meaning | Evidence |
|---:|---|---|
| `+0x0` | DSP destination offset in **words**; the transfer uses `field0 >> 2` | passed as `r2` to `FUN_6000182E` at `0x600032b2`; `FUN_6000182E` computes `0x40150000 + (r2*4)` at `0x60001878` |
| `+0x4` | byte length | passed as `r3`; `FUN_6000182E` splits it into 16-byte blocks (`r6 = r3 >> 4`) plus remainder (`r0 = r3 & 0xf`) at `0x60001840–0x60001846`; the 0x466-byte source and the 2-byte second entry match this directly |
| `+0x8` | ARM-side source buffer pointer | saved/zeroed/restored at `0x60003290`, `0x6000329e–0x600032a0`, `0x600032d8`; passed as the 5th arg to `FUN_6000182E` at `0x600032ae` |

The loader calls `FUN_60002E10(ctx, bank, field0, 2, 0)`, `FUN_600031EA(ctx, 0)`, then `FUN_6000182E(ctx, bank, field0 >> 2, field1, field2)`, then restores the saved word.

### What the helper functions do

- `FUN_60002E10` (`0x60002e10`) is a **DSP command/data register write**, not a general memory write. It selects base `0x50000` (bank 0) or `0x70000` (bank != 0), adds the offset in `r2`, ORs a width tag `r3 << 28`, writes the command word to `0x40100000` (`ldr r6,[pc,#0x184]`; `str r5,[r6]`), then writes the payload to `0x40100004` with a width-dependent shift.
- `FUN_6000182E` (`0x6000182e`) is the **ARM↔DSP block transfer**. It loads the literal at `0x60001C70` (value `0x40150000`; the alternate path at `0x60001890` uses `0x40170000`), adds `r2*4`, uses `r3` as the byte length, and uses the 5th argument as the ARM source buffer. It splits the length into 16-byte blocks plus a remainder, chunks the transfer, and calls `0x600042CC` for the actual block operation. The destination base is therefore the DSP window at `0x40150000` (or `0x40170000` on the alternate path), not an arbitrary ARM address.
  - Instruction anchors: `0x60001876 ldr r0,[pc,#0x3f8]` reads `0x60001C70` = `0x40150000`; `0x60001890 ldr r0,[pc,#0x3e0]` reads `0x60001C74` = `0x40170000`; `0x60001872 ldr r0,[sp,#0x18]` reads the saved `r6` (the source's first word).

### First confirmed descriptor table

The `A35C` structure at runtime `0x60086670` is `{count = 2, table = 0x600db764}`. The table at FA file offset `0xDB764` is:

```
0xDB764: 20 00 00 00  66 04 00 00  F8 B2 0D 60
0xDB770: 86 04 00 00  02 00 00 00  60 B7 0D 60
```

Confirmed interpretation:

| Entry | `field0` | `field1` | `field2` | Computed DSP destination | Length | Source |
|---:|---:|---:|---|---:|---:|---|
| 0 | `0x20` | `0x466` | `0x600DB2F8` (file `0xDB2F8`) | source first word `0x0C030FE0` is nonzero → PRAM1 base: `0x40170000 + (0x20>>2)*4` = **`0x40170020`** | `0x466` bytes | FA file `0xDB2F8`, SHA-256 `0c089fc1ada2a57b43aed5d29ea64c220b6f70aebf200b100a8971363079443f` |
| 1 | `0x486` | `0x2` | `0x600DB760` (file `0xDB760`) | source first word `0x00000000` is zero → PRAM0 base: `0x40150000 + (0x486>>2)*4` = **`0x40150484`** | 2 bytes | FA file `0xDB760`, first two bytes `00 00` |

The PRAM0/PRAM1 selection is encoded in the **first word of the source buffer**, not in the descriptor. `FUN_60003230` loads that word into `r6` at `0x60003290`, then calls `FUN_6000182E`; the callee saves `r6` at `[sp+0x18]` and branches on it at `0x60001872`. If `r6 == 0`, the base literal is `0x40150000` (PRAM0); if nonzero, the alternate literal at `0x60001C74` is `0x40170000` (PRAM1). This is why the 0x466-byte payload lands in PRAM1 and the 2-byte zero patch lands in PRAM0.

The 0x466-byte source at `0xDB2F8` has entropy 5.499 bits/byte. It does **not** decode coherently as ARM or Thumb: the first 0x60 bytes produce 27 Thumb instructions with nonsensical semantics and zero ARM instructions. It is a structured 16-bit-word payload, consistent with DSP microcode or DSP coefficient/data tables. This is a **DSP-domain payload candidate**, not a confirmed DSP program until the DSP ISA is known.

The same 0x466-byte blob is **not present** in the GT-1 v1.09 decoded app: exact searches for the full blob and for its first 32/64/128 bytes return zero hits. The FA payload is therefore FA-specific; GT-1 must have its own payload.

### Other loader tables

- `FUN_6000ff3c` uses structures at `0x600786d4` / `0x600786e0`; the first-level tables at `0x600ca754` / `0x600ca8b0` currently look like ARM-side data/coefficient descriptors, not obviously DSP PRAM loads. They need the same field-by-field treatment before being classified.
- `FUN_6004e07a` uses a runtime table at `[param1 + param2*0x34 + 8]`; its descriptor fields are `*puVar2`, `puVar2[1]`, and the destination pointer at `+8`. It is not a static table and needs a runtime caller/parameter trace.

### Unresolved questions after this pass

1. Are `0x40150020` / `0x40170020` real DSP PRAM addresses, or offsets into command/register windows? The base literals (`0x40150000`, `0x40170000`) and arithmetic support a DSP-window interpretation; the physical DSP memory map is still undocumented.
2. What is the DSP instruction encoding in the 0x466-byte blob? It is not ARM, but it is not yet decoded as DSP code.
3. Where is the GT-1 equivalent descriptor table and payload? The GT-1 has helpers at `0x60056D06` / `0x60056BFE`, but no confirmed table/blob yet.
4. Do the `FUN_6000ff3c` tables load additional DSP code, or are they ARM-side coefficient copies? The current first-level entries are ambiguous.
5. Is the byte-length interpretation exact for all entries, including the 2-byte entry and the chunked 0x200-byte loop in `FUN_6000182E`? The first entry is consistent; the full chunking loop has not been exhaustively simulated.

### Next actions

1. Run the same Ghidra caller/table trace on the GT-1 v1.09 decoded app, targeting `0x60056BFE` / `0x60056D06`, and resolve its descriptor tables.
2. Decode the FA `0xDB2F8` blob as 16-bit/32-bit field streams; look for opcode regularity and a header/vector pattern.
3. Classify every `FUN_60003230` caller table by destination: DSP window (`0x4015xxxx`/`0x4017xxxx`) vs. ARM memory. Do not call a transfer a DSP program load merely because a destination field looks like a DSP window.
4. If the GT-1 payload is located, compare its descriptor table and payload structure with FA `0xDB764` / `0xDB2F8`.

## What is solid

### GT-1 side

- **Device confirmation via Test Mode (2026-11-03):** the connected unit's `1. VERSION` screen reads `1.08 (10D59B9B) 0082`. Those are the v1.08 application-header fields, not a DSP version:
  - `1.08` at file offset `0x40020` (header `+0x20`).
  - `10D59B9B` at file offset `0x4001C` (header `+0x1C`), stored big-endian as bytes `10 D5 9B 9B`.
  - `0082` at file offset `0x40024` (header `+0x24`).
  - The same values are present in the local v1.08 `GT1ROM.BIN` (SHA-256 `7219679a87e985316264544423c9940ccbcbadeb2df0b2f13711ae57194cb612`), so the device is running the local v1.08 build. The header build stamp at `+0x10` is `180313073852` (2018-03-13 07:38:52), consistent with the March 2018 v1.08 release.
  - For comparison, v1.09's app header reads `1.09 (CBA3673B) 0000` with build stamp `210610153839`. `10D59B9B` is a header SUM/build ID, not an ESC2/DSP firmware version.
- The GT-1 v1.09 app is decodable/re-encodable in its LZ format; an offline no-op repack round-trips byte-for-byte. This is for the later integration phase, not the DSP reverse engineering.
- The recovered GT-1 app code segment is integer-only ARMv7-M/Thumb-2: 0 VFP/NEON, 0 Armv7E-M DSP instructions, no CPACR literal. The CPU is not an A2-Lite target.
- The GT-1 app has DSP transfer helpers at `0x60056D06` (register/address write) and `0x60056BFE` (block transfer to DSP windows). These are analogous to the FA helpers below.
- The GT-1 app has an ESC2 DSP window table at `0x467B0`: `0x40100000`, `0x40100600`, `0x40140000`, `0x40144000`, `0x4014E000`, `0x40150000`, `0x40160000`, `0x40164000`, `0x4016E000`, `0x40170000`.
- Related strings: `CPrmESC2DT1 Error: PRG Set without DSP Halt!`, `DRP Set without DSP Halt`, `NG (IRAM0)`, `NG (PRAM0)`, `NG (IRAM1)`, `NG (PRAM1)`.

### FA-08 ESC2 side

The FA-08 `fantom_e_up.bin` (member SHA-256 `900028695b7ec1b63631737d1bd0eaf4707514264a7b325914d951cb59731d23`) has:

- outer header at `0x2000`, marker `ESC2 Firmware`;
- stored payload at `0x2044`, length `0xC4C6A` (805,994), checksum `0x05C69C40`;
- expanded length `0x1D6184` (1,925,508);
- same control-bit LZ routine as the GT-1 loader;
- decoded artifact: `firmware/work/decoded/fa08-ESC2-decoded.bin`;
- manifest: `firmware/work/fa08-esc2-decoded-manifest.json`.

The decoded FA image:

- starts with the same ARM startup stub as the GT-1 app (`4f f0 08 00 80 f3 11 88 …`);
- has a Cortex-M3-style vector table at `0x34` (initial SP `0x01011220`, reset `0x0100031D`);
- copies `0xB5A4` bytes to `0x01000300` from `0x601CAB28` (46 KB code segment);
- writes 4 bytes to `0x40008000` and `0x40045000`, then zero-fills `0x1000` bytes at `0x40008004`;
- contains a hardware event/name table around `0xC5640–0xC6030`:
  - `CM3D`, `CM3I`, `CM3S`
  - `PL080_1`, `PL080_2`, `ACT_PL080_1`, `ACT_PL080_2`
  - `HDMAC`, `ACT_HDMAC`
  - `DSP0…`, `DSPFO0…DSPFO5`, `BUDO0…BUDO5`
  - `MACRO0…MACRO14`
  - `BREQ0…BREQ7`, `DREQ3…DREQ7`
  - `LRCKo0…LRCKo7`
  - `TFPU`, `TFPU_LE`, `TFPU_ACK`, `TFPU_BUSY`, `FPUACK`
  - other blocks: `PTIMER`, `PxCLK`, `LCD`, `LCDD`, `USBD`, `USBH`, `EHCI_SOF`, `OHCI_SOF`, `SCKo`, `TXD`, `RXD`, `MCS`, `ASCPPInt`.
- contains `CDSPIF::change_dramio_rw_adrs()` at `0x601D2CB8`, plus `dramio_rw_adrs()` references;
- contains low-level DSP helpers:
  - `FUN_60001C08`: build `0x50000`/`0x70000` DSP address, OR `0x60000000`, write command register, read data register.
  - `FUN_6000182E`: block transfer into DSP program/data windows.
  - `FUN_60001728`, `FUN_60001DBE`: copy/transfer helpers.
  - `FUN_60003230`: descriptor-driven loader.
- Ghidra call graph for `FUN_60003230`:
  - `FUN_6001a2be` calls it at `0x6001a2ea` and `0x6001a312`.
  - `FUN_6000ff3c` calls it at `0x6000ff62` and `0x6000ff8a`.
  - `FUN_6004e07a` calls it at `0x6004e0a6`.
  - The decompile shows `for i < count: size = table[i*12]; src = table[i*12+4]; dst = table[i*12+8]`, then a block transfer.
  - Call sites load a `{count, table_ptr}` pair with `ldm r0!, {r2,r3}`; the 5th stack argument is a third value from the same structure. The first tables I resolved (`0x60086670`, `0x6008667c`, `0x60085090`, etc.) contain sizes and ARM-side addresses, and their `src` fields sometimes look like offsets (0x2, 0x466, 0x80) rather than pointers. **Do not assume these are the DSP program tables.** The next step is to resolve the 5th argument/base and trace the actual callers.

## What I think

1. **ESC2 is a heterogeneous SoC.** The event table names are consistent with a Cortex-M3 (`CM3D/I/S`), an ARM PL080 DMA, a second HDMAC, and a multi-unit DSP fabric (`DSP*`, `DSPFO*`, `BUDO*`, `MACRO0…14`, `BREQ/DREQ`). The `MACRO` units are the most interesting: if they are parallel MAC/macro cells, NAM's conv1d layers could map reasonably; if they are fixed audio microcode slots, they may not.
2. **The DSP program is not loaded at reset in the FA image.** The startup only touches the `0x40008000` window. The program is either loaded later by `CDSPIF`/the descriptor loader, stored in mask ROM, or built from a macro/config table. This is the central unknown.
3. **The FA image is a better Rosetta stone than the GT-1 app.** It has a richer DSP/event map and a clearer C++ `CDSPIF` layer. Use it to recover the register map and loader contract, then map that back to the GT-1's `0x60056D06`/`0x60056BFE` helpers.
4. **The 12-byte loader entries are now resolved.** The first A35C table loads a 0x466-byte DSP payload from FA file `0xDB2F8` to PRAM1 `0x40170020`, plus a 2-byte zero patch to PRAM0 `0x40150484`. The format is `(DSP offset, byte length, ARM source)`; the source's first word selects PRAM1 (nonzero) vs PRAM0 (zero). The remaining uncertainty is whether `0x4017xxxx` is genuinely DSP program RAM and what the payload's instruction encoding is.
5. **Hardware is the fastest way to settle the ISA.** A read-only JTAG/SWD chain scan on `CN3` (or the GT-100-style `JTAG for ESC2`) could tell us whether the DSP is on the scan chain and, if so, dump its program memory. The service notes mark the GT-1 connector UnPop, so this needs board inspection and an explicit safe procedure. Do not halt the audio core casually.
6. **Expect a real chance of a no-go.** The DSP may be fixed-function or mask-ROM microcoded; NAM may not fit the macro model; numeric format/accuracy and real-time budget are unknown. That is still a valid research outcome.

## Top three next moves for Codex

### 1. Finish the FA loader trace

- Re-disassemble `FUN_6001a2be` / `FUN_6000ff3c` / `FUN_6004e07a` at the raw instruction level, not just the decompiler.
- Resolve the 5th stack argument and the `{count, table_ptr}` structure. Determine whether the table `src` fields are absolute pointers, offsets from a base, or something else.
- Follow `FUN_6000334A`, `FUN_60003478`, `FUN_60003532`, `FUN_6000381A`, `FUN_60003A2E`, `FUN_60003B26` (the related loaders/consumers).
- Look for a table whose `dst` values are in the DSP windows (`0x40150000`/`0x40170000`/`0x4014E000`/`0x4016E000`), not ARM addresses. That is the DSP program/data candidate.

### 2. Parse the FA event/name table into a register map

- The table is at `0xC5640–0xC6030` in the decoded FA image.
- Entries look like `<bit/index>:<name>` and may be a debug/trace event selector.
- Map the `DSP*`/`DSPFO*`/`BUDO*`/`MACRO*`/`BREQ*`/`DREQ*`/`LRCKo*`/`TFPU*` entries to their surrounding data structures and any adjacent 32-bit addresses. This may reveal the DSP register file and the macro/instruction model.
- Find the code that consumes the table (search for references to `0x600C56D7` etc.; the Ghidra probe found none yet because the table may be referenced by a base pointer plus index).

### 3. Search for the DSP program blob and the mask-ROM hypothesis

- Search the FA and GT-1 decoded images for large 32-bit-word blocks with a small opcode vocabulary, regular field structure, and low ASCII content. A DSP program should look different from presets/graphics.
- Check whether any data is referenced by `FUN_6000182E`/`FUN_60001DBE` with a destination in `0x4015xxxx`/`0x4017xxxx`.
- If no blob exists, record the mask-ROM hypothesis and move the next decisive step to hardware/JTAG or primary documentation.

## Hardware plan when access exists

1. **Board inspection:** confirm whether `CN3` / JTAG pads are populated on the actual GT-1 main board; photograph and trace the nets. The service notes mark the connector UnPop.
2. **Read-only JTAG/SWD scan:** use a probe that can enumerate the chain without halting the audio core. Record IDCODEs and core types. Do not attach a generic probe blindly.
3. **Serial-flash readback:** a SOIC-8 clip/programmer gives a full, non-invasive image; compare with the official v1.08/v1.09 files. This confirms the device image but not mask-ROM DSP code.
4. **Logic analyzer:** capture codec `LRCK`/`BCLK`/`SDATA` and DSP control/status lines to establish the audio contract and transaction timing.
5. **Only then:** consider a controlled DSP program read or a reversible test. BOSS warns interrupted updates can require service; there is no documented recovery partition.

## Artifacts and commands

- Decoded FA image: `firmware/work/decoded/fa08-ESC2-decoded.bin`
- Manifest: `firmware/work/fa08-esc2-decoded-manifest.json`
- Ghidra report: `firmware/work/ghidra-fa08-dsp-interface.txt` (3,218 lines; 13 functions, decompiles included)
- Ghidra project: `firmware/work/ghidra-projects/FA08_ESC2_DSP.gpr`
- Ghidra scripts: `tools/ghidra_scripts/FA08DspInterfaceProbe.java`, `tools/ghidra_scripts/SetThumbContext.java`
- Route C plan: `docs/GT1-DSP-NAM-REVERSE-ENGINEERING-PLAN.md`
- CPU/DSP census: `firmware/work/gt1-execution-domain-census.json`
- GT-1 repack: `firmware/work/scripts/reproduce_gt1_app_repack.py` (later integration phase)

Ghidra analysis command used:

```sh
export JAVA_HOME="$PWD/tools/jdk25/usr/lib/jvm/java-25-openjdk-amd64"
export PATH="$JAVA_HOME/bin:$PATH"
export LD_LIBRARY_PATH="/usr/lib/jvm/java-25-openjdk-amd64/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
tools/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless \
  firmware/work/ghidra-projects FA08_ESC2_DSP \
  -import firmware/work/decoded/fa08-ESC2-decoded.bin -overwrite \
  -loader BinaryLoader -loader-baseAddr 60000000 \
  -processor ARM:LE:32:v7 \
  -scriptPath tools/ghidra_scripts \
  -preScript SetThumbContext.java \
  -postScript FA08DspInterfaceProbe.java \
  -analysisTimeoutPerFile 600
```

## Key limits

- The FA image is the FA-08 ESC2 application, not the GT-1 DSP microcode.
- The event names are a working map, not a datasheet.
- The `FUN_60003230` table analysis is a lead, not a confirmed DSP program load.
- No target DSP benchmark exists.
- No hardware attach has been performed.
- The user has USB/MIDI only for now, so hardware steps are deferred.
