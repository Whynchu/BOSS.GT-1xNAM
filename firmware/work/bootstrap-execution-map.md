# GT-1 bootstrap execution map

## Scope and reproduction

This read-only trace covers v1.09 file offsets `0x000000–0x001FFF`, imported as ARM Cortex Thumb using the candidate mapping `runtime = 0x00FFFFD0 + file_offset`. Input image SHA-256: `412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf`. Reproduce with `firmware/work/scripts/run_ghidra_esc91.sh`, `python3 firmware/work/scripts/reproduce_bootstrap_execution_map.py`, and `python3 firmware/work/scripts/reproduce_gt1_bootstrap_decoder_probe.py`. The decoder probe hashes and asserts all four preserved source images and emits bounded per-section statistics. Cross-version byte evidence is in `bootstrap-descriptor-cross-version.json`.

## Control flow and descriptors

| File offset | Runtime address | Evidence-based interpretation |
|---|---|---|
| `0x30` | `0x01000000` | Vector words: SP `0x01011240`; reset PC `0x01000AE5` (Thumb bit set). |
| `0xB14` | `0x01000AE4` | Loads `0x010002C1` from file `0xB2C` and branches to `0x010002C0`. |
| `0x2F0` | `0x010002C0` | Sets SP to `0x01028000`, calls `0x01000BB0`, then branches through the literal `0x010009F1`; under `runtime = 0x00FFFFD0 + file_offset` this enters file `0xA20` (runtime `0x010009F0`). |
| `0xBB0` | `0x01000B80` | Initializes hardware and returns to the trampoline, which then branches to `0x010009F0`. |
| `0xA20` | `0x010009F0` | Loader entry selected by the trampoline. Calls setup, invokes the validator at runtime `0x010009BC` (file `0x9EC`), then selects section base `0x03002000` or `0x03040000` and uses its header fields to call decoder entry `0x010008DA` (file `0x90A`) or take a copy path. The two selected bases equal `0x03000000 + file offsets 0x2000/0x40000`; both image locations contain the matching `GT1Upd`/`GT1Appli` headers. This is strong header-to-address mapping evidence, though it does not by itself prove those file bytes are copied to runtime at that base. |
| `0xBE0` | `0x01000C10` | A separate table walker exists at this address. Its start and end literals resolve to runtime `0x01000C64` and `0x01000C84`, mapping to file `0xC94–0xCB4`; it walks two 16-byte records and calls `0x010002C8`. Its reachability from the reset path is not established. |
| `0x2C8` | `0x010002F8` | Code in the first block at this address has not been established as the continuation of the table walker under the current linear file mapping; this branch target needs separate mapping evidence. |
| `0xC04` | `0x01000C34` | First descriptor callback target after translating runtime `0x01000BD4` through the candidate base: word copy loop. |
| `0xC14` | `0x01000C44` | Second descriptor callback target after translating runtime `0x01000BE4` through the candidate base: word fill loop. |

The candidate two descriptor records occupy runtime `0x01000C64–0x01000C84`, which maps to file `0xC94–0xCB4`. Each record is four little-endian words. The table walker at `0xBE0` invokes callbacks through `BLX`; descriptor callback values are runtime addresses, so translating them through the candidate base gives file offsets `0xC04` and `0xC14`:

| File offset | Source runtime | Destination runtime | Length | Callback |
|---|---:|---:|---:|---:|
| `0xC94` | `0x01000C84` | `0x01010000` | `0x28` | `0x01000BD4` |
| `0xCA4` | `0x01000CAC` | `0x01010028` | `0x1218` | `0x01000BE4` |

Because the candidate map is `0x00FFFFD0 + file_offset`, source runtime `0x01000C84` maps to file `0xCB4`; source `0x01000CAC` maps to file `0xCDC`. The first 40-byte source span contains structured values; the second 0x1218-byte source span is predominantly `0xFF` fill in the distributed image. The candidate callback offsets contain copy/fill-like instructions. This connection remains a register-flow interpretation until the routine reachability and address mapping are confirmed.

## Version comparison

Across GT-1 v1.05, v1.07, v1.08, and v1.09, bytes at `0xC94–0xCB4`, `0xCB4–0xCDC`, `0xCDC–0x1EF4`, and the candidate callback offsets are byte-identical. These are stable bootstrap data/code regions, but their role and reachability remain uncertain; no evidence links them to the later `GT1Upd`/`GT1Appli` sections. Same-offset KATANA comparison bytes are recorded separately; they do not establish KATANA semantics without tracing that product's callers.

## Corrected conclusions

- The loader calls runtime `0x010008DA`, which maps to file `0x90A`; that is the start of a bounded literal/back-reference routine using a 4 KiB ring buffer. File `0x8DA` is unrelated code under this mapping. The ring base is runtime `0x01010028`, mapping to file `0x10058` under the full-image candidate map, not outside the 4 MiB image. The ring is initialized by the routine before it is used.
- The loader's actual arguments are source=`header_base + [0x2C]`, destination=`[0x38]`, and output-end length=`[0x3C]`; the zero-`[0x3C]` path copies `[0x30]` bytes. In all GT-1 headers `[0x2C]=0x40`, `[0x30]` matches the stored payload size, `[0x34]` matches its additive checksum, `[0x38]=0x60000000`, and `[0x3C]` is the output-length candidate. The complete instruction-derived parser and bounded model are in `bootstrap-decoder-probe.json`, reproducible with `python3 firmware/work/scripts/reproduce_gt1_bootstrap_decoder_probe.py`.
- The v1.09 loader calls runtime `0x010002D4` with the selected header's `[0x28]` value (`0x60000000`). That address maps to file `0x304`, where the executed instructions are `ORR r0,r0,#1` (`0x304`) and `BX r0` (`0x308`), giving a static Thumb transfer to `0x60000001`. The loader validator scans up to four 8-byte records at runtime table pointer `0x01010028`, calls each nonzero callback, and compares its return with the record's first word. It returns 0 on mismatch or a missing callback and 1 after all visited records pass. The loader selects `GT1Upd` at section base `0x03002000` on return 1, and `GT1Appli` at `0x03040000` on return 0. Runtime table contents and validation meaning remain unknown; this does not prove which section is selected during normal operation.
- Both decoded outputs share bytes `0x000–0x0E7`. At output offset `0x7C`, startup loads the `+0x164` entry pointer and branches through `BX r0` at `0x7E`. The common stub calls a copy helper at `0x80` six times and a zero helper at `0x9E` seven times, using literal descriptors at `0xE4–0x164`. Source addresses are offsets into the decoded buffer based at `0x60000000`; the first copied segment has destination `0x01000300`. The selected `0x0100xxxx` entry pointer falls within this copied segment. Its first instructions load `0x01000000`, write it to an image-specific address from the literal pool, load SP through another pointer, and branch to a second entry inside a copied segment. That second entry begins with sustained plausible Thumb control flow for updater and application across all four releases. Copy maps, target bytes, disassembly, and hashes are in `bootstrap-handoff-evidence.json`, reproduced with `python3 firmware/work/scripts/reproduce_bootstrap_handoff.py` (Capstone Python binding required).
- A bounded Ghidra ARMv7/Thumb probe of v1.09 decoded app output at candidate base `0x60000000` remains in `ghidra-decoded-candidate.txt`; reproduce by importing `firmware/work/decoded/v109-GT1Appli.bin` with `ARM:LE:32:v7`, base `0x60000000`, Thumb context, and `tools/ghidra_scripts/GT1DecodedCandidate.java`. This import establishes the common loader-side startup stub, not the relocated segment's full ISA. The literal-derived destination map now justifies a separate Ghidra import at `0x01000300`, with the second entry seeded. Physical memory types behind `0x60000000`, `0x01000000`, and `0x20000000` and MB8AA4181 core identity remain unverified.
- If the descriptor tuple interpretation is correct, callback candidates at `0xC04` and `0xC14` lead to copy/fill loops; the call target mapping needs independent confirmation.
- The two-record table at file `0xC94` is populated. The validator's table pointer resolves to runtime `0x01010028`, which maps to file `0x10058` in the full image candidate mapping. It may be initialized/overwritten during startup; its file bytes are not asserted to be its runtime contents.
- The decoder outputs and the loader's destination/entry fields connect stored sections to startup code and relocated executable ranges. This establishes a static launch chain under the candidate mappings, not the physical memory map, normal runtime selector condition, or exact application ISA.
- The updater output is byte-identical across all four releases (173,176 bytes; SHA-256 `0f247f1b94c0c9ca8e4eef1ec980e2f060f95ef494ed7fa6bd9fbaf52d93a6a4`). Application output hashes: v1.05 `8297887084af48b04189955bbd8bdb4e0e6ff6a0e0fbcac7f85a175792775e29`, v1.07 `304b88a2c628cf47bb5091ecbc6da4fab4924f88cdea8897b44e5f474b9fb001`, v1.08 `c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1`, and v1.09 `2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29`. Per-section sizes and hashes are also in `bootstrap-decoder-probe.json`.

## Next experiment

The next check is to trace the application function-pointer dispatch at `0x600004A8` through its table and callees, then identify reachable audio initialization and processing paths. The combined Ghidra import now maps all nonempty startup copy descriptors; reports and command lines are in `ghidra-relocated-probe-run.md`. Keep the exact MB8AA4181 ISA and physical memory map unresolved until stronger evidence appears.

No device was accessed or modified.
