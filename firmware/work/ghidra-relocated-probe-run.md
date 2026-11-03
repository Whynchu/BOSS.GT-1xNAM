# Ghidra probe of GT-1 relocated entry segments

## Method and reproduction

The decoded startup's first copy descriptor at output offsets `0xE4`, `0xE8`, and `0xEC` defines the bytes imported at `0x01000300`. `python3 firmware/work/scripts/reconstruct_gt1_entry_segments.py` writes the bounded segment binaries and `firmware/work/reconstructed/entry-segments.json`; each source image and derived segment is SHA-256 checked. The imports use Ghidra 12.2, `ARM:LE:32:v7`, Thumb context, `-noanalysis`, and `GT1RelocatedSectionProbe.java` with explicit seeds. Run the reproducible wrapper:

```sh
firmware/work/scripts/run_ghidra_relocated_probe.sh \
  GT1_Relocated_v109_App \
  firmware/work/reconstructed/v109-GT1Appli-seg0.bin \
  "$PWD/firmware/work/ghidra-relocated-v109-app.txt" \
  0x010046f8 0x0100114e

firmware/work/scripts/run_ghidra_relocated_probe.sh \
  GT1_Relocated_v109_Updater \
  firmware/work/reconstructed/v109-GT1Upd-seg0.bin \
  "$PWD/firmware/work/ghidra-relocated-v109-updater.txt" \
  0x01003dc0 0x01000952

firmware/work/scripts/run_ghidra_relocated_probe.sh \
  GT1_Relocated_v108_App \
  firmware/work/reconstructed/v108-GT1Appli-seg0.bin \
  "$PWD/firmware/work/ghidra-relocated-v108-app.txt" \
  0x0100465c 0x010010ae
```

The wrapper sets Ghidra's binary loader base to `0x01000300`; the Java script marks Thumb context and disassembles from the segment start and provided entries. This is bounded static analysis, not an exact MB8AA4181 processor identification.

## Reproduced observations

- The v1.09 application second entry at `0x0100114E` begins with `PUSH {r4-r8,lr}`, calls two local veneers, then checks a result and iterates a table of function pointers via `BLX`. A helper at `0x01002144` uses `LDRD`, `UDIV`, and `MLS` while initializing a structure. The startup also enters a local branch loop at `0x01002A80` after calling `0x0100466E` and a veneer.
- The v1.08 application second entry at `0x010010AE` has the same broad Thumb call/table pattern and calls local veneers at `0x010083DE` and `0x010083D4`.
- The stable updater second entry at `0x01000952` begins with the same register-save pattern and iterates a callback table through `BLX`; its helper at `0x01001528` also contains `LDRD`, `UDIV`, and `MLS`.
- In the v1.09 application, veneers at `0x010082D0`, `0x010082DA`, `0x010082E4`, and `0x01008316` use `MOVW`/`MOVT` to form `0x60000205`, `0x6000028D`, `0x60000291`, and `0x600002AD`, then `BX r12`. Their targets fall within the preserved decoded application at base `0x60000000`. Equivalent updater veneers point into the updater output. This cross-reference supports a split runtime address view and explains why analysis of the copied segment alone stops at `0x600xxxxx` targets.

The `0x60000000` bytes are in the decoded image and the `0x01000300` bytes are reproduced from its copy descriptor. This supports the copy and branch chain. The physical backing, cache/alias behavior, permissions, exact CPU, and meaning of the `0x01000000` write remain unknown. These findings do not yet identify audio initialization or the amp-model dispatch path.

## Artifacts and hashes

| Report | Input segment SHA-256 | Report SHA-256 |
|---|---|---|
| v1.09 app | `019adcf28e4a12444d48699b0b2a386a1a5feb2e43b59d465c696ee42540b9f9` | `0275013f5aa32256b320e25ac6892daf22f1fe183ac2312f381f25d7c463cf11` |
| v1.09 updater | `04fb01186e6fda6c529bc609b61c87f53b95295789055df77369622169e8a44d` | `b7f2912b767dfb1995b12b33ae3a0e7da9aa211602768db8067a5c2e0411d3fc` |
| v1.08 app | `5691f04c08e52373973725ede20ff9de0bc3fc0e77a160e856a11342701168a0` | `62910df794b8ea4da029d3e72fe9f745984b08dd2db4d7e2628acd97c5348c90` |

The full instruction excerpts are in those report files. Source decoded-image hashes and offsets are in `entry-segments.json`.

## Combined address-space probe

A second v1.09 application import adds the full decoded output as a Ghidra memory block at `0x60000000` alongside the reconstructed first copy segment at `0x01000300`. Since Ghidra cannot infer the destination of `BX r12` from the veneer registers, seed targets computed from the veneer `MOVW`/`MOVT` instructions explicitly:

```sh
firmware/work/scripts/run_ghidra_combined_probe.sh \
  GT1_Combined_v109_App_Targets \
  firmware/work/reconstructed/v109-GT1Appli-seg0.bin \
  firmware/work/decoded/v109-GT1Appli.bin \
  "$PWD/firmware/work/ghidra-combined-v109-app-allcopies.txt" \
  0x010046f8 0x0100114e \
  0x60000204 0x6000028c 0x60000290 0x600002ac \
  0x6004fd44 0x6004fd12
```

The report SHA-256 is `c340d118bbb4ea495220cb0171d11b229de5c268961b8ee3cba02226485fe699`. Its decoded input SHA-256 is `2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29`; its copied segment SHA-256 is `019adcf28e4a12444d48699b0b2a386a1a5feb2e43b59d465c696ee42540b9f9`.

This resolves several targets statically: `0x010082D0` reaches `0x60000204`; `0x010082DA` reaches `0x6000028C`; `0x010082E4` reaches `0x60000290`; and `0x01008316` reaches `0x600002AC`. The code at `0x60000204` calls additional veneers back to `0x0100415A`, `0x01003C38`, and `0x01003C50`. These cross-region calls are reproducible code references. Ghidra still needs explicit seeds for the register-computed targets and cannot determine physical aliases or permissions from this static map.

The application second entry at `0x0100114E` calls into `0x6000028C`, which branches onward to `0x600004A8`; there it dispatches through several function pointers. That is a promising startup/dispatch lead, but its role is not yet identified as audio or effects processing. Follow these reachable paths and the data structures they use before assigning DSP semantics.

## Combined updater probe

The stable updater has also been imported with the decoded updater at `0x60000000`. Explicit seeds resolve its register-computed veneers:

```sh
firmware/work/scripts/run_ghidra_combined_probe.sh \
  GT1_Combined_v109_Updater_Targets \
  firmware/work/reconstructed/v109-GT1Upd-seg0.bin \
  firmware/work/decoded/v109-GT1Upd.bin \
  "$PWD/firmware/work/ghidra-combined-v109-updater-allcopies.txt" \
  0x01003dc0 0x01000952 \
  0x60003cf8 0x6001e914 0x60020c5a \
  0x60003d22 0x60003d00 0x6001ea54
```

The report SHA-256 is `af05e53fa7a0116a9f920ac5f6e38b1f8dd0ba6b8bffc83948f168015e3c5c67`. The decoded updater SHA-256 is `0f247f1b94c0c9ca8e4eef1ec980e2f060f95ef494ed7fa6bd9fbaf52d93a6a4`; the copied segment SHA-256 is `04fb01186e6fda6c529bc609b61c87f53b95295789055df77369622169e8a44d`.

This combined import also maps updater descriptor 1 from decoded offset `0x2A468` to `0x01006000` (length `0xE`). It confirms the updater uses veneers across the `0x0100xxxx` and `0x600xxxxx` ranges. Its traced entry contains a callback loop and the same `LDRD`/`UDIV`/`MLS` helper family seen in the app. The combined report is a bounded disassembly around explicit seeds; it does not yet identify audio processing. The app function at `0x600004A8` remains a function-pointer dispatch lead whose table and callees need tracing.

## Application import with every initialized copy range

The combined probe script now reads all six copy triples from the decoded startup literals. For v1.09 application it maps the nonempty destinations:

| Descriptor | Decoded source offset | Destination | Length |
|---|---:|---:|---:|
| 0 | `0x2BADEC` | `0x01000300` | `0x10FB2` |
| 1 | `0x2CBDA0` | `0x01011800` | `0x7B8` |
| 3 | `0x2CC558` | `0x20000000` | `0xD5C` |

Zero descriptors separately show cleared ranges beginning at `0x01011FB8`, `0x01020000`, `0x20000D5C`, and `0x602BADF0`, with lengths in the main evidence JSON. The last zero range is in the decoded image address view, so it must be treated as startup memory state; the static Ghidra import preserves the original decoded bytes for analysis.

Re-run the v1.09 application command above with the same seeds; the all-copy report SHA-256 is `c340d118bbb4ea495220cb0171d11b229de5c268961b8ee3cba02226485fe699`. It records the mapped descriptors at the report head. Destination names and physical memory types remain hypotheses; the copied contents and lengths are derived from startup instructions and literals.

## Unresolved application dispatch at `0x600004A8`

The v1.09 application startup branches from `0x6000028C` to `0x600004A8`. The code loads `0x020030B4` from a literal, then makes indirect calls through pointers stored at offsets `-0x5C`, `+0x58`, `+0x70`, and `+0x7C` from that base. Its final call passes `0x60260C9C` as an argument. The instruction sequence and constants are present in `ghidra-combined-v109-app-allcopies.txt`; they establish a callback dispatch but not its role. The base table at `0x020030B4` lies outside all currently mapped startup copy ranges, so its source and physical memory type remain unknown. Resolve this external table or trace how it is populated before classifying this path as audio/effect processing.
