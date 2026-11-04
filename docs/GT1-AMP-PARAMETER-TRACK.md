# GT-1 amp parameter track: new sounds on the stock DSP

**Status:** active investigation. Offline analysis plus reversible patch experiments. No firmware flashed, no hardware modified.
**Opened:** 2026-11-03.
**Relation to Route C:** this track does not attempt to run NAM. It targets the other realistic outcome — retuning and recombining the amp engine the GT-1 already ships, so that new voicings become possible without an ISA, a DSP program dump, or a hardware mod.

## Why this direction

Route C (native NAM on the ESC2 DSP) is blocked by evidence gathered on the same day: the FA-08-style program loader exists in the GT-1 application but is unreachable in v105/v107/v108/v109 (`docs/HANDOFF-DSP-ROUTE-C.md`, `firmware/work/gt1-dsp-load-reachability.json`), and the live application-to-DSP traffic is parameter/data only. That makes the DSP a fixed program with a rich, host-driven parameter surface — which is exactly the surface this track exploits.

The practical claim under test:

> **The GT-1's amp voicing is data, not code.** Each preamp slot carries a full amp+cab parameter set in the patch, and the DSP evaluates a shared parametric engine against it. If that holds, new amps can be produced by new parameter data, not new DSP code.

## The parameter surface

From the community editor mapping in `firmware/work/amp-control-lead-evidence.json` (source-evidenced, not yet validated on hardware), each preamp slot has 30 fields:

| Group | Fields |
|---|---|
| Core | `type`, `gain`, `level`, `gain_sw`, `solo_sw`, `solo_level` |
| Voicing | `bright`, `t_comp`, `bass`, `middle`, `treble`, `presence` |
| Cabinet | `sp_type`, `sp_cabinet`, `sp_num`, `sp_size`, `sp_color_low`, `sp_color_high` |
| Mic | `mic_type`, `mic_dis`, `mic_pos`, `mic_level`, `direct_mix` |
| Custom | `custom_type`, `custom_char`, `custom_bottom`, `custom_edge`, `custom_preamp_low`, `custom_preamp_high` |

Working interpretation, not established fact: a shared signal path — input trim, gain stage with compression/brightness, voicing network driven by `char`/`edge`/`bottom`/`preamp_low`/`preamp_high`, a four-band tone stack, a speaker/cabinet model driven by `sp_*`, a mic model driven by `mic_*`, then `direct_mix` and `level`. A named TYPE would then be a preset over that surface, and `CUSTOM` the mode that exposes it directly.

## Confirmed field map

`reproduce_gt1_amp_field_map.py` tests the hypothesis that the preamp slot occupies 32 bytes at record+`0x2B`, in the community editor's byte order, including the two bytes that map skips. Result over **246 populated records: 0 invariant violations.** Every editor default that a factory bank would not vary — `mic_level 100`, `custom_bottom/edge/char/preamp_low/preamp_high 50`, `sp_size 7`, `sp_color_low/high 10`, `sp_num 2`, `sp_cabinet 0` — holds byte-for-byte in all 246. The field identity is therefore established structurally, not just by resemblance.

| Record offset | Field | Range across 246 |
|---|---|---|
| `+0x2B` | `preamp_a_on_off` | 0–1 |
| `+0x2C` | **`preamp_a_type`** | **0–26** |
| `+0x2D` | `gain` | 10–120 |
| `+0x2E` | `t_comp` | constant 10 |
| `+0x2F` | `bass` | 13–92 |
| `+0x30` | `middle` | 7–87 |
| `+0x31` | `treble` | 0–80 |
| `+0x32` | `presence` | 0–100 |
| `+0x33` | `level` | 27–90 |
| `+0x34` | `bright` | 0–1 |
| `+0x35` | `gain_sw` | 1–2 |
| `+0x36` | `solo_sw` | 0–1 |
| `+0x37` | `solo_level` | 20–80 |
| `+0x38` | `sp_type` | 1–7 |
| `+0x39` | `mic_type` | constant 1 |
| `+0x3A` | `mic_dis` | 0–1 |
| `+0x3B` | `mic_pos` | 3–7 |
| `+0x3C` | `mic_level` | constant 100 |
| `+0x3D` | `direct_mix` | constant 0 |
| `+0x3E` | `custom_type` | constant 0 |
| `+0x3F`–`+0x45` | `custom_bottom`, `custom_edge`, **`unmapped_113`**, **`unmapped_114`**, `custom_preamp_low`, `custom_preamp_high`, `custom_char` | all constant: 50, 50, **5, 5**, 50, 50, 50 |
| `+0x46`–`+0x4A` | `sp_size`, `sp_color_low`, `sp_color_high`, `sp_num`, `sp_cabinet` | constant 7, 10, 10, 2, 0 |

Slot B (`preamp_b_*`) sits at record+`0x4F` with the same 32-byte layout.

Two consequences worth noting:

- **The amp type space is `0..26`, i.e. 27 models**, and the factory presets exercise all of them. Types `25` and `26` carry the orange/Brown-class names (`BGNR LEAD`, `ORNG ROOMY LEAD`, `ORNG CRUNCH`). Whatever the UI exposes, the data model already addresses at least 27.
- **Factory data exceeds the nominal control ranges.** `gain` reaches 120, `presence` 100, `mic_pos` 7, `sp_type` 6. Values above the editor's apparent 0–100 display range already ship in stock patches, which means the DSP side tolerates them.

The complete per-field statistics, offsets for both slots, and the histogram are in `firmware/work/gt1-amp-field-map.json`.

## What is established today

1. **The parameter encoding is plain small integers in the patch.** Values such as `0x32` (50) and `0x64` (100) recur throughout; the editor's default `default.tsl` values appear verbatim in the image, including the custom set `sp_size = 7`, `sp_color_low = 10`, `sp_color_high = 10`, `sp_num = 2`, `sp_cabinet = 0` and five `50`s.
2. **The image ships plaintext parameter records.** A `53 07` prefix followed by a 16-byte ASCII name and `00 00 00` introduces a record whose following bytes are a patch-style parameter block. `reproduce_gt1_amp_record_scan.py` finds **310 candidates, 308 of them on a uniform `0x753` (1875-byte) stride**, spanning `0x199D7C`–`0x25ECB1` with one break. Names run `Tex.Crunch B`, `ComboClean SF`, `Heavy Riff 80`, `Stack Solo MM`, `Hi GAIN STACK`, `BROWN SND For ST`. Only 3 records are referenced by an aligned pointer, so the table is mostly addressed by base + index rather than by pointer.
3. **Two records are referenced from the data segment that startup copies to `0x20000000`.** At file `0x2CAEF0`–`0x2CAF14` (runtime `0x20000134`–`0x20000158`) there is a run of image pointers interleaved with counts:

   ```
   0x2CAEF0: 0x6005635B  0x60056349  0x6005632B   <- Thumb pointers into the DSP layer
   0x2CAEFC: 0x60216024  ("Hi GAIN STACK" record)
   0x2CAF00: 0x0000009F  (159)
   0x2CAF04: 0x00000063  (99)
   0x2CAF14: 0x6025ECB1  (empty-name record)
   ```

   A `{pointer, 159, 99}` shape next to records is a plausible index/count descriptor, and `0x63` is also the user-patch count. Not established, but it is the most direct route to "where does the amp list start and how long is it".
4. **Named voicing strings also appear in a second region** around `0x216ECC` (`NATURAL CLEAN`), `0x218C1B` (`FDR BLUES CRUNCH`), `0x21A211` (`ORNG ROOMY LEAD`), `0x22EBA8` (`BGNR LEAD`), each followed by the same `00 00 00` + parameter block shape. These sit inside the same `0x753` family but not on a fixed intra-record offset, so the name field position varies between record groups.

Evidence artifacts: `firmware/work/amp-control-lead-evidence.json` (field map), and the scan below.

## Open questions

1. **Does selecting a TYPE send an identifier, or a full parameter block?** If a block, the voicing tables live in `GT1Appli` and are editable. This is the decisive question for the whole track. The type byte is at record+`0x2C`; what the app does with it is not yet traced.
2. **What does the `{0x60216024, 0x9F, 0x63}` descriptor at `0x20000134` actually index?** Counts of 159 and 99 next to record pointers are still the best available clue to a table extent.
3. **What are types 25 and 26?** They exist in the data model and appear in factory patches (`BGNR LEAD`, `ORNG ROOMY LEAD`, `ORNG CRUNCH`). Whether the device UI can select them, and whether the type space extends past 26, is untested.
4. **What occupies the unmapped bytes 113-114 (slot A) / 174-175 (slot B)?** Confirmed present and constant `5` across all 246 populated records, so they are not padding. Not identified.
5. **What ranges does the application validate before sending?** Factory data already ships `gain 120` and `presence 100`, so any clamp is wider than the editor display. The `Set to UnKnown Memory` and address-fence strings indicate checks elsewhere in the path.
6. **Does the DSP clamp, ignore, or misbehave on out-of-range values?** Only a device experiment answers this.

## Experiment ladder

Ordered by risk. Each step is reversible and none requires a firmware flash until step 4.

| Step | Action | Risk | Needs |
|---|---|---|---|
| 0 | Offline: resolve record boundaries and the type→parameter path | none | this repo only |
| 1 | Drive `CUSTOM` and its full parameter surface through the editor/SysEx | none (patch data only) | editor or SysEx sender |
| 2 | Sweep values past the editor's limits in a scratch patch | low; patch change resets state | verified backup first |
| 3 | Probe bytes 113–114 / 174–175 | low | same |
| 4 | Patch the app's range table or preset records in a repacked image | requires a proven no-op flash first | bootloader validation unresolved |

Step 4 stays blocked until the no-op repack has actually booted on hardware. `docs/GT1-FIRMWARE-EDITING-ASSESSMENT.md` records that the container pipeline is exact but the updater/bootloader path is untested.

## First tasks

1. ~~Map one `0x753` record end to end.~~ **Done** — see the confirmed field map above; 0 invariant violations over 246 populated records.
2. Find the code that consumes the `preamp_a_type` byte (record+`0x2C`) and determine whether it indexes a record or emits a scalar. This is the decisive step.
3. Resolve the `{pointer, 0x9F, 0x63}` descriptor at file `0x2CAEF0` and determine what it indexes: amp list, preset bank, or a transfer descriptor.
4. Cross-check the same region in v1.05/v1.07/v1.09 and against GT-100 v2.12 to see whether the type space grows with the product's amp list — that distinguishes "per-product voicing table" from "shared DSP-side enum".
5. Enumerate types `25` and `26` and probe for `27+`: if the data model accepts them, the DSP may already know voicings the GT-1 does not advertise.

## Reproduction

```sh
python -B firmware/work/scripts/reproduce_gt1_amp_record_scan.py
python -B firmware/work/scripts/reproduce_gt1_amp_field_map.py
```

Requires the official packages under `firmware/extracted/` and the decoded application under `firmware/work/decoded/`; see the bootstrap decoder probe.

## Limits

- The field map is community-editor evidence and has not been validated against a live unit.
- Identifying a byte as a parameter by pattern matching is structural inference, not proof of use.
- No DSP-side semantics are established: the signal path above is a hypothesis consistent with the field names, not a recovered algorithm.
- Writing patches is a device write to user data; it does not modify firmware, but a verified backup must precede any experiment.
