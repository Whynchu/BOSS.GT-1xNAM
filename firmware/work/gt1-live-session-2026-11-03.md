# GT-1 live connection session — 2026-11-03

## Device and verified capture

- USB identity: Roland/BOSS GT-1, USB `0582:01d6`; ALSA MIDI `hw:1,0,0`.
- User-reported system version: v1.08. This matches an available firmware package, but the device firmware was not read back.
- The GT-1 service-notes backup sequence succeeded and is saved at `backups/gt1-2026-11-03/gt1-user-data.syx` (232,336 bytes). It contains 992 complete GT-1 DT1 frames: two system-data frames and 990 frames in the user-patch address region. The saved checker reports valid checksums, 99 patch slots, and no trailing partial bytes.
- Pressing PREAMP during a passive MIDI capture emitted no MIDI.

## Host connection observed (2026-11-03)

Read-only host enumeration confirms that the GT-1 is currently attached at USB high speed and exposes ALSA MIDI plus playback and capture PCM devices:

- **MIDI:** ALSA legacy port `GT-1 MIDI 1` on `hw:1,0,0`. The device uses vendor-specific USB interfaces, so its logical ALSA MIDI port does not by itself identify a standard USB-MIDI endpoint. USB interface 0 has no endpoints and is unclaimed by a kernel driver.
- **USB audio playback and capture:** ALSA exposes stereo, 24-bit-in-32-bit containers (`S32_LE`, 24 significant bits) at 44.1 kHz. Playback uses isochronous OUT endpoint `0x0D`; capture uses isochronous IN endpoint `0x8E`, with implicit feedback. Both streams were idle during inspection.
- **Other USB interface:** interface 3 is vendor-specific and bound by `snd-usb-audio`. Alternate setting 0 advertises bulk OUT `0x03`/IN `0x84`; alternate setting 1 advertises interrupt OUT `0x03`/IN `0x85`. Its role and relation to the ALSA MIDI port are not established from descriptors alone. The descriptors do not present a standard USB Audio/MIDI class interface; Linux nevertheless binds interfaces 1–3 to `snd-usb-audio`.

This verifies a direct host route for stereo audio and a logical MIDI port. BOSS says the USB jack supports DAW recording and lists 44.1 kHz sampling, 24-bit A/D and D/A conversion; this corroborates intended external use and sample-rate context, but does not specify USB packet format ([official product specifications](https://www.boss.info/us/products/gt-1/downloads/?lang=en-US)). The official [GT-1 Parameter Guide](https://static.roland.com/assets/media/pdf/GT-1_parameter_eng02_W.pdf) shows USB OUT fed after the effect chain, and says EFX OUT controls the processed sound sent to the computer; USB IN is mixed at the final stage. Inference: the host capture PCM is the device's USB OUT path and therefore exposes post-chain processed audio, not a tap at the amp-model stage. No USB audio data was captured during enumeration; the separate capture below is the first stream recording. This host route does not provide an internal codec/I2S tap, expose the processor's internal DSP/debug port, or show the firmware audio callback. Reproduce host enumeration with `lsusb -v -d 0582:01d6`, `amidi -l`, `aconnect -l`, and `cat /proc/asound/card1/stream0` while connected; device node and card number can vary by host.

### Idle USB audio receive baseline

A 15-second host-side ALSA capture was made from the GT-1 capture PCM at 44.1 kHz stereo, `S32_LE` containers with 24 significant bits. The user confirmed no guitar was connected; only an open patch cable was plugged in. The file `firmware/work/gt1-usb-audio-capture-2026-11-03.wav` is 5,292,044 bytes (661,500 frames, 15.0 seconds), SHA-256 `d4fbcd26e633fa37edda3c4a0ccee6b66f35deb90b3c355744c556c200c66b00`. Both channels are bit-identical, with peak 659,182 and RMS 255,542 as signed 32-bit integer samples. The container-relative level is about -70.3 dBFS; 24-bit sample alignment and analog calibration have not been established, so do not treat that as a calibrated noise level. This is an idle/open-input baseline only; it does not show the guitar signal, USB playback/capture routing under use, or internal processing. A useful follow-up is a second capture with a guitar connected and a repeatable sustained note, then compare the two captures and channel behavior.

## Current-patch read attempts

The community Fx FloorBoard source maps `patchRequest(0, 0)` to Temporary Buffer (Bulk), address `60 00 00 00`, and requests size `00 00 11 00` using command `11` and Roland checksum. Its `getHeader(true)` creates a GT-100-form header (`41 00 00 00 60 11`); `midiIO::sendSysxMsg` later rewrites it to the GT-1 header (`41 00 00 00 30 11`). The source also expects a fixed patch-reply size and converts returned bytes to a GT-100 template for editor parsing.

Direct host attempts were made with both the GT-100-form (`model 60`) and GT-1-form (`model 30`) headers, and with device IDs `00` and `7F`. No replies were captured. Thus the no-reply outcome does not identify a single cause. Remaining possibilities include request field/header details, device-ID handling, a distinction between full-buffer and current-patch requests, timing/receive framing, or special editor sequencing. Do not call the direct request verified merely because its checksum is valid.

The service-manual bulk-backup exchange is independently verified on this pedal and remains the known-good read path. The failed current-buffer requests did not modify user data.

### Community editor receive-path detail

Inspection of the pinned local Fx FloorBoard source shows that `patchRequest(0, 0)` requests its “Temporary Buffer (Bulk)” at address `60 00 00 00`, with length `00 00 11 00` and command `11`. Its `getHeader(true)` initially uses model `0x60`; `midiIO::sendSysxMsg` translates that to GT-1 model `0x30`, recomputes the checksum, opens MIDI input before sending, and waits for an exact 2,316-byte patch response, retrying up to three times. Its receive side expects a fixed patch reply size or parses multiple frames. This is community implementation behavior, not a BOSS protocol specification. It offers a reproducible comparison target for a future read-only capture, but it does not establish why prior direct requests got no reply.

The v1.08 firmware candidate receive-state function at `0x6007D686` calls parser `0x6007CDE2`; no direct call, exact pointer, or common absolute/image-relative literal to the receive-state entry was found in the decoded app. Registration may be indirect, computed, or supplied through a bootstrap/provider structure. The known helper callers include diagnostic/test code. Registration and any audio/amp-model relationship remain unresolved.

## What firmware evidence says

The existing v1.08 bounded report `firmware/work/ghidra-combined-v108-app-init-callbacks.txt` maps the startup entry at `0x010010AE` and 14 initialization callbacks. Callback 0 at `0x01002268` initializes list/task-like objects and names one `initial task`; callback 9 initializes named pool descriptors. These are startup/framework structures. The report does not demonstrate a recurring audio callback, amp-model dispatch, or the live user-patch SysEx handler.

The v1.08 transfer helper report (`firmware/work/ghidra-v108-esc2-transfer-helper.txt`) confirms code patterns for ESC2 program/data transfer and the candidate control/data registers. That path is separate from the documented model-`0x30` user-data dump in current evidence. No caller/path links it to startup audio loading or amp processing.

## New v1.08 helper-caller scan (hash-pinned)

`firmware/work/scripts/reproduce_esc2_transfer_callrefs_v108.py` scans every halfword for structurally valid Thumb-2 BL encodings in the pinned v1.08 decoded application (SHA-256 `c41319e5f5a1facd5e55fe2c8e56d37069e31b98e5034d6d54d932fa7713e8c1`) and records direct calls plus aligned absolute pointers in `firmware/work/esc2-transfer-callrefs-v108.json`.

Results: parser `0x6007CDE2` is called directly at `0x6007D7B6`; stager `0x60093B14` has six direct calls from the parser/flush region; flush dispatcher `0x6007CCD0` is called at three sites in the candidate receive-state routine; read helper `0x60058E1C` is called by the response builder at `0x6007CD6C` and by an adjacent helper at `0x600592F2`; write helper `0x60058D3C` is called by the parser at `0x6007CD7E` and `0x6007CDAA`. The receive-state entry `0x6007D686` itself has no direct BL or aligned absolute-pointer reference in this image scan. This narrows the path but leaves receive-state registration unresolved; indirect tables and computed references are not ruled out.

The shared class-7 transfer helper `0x600593A2` has callers at `0x60008164`, `0x6000818C`, `0x60047A46`, `0x60047D82`, and parser site `0x6007CD9A`. Bounded Thumb context around the two `0x600081xx` sites shows a paired loop over descriptor fields and alternating calls to helper `0x6005949C`; this is consistent with the existing PRAM diagnostic lead. The two `0x60047xxx` call contexts use table-selected descriptors but are not classified. The parser and response builder calls are direct code evidence; none of these observations connects the transfer facility to periodic audio execution.

A focused Ghidra probe of those callers is saved as `firmware/work/ghidra-v108-esc2-helper-callers.txt`, generated by `tools/ghidra_scripts/GT1Esc2V108HelperCallerProbe.java`. The bounded function containing `0x60047D82` is recovered at `0x60047D30`: it walks a table, then checks two descriptor-selected regions for `0x300` pairs of zero words, calls the class-7 helper and a paired helper, and verifies the results through additional routines. This is strong evidence that at least one shared-helper consumer is a memory test/diagnostic path. The containing function and its caller’s full role are not identified, so this does not establish the transfer engine's only role.

## Registration and startup callback limits

The byte-exact decoded-image search found no embedded little-endian pointer to `0x6007D686` or Thumb-tagged `0x6007D687`, even at unaligned byte offsets. The hash-pinned Thumb-2 BL scan likewise found no direct caller to that receive-state entry. Existing evidence therefore supports an indirect/computed registration hypothesis only; it does not reveal a provider table or registration site.

The v1.08 startup callback named `initial task` is evidenced by copying that string into an initialized object. Its tail calls `0x0100117C`, which adds 12 to the destination pointer and branches to `0x01004424`; bounded disassembly of `0x01004424` shows a generic optimized string-copy routine. This supports a task-like object name/initialization role. It does not show that the callback schedules or starts audio work. The established v1.08 startup path still reaches a relocated vector/SVC setup, but no periodic audio callback or codec routine has been identified.

## Next evidence to collect

1. Capture the community editor's one-request temporary-buffer exchange with MIDI input armed first; compare request/response bytes, port, and timing with the prior failed raw attempts. Keep the verified full backup unchanged and use read requests only.
2. Continue bounded v1.08 trace from startup/task registration toward timer, interrupt, codec, or recurring-work registration; identify whether callbacks eventually enter audio processing.
3. Trace PREAMP model selection from patch data through control code to the amp algorithm, and determine whether the app core or an internal DSP domain executes it.
4. Only after a recurring processing path is identified, recover block size, sample representation, memory access, and deadline for a NAM fit decision.
5. If the host audio route is useful, make a short user-approved loopback/capture of the GT-1's USB audio while playing a known signal. This can characterize the external USB stream, but will not replace internal callback tracing.

Current decision: connection and user-data backup paths are demonstrated; current-buffer reads, amp execution ownership, and NAM compatibility remain unresolved.
