# Decoded application Ghidra probe

The input is the locally decoded v1.09 application at `firmware/work/decoded/v109-GT1Appli.bin` (SHA-256 `2028d7e1f8a72e54b23a80427f53ba27629a7039a72712504a612c877556aa29`). Import it as a raw binary with candidate base `0x60000000`, language `ARM:LE:32:v7`, then use Thumb context and `tools/ghidra_scripts/GT1DecodedCandidate.java`.

From the project root, with the bundled JDK/Ghidra:

```sh
ROOT="$PWD"
GHIDRA="$ROOT/tools/ghidra/ghidra_12.2_PUBLIC"
JDK="$ROOT/tools/jdk25/usr/lib/jvm/java-25-openjdk-amd64"
export JAVA_HOME="$JDK"
export PATH="$JDK/bin:$PATH"
export LD_LIBRARY_PATH="/usr/lib/jvm/java-25-openjdk-amd64/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
GT1_DECODED_GHIDRA_REPORT="$ROOT/firmware/work/ghidra-decoded-candidate.txt" \
  "$GHIDRA/support/analyzeHeadless" \
  firmware/work/ghidra-projects GT1_Decoded_v109_final \
  -import firmware/work/decoded/v109-GT1Appli.bin -overwrite \
  -loader BinaryLoader -loader-baseAddr 60000000 \
  -processor ARM:LE:32:v7 -noanalysis \
  -scriptPath tools/ghidra_scripts -postScript GT1DecodedCandidate.java
```

This is a bounded ISA/mapping probe, not a full decompilation. It sets Thumb context, disassembles the first 0x200-byte setup region and seeds offsets `0x80`, `0x300`, and `0x400`. Ghidra reports 84 instructions in the first 0x200 bytes. The first instructions set `BASEPRI` then call copy/zero helpers, and the stub returns at output offset `0x7C`; this is not proven to be the application reset entry. Literal values mix `0x0100xxxx` fixed references and `0x600xxxxx` candidate app references. The output at offset `0xE4` is `0x01000300`, outside the decoded app range but plausibly inside bootstrap ROM.

Interpretation: Thumb-2 is a credible ISA-family lead for at least the decoded setup component. `0x60000000` is a plausible app base because it is the header destination and produces coherent self-references. Neither the exact ESC2 core ISA nor physical placement, launch entry, or full-image ISA has been proven. Ghidra 12.2 generic ARMv7 was selected because the v6/Cortex language rejects a valid Thumb-2 `MOVW` at the prefix; this is not a core identification.
