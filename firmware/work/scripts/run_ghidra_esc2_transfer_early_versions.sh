#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

export JAVA_HOME="$ROOT/tools/jdk25/usr/lib/jvm/java-25-openjdk-amd64"
export PATH="$JAVA_HOME/bin:$PATH"
export LD_LIBRARY_PATH="/usr/lib/jvm/java-25-openjdk-amd64/lib"

GT1_ESC2_TRANSFER_ENTRY_REPORT="$ROOT/firmware/work/ghidra-v105-esc2-transfer-compare.txt" \
  tools/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless \
  firmware/work/ghidra-projects GT1_v105_ESC2TransferCompare \
  -import firmware/work/decoded/v105-GT1Appli.bin -overwrite \
  -loader BinaryLoader -loader-baseAddr 60000000 -processor ARM:LE:32:v7 -noanalysis \
  -scriptPath tools/ghidra_scripts -postScript GT1Esc2TransferEntryProbe.java \
  firmware/work/decoded/v105-GT1Appli.bin \
  0x6007C9A4,0x6007CA48,0x6007CB5A,0x6007D3FE,0x60093318,0x60059240,0x60058BC0,0x60058AE0,0x60059146

GT1_ESC2_TRANSFER_ENTRY_REPORT="$ROOT/firmware/work/ghidra-v107-esc2-transfer-compare.txt" \
  tools/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless \
  firmware/work/ghidra-projects GT1_v107_ESC2TransferCompare \
  -import firmware/work/decoded/v107-GT1Appli.bin -overwrite \
  -loader BinaryLoader -loader-baseAddr 60000000 -processor ARM:LE:32:v7 -noanalysis \
  -scriptPath tools/ghidra_scripts -postScript GT1Esc2TransferEntryProbe.java \
  firmware/work/decoded/v107-GT1Appli.bin \
  0x6007CBD8,0x6007CC7C,0x6007CD8E,0x6007D632,0x60093A90,0x60059448,0x60058DC8,0x60058CE8,0x6005934E
