#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
REPORT="$ROOT/firmware/work/ghidra-v109-esc2-protocol-path.txt"
GT1_ESC2_TRANSFER_DECOMPILE_REPORT="$REPORT" \
  tools/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless \
  firmware/work/ghidra-projects GT1_v109_ESC2ProtocolPath \
  -import firmware/work/decoded/v109-GT1Appli.bin -overwrite \
  -loader BinaryLoader -loader-baseAddr 60000000 \
  -processor ARM:LE:32:v7 -noanalysis \
  -scriptPath tools/ghidra_scripts \
  -postScript GT1Esc2ProtocolPathProbe.java \
  firmware/work/decoded/v109-GT1Appli.bin
