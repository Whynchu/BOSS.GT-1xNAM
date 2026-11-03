#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 ]]; then
  echo "usage: $0 PROJECT_NAME SEGMENT.bin DECODED_IMAGE.bin REPORT.txt ENTRY_ADDRESS [ENTRY_ADDRESS ...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GHIDRA="$ROOT/tools/ghidra/ghidra_12.2_PUBLIC"
JDK="$ROOT/tools/jdk25/usr/lib/jvm/java-25-openjdk-amd64"
PROJECT_NAME="$1"
SEGMENT="$2"
DECODED_IMAGE="$3"
REPORT="$4"
shift 4

export JAVA_HOME="$JDK"
export PATH="$JDK/bin:$PATH"
export LD_LIBRARY_PATH="/usr/lib/jvm/java-25-openjdk-amd64/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p "$ROOT/firmware/work/ghidra-projects" "$(dirname "$REPORT")"
cd "$ROOT"
GT1_COMBINED_GHIDRA_REPORT="$REPORT" \
  "$GHIDRA/support/analyzeHeadless" \
  firmware/work/ghidra-projects "$PROJECT_NAME" \
  -import "$SEGMENT" -overwrite \
  -loader BinaryLoader -loader-baseAddr 1000300 \
  -processor ARM:LE:32:v7 -noanalysis \
  -scriptPath tools/ghidra_scripts \
  -postScript GT1CombinedAddressProbe.java "$DECODED_IMAGE" "$@"
