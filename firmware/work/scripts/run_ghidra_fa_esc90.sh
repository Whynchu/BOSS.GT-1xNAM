#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GHIDRA="$ROOT/tools/ghidra/ghidra_12.2_PUBLIC"
JDK="$ROOT/tools/jdk25/usr/lib/jvm/java-25-openjdk-amd64"
IMAGE="$ROOT/firmware/work/reference/esc2-comparators/fa08_v203/extracted/_tmp/fantom_e_up.bin"
expected="900028695b7ec1b63631737d1bd0eaf4707514264a7b325914d951cb59731d23"
actual="$(sha256sum "$IMAGE" | awk '{print $1}')"
if [[ "$actual" != "$expected" ]]; then echo "Unexpected FA ESC90 image SHA-256: $actual" >&2; exit 3; fi
if [[ -x "$JDK/bin/javac" && -x "$JDK/bin/java" ]]; then
  export JAVA_HOME="$JDK"
  export PATH="$JDK/bin:$PATH"
  export LD_LIBRARY_PATH="/usr/lib/jvm/java-25-openjdk-amd64/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
elif [[ -z "${JAVA_HOME:-}" ]]; then
  echo "Set JAVA_HOME to a supported JDK 25+ before running Ghidra." >&2; exit 2
fi
mkdir -p "$ROOT/firmware/work/ghidra-projects"
cd "$ROOT"
"$GHIDRA/support/analyzeHeadless" firmware/work/ghidra-projects FA_ESC90 \
  -import "$IMAGE" -overwrite -loader BinaryLoader -loader-baseAddr FFFFD0 \
  -loader-fileOffset 0 -loader-length 8192 -processor ARM:LE:32:Cortex -noanalysis \
  -scriptPath tools/ghidra_scripts -postScript FAESC90ThumbBlock.java
