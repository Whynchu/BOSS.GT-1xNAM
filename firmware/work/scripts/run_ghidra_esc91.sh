#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GHIDRA="$ROOT/tools/ghidra/ghidra_12.2_PUBLIC"
JDK="$ROOT/tools/jdk25/usr/lib/jvm/java-25-openjdk-amd64"
IMAGE="$ROOT/firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN"

if [[ -x "$JDK/bin/javac" && -x "$JDK/bin/java" ]]; then
  export JAVA_HOME="$JDK"
  export PATH="$JDK/bin:$PATH"
  # The extracted Ubuntu JDK package uses the installed OpenJDK 25 runtime.
  export LD_LIBRARY_PATH="/usr/lib/jvm/java-25-openjdk-amd64/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
elif [[ -z "${JAVA_HOME:-}" ]]; then
  echo "Set JAVA_HOME to a supported JDK 25+ before running Ghidra." >&2
  exit 2
fi

expected="412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf"
actual="$(sha256sum "$IMAGE" | awk '{print $1}')"
if [[ "$actual" != "$expected" ]]; then
  echo "Unexpected v1.09 image SHA-256: $actual" >&2
  exit 3
fi

mkdir -p "$ROOT/firmware/work/ghidra-projects"
cd "$ROOT"
"$GHIDRA/support/analyzeHeadless" \
  firmware/work/ghidra-projects GT1_ESC91 \
  -import "$IMAGE" -overwrite \
  -loader BinaryLoader \
  -loader-baseAddr FFFFD0 \
  -loader-fileOffset 0 \
  -loader-length 8192 \
  -processor ARM:LE:32:Cortex \
  -noanalysis \
  -scriptPath tools/ghidra_scripts \
  -postScript GT1ThumbBlock.java
