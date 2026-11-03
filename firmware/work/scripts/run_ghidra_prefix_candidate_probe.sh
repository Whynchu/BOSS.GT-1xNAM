#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
IMAGE="$ROOT/firmware/extracted/v109/gt1_sys_v109/GT1ROM.BIN"
PREFIX="$ROOT/firmware/work/gt1-common-prefix.bin"
REPORT="$ROOT/firmware/work/ghidra-prefix-candidate-probe.txt"
GHIDRA="$ROOT/tools/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless"
PROJECT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gt1-prefix-ghidra.XXXXXX")"
trap 'rm -rf -- "$PROJECT_DIR"' EXIT

python3 - "$IMAGE" "$PREFIX" <<'PY'
import hashlib
import sys
from pathlib import Path

image_path, output_path = map(Path, sys.argv[1:])
image = image_path.read_bytes()
expected = "412ebf5ffdc48554454c27df47f61428f046ea0a7d93f5c77b7f0302861abdbf"
actual = hashlib.sha256(image).hexdigest()
if actual != expected:
    raise SystemExit(f"unexpected v1.09 image SHA-256: {actual}")
output_path.write_bytes(image[0x2040 : 0x2040 + 194])
PY

GT1_PREFIX_GHIDRA_REPORT="$REPORT" "$GHIDRA" \
    "$PROJECT_DIR" GT1_Prefix_Probe \
    -import "$PREFIX" \
    -processor ARM:LE:32:Cortex \
    -noanalysis \
    -scriptPath "$SCRIPT_DIR/ghidra" \
    -postScript GT1PrefixCandidateProbe.java
