#!/usr/bin/env python3
"""Record locally discoverable toolchains relevant to an offline NAM benchmark."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMMANDS = {
    "host_gcc": ["gcc", "--version"],
    "arm_none_eabi_gcc": ["arm-none-eabi-gcc", "--version"],
    "arm_linux_gnueabi_gcc": ["arm-linux-gnueabi-gcc", "--version"],
    "arm_linux_gnueabihf_gcc": ["arm-linux-gnueabihf-gcc", "--version"],
    "aarch64_linux_gnu_gcc": ["aarch64-linux-gnu-gcc", "--version"],
    "clang": ["clang", "--version"],
    "llvm_mc": ["llvm-mc", "--version"],
    "llvm_objdump": ["llvm-objdump", "--version"],
    "qemu_system_arm": ["qemu-system-arm", "--version"],
    "qemu_arm_user": ["qemu-arm", "--version"],
    "mips_linux_gnu_gcc": ["mips-linux-gnu-gcc", "--version"],
    "mipsel_linux_gnu_gcc": ["mipsel-linux-gnu-gcc", "--version"],
}

def describe(argv: list[str]) -> dict:
    executable = shutil.which(argv[0])
    item = {"path": executable}
    if executable:
        try:
            proc = subprocess.run([executable, *argv[1:]], capture_output=True, text=True, timeout=5, check=False)
            line = (proc.stdout or proc.stderr).splitlines()
            item["version_line"] = line[0].strip() if line else ""
            item["exit_code"] = proc.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            item["probe_error"] = str(exc)
    return item

tools = {name: describe(argv) for name, argv in COMMANDS.items()}
host_target = None
gcc = shutil.which("gcc")
if gcc:
    proc = subprocess.run([gcc, "-dumpmachine"], capture_output=True, text=True, timeout=5, check=False)
    host_target = proc.stdout.strip() if proc.returncode == 0 else None

result = {
    "classification": "PATH-based inventory in this workspace environment; not a global search for proprietary tools",
    "host_gcc_target": host_target,
    "tools": tools,
    "target_benchmark_status": "No confirmed ESC2 ISA or compatible compiler is identified, and no listed cross compiler or emulator is available in PATH. Host GCC is not a meaningful proxy for ESC2 cycle cost.",
    "limitations": [
        "A PATH miss does not prove a compiler or ICE is unavailable elsewhere on the machine or from Roland/Fujitsu.",
        "An ARM cross compiler alone would not establish that MB8AA4181 implements ARM or that GT-1 application code runs on it.",
        "No target benchmark was built or run; the existing NAM cycles/sample values remain Cortex-M7 references only.",
    ],
}
out = ROOT / "firmware/work/nam-target-toolchain-inventory.json"
out.write_text(json.dumps(result, indent=2) + "\n")
print(f"wrote {out.relative_to(ROOT)}")
print(json.dumps({"host_gcc_target": host_target, "available": {k: v["path"] for k, v in tools.items() if v["path"]}}, indent=2))
