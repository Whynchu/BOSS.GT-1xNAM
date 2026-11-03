#!/usr/bin/env python3
"""Record static, reproducible facts from the preserved GT-1 FxFloorBoard source."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[3]
REFERENCE = ROOT / "firmware/work/reference/gt-1"
ARCHIVE = ROOT / "firmware/work/reference/gt-1_fxfb_source_code_20260405.zip"
DEFAULT_SYX = REFERENCE / "new_default.syx"
DEFAULT_TSL = REFERENCE / "default.tsl"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def entries(path: Path) -> list[tuple[str, str]]:
    root = ET.parse(path).getroot()
    header = root.find("Header")
    assert header is not None
    return [
        (child.get("value", ""), param.get("value", ""))
        for child in header
        for param in child
    ]


def parse_syx_messages(path: Path) -> list[dict[str, object]]:
    data = path.read_bytes()
    messages = []
    offset = 0
    while offset < len(data):
        assert data[offset] == 0xF0, f"missing SysEx start at {offset:#x}"
        end = data.find(b"\xF7", offset)
        assert end >= 0, f"missing SysEx end after {offset:#x}"
        message = data[offset : end + 1]
        assert len(message) >= 13
        checksum = message[-2]
        calculated = (-sum(message[7:-2])) & 0x7F
        messages.append(
            {
                "offset": offset,
                "length": len(message),
                "address": message[7:11].hex(),
                "checksum": checksum,
                "calculated_checksum": calculated,
                "checksum_valid_under_editor_algorithm": checksum == calculated,
            }
        )
        offset = end + 1
    assert offset == len(data)
    return messages


def main() -> None:
    midi = REFERENCE / "midi.xml"
    globals_h = REFERENCE / "globalVariables.h"
    midi_table = REFERENCE / "MidiTable.cpp"
    syx_io = REFERENCE / "SysxIO.cpp"
    messages = parse_syx_messages(DEFAULT_SYX)
    patch_set = json.loads(DEFAULT_TSL.read_text(encoding="utf-8"))
    example_params = patch_set["patchList"][0]["params"]
    amp_param_sample = {
        key: example_params[key]
        for key in (
            "preamp_a_type",
            "preamp_a_gain",
            "preamp_b_type",
            "preamp_a_custom_type",
            "fx1_sub_od_ds_type",
        )
        if key in example_params
    }
    header_entries = entries(midi)
    # These are descriptive source-map values; preserve order as bytes 0..6.
    header_by_offset: dict[int, list[str]] = {}
    for offset, value in header_entries:
        header_by_offset.setdefault(int(offset, 16), []).append(value)
    assert header_by_offset == {
        0: ["F0"],
        1: ["41"],
        2: ["00"],
        3: ["00"],
        4: ["00"],
        5: ["60"],
        6: ["11", "12"],
    }

    global_text = globals_h.read_text(encoding="utf-8", errors="replace")
    midi_text = midi_table.read_text(encoding="utf-8", errors="replace")
    io_text = syx_io.read_text(encoding="utf-8", errors="replace")
    write_start = io_text.index("void SysxIO::writeToBuffer()")
    write_end = io_text.index("void SysxIO::relayUpdateSignal()", write_start)
    write_to_buffer = io_text[write_start:write_end]
    evidence = {
        "source": "GT-1 Fx FloorBoard community source; static inspection only",
        "archive": {
            "path": str(ARCHIVE.relative_to(ROOT)),
            "sha256": sha256(ARCHIVE),
        },
        "files": {
            path.name: {"path": str(path.relative_to(ROOT)), "sha256": sha256(path)}
            for path in (midi, midi_table, syx_io, globals_h, DEFAULT_SYX, DEFAULT_TSL)
        },
        "findings": {
            "sys_ex_header_bytes_0_to_6": [header_by_offset[i][0] for i in range(7)],
            "command_byte_0x11_label": header_entries[-2] == ("06", "11"),
            "command_byte_0x12_label": header_entries[-1] == ("06", "12"),
            "address_offset_zero_based": 7,
            "data_offset_zero_based": 11,
            "checksum_offset_zero_based": 7,
            "checksum_implementation_modulus": 128,
            "checksum_implementation_present": all(
                token in midi_text for token in ('QString base = "80"', "dataSize % base")
            ),
            "system_read_request": "F0410000000030110000000000087F0079F7",
            "temporary_bulk_address_msb": "60",
            "writeToBuffer_sets_address_bytes_to_60_00": (
                'QString::number(96, 16).toUpper()' in write_to_buffer
                and 'QString::number(0, 16).toUpper()' in write_to_buffer
            ),
            "writeToBuffer_rewrites_SysEx_address_offsets": (
                "x == sysxAddressOffset" in write_to_buffer
                and "x == sysxAddressOffset + 1" in write_to_buffer
            ),
            "writeToBuffer_sends_patch_messages_via_SysEx": "sendSysx(sysxMsg)" in write_to_buffer,
            "writeToBuffer_waits_for_reset_reply": (
                'SIGNAL(sysxReply(QString))' in write_to_buffer
                and 'SLOT(resetDevice(QString))' in write_to_buffer
            ),
            "user_patches": 50,
            "patches_per_bank": 4,
            "writes_present_in_source": "sendSysx(sysxMsg)" in io_text,
            "saved_example_patch_set_device": patch_set.get("device"),
            "saved_example_patch_count": len(patch_set.get("patchList", [])),
            "saved_example_amp_parameter_values": amp_param_sample,
            "saved_example_syx_message_count": len(messages),
            "saved_example_syx_message_lengths": sorted(
                {message["length"] for message in messages}
            ),
            "saved_example_syx_all_checksums_valid": all(
                message["checksum_valid_under_editor_algorithm"] for message in messages
            ),
            "saved_example_syx_message_addresses": [
                message["address"] for message in messages
            ],
        },
        "saved_example_syx_messages": messages,
        "limitations": [
            "Community-maintained table, not an official Roland protocol specification.",
            "Static source inspection does not establish executable upload or firmware access.",
            "No hardware was connected and no SysEx was transmitted.",
        ],
    }
    out = ROOT / "firmware/work/fxfloorboard-source-evidence.json"
    out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(out.relative_to(ROOT))


if __name__ == "__main__":
    main()
