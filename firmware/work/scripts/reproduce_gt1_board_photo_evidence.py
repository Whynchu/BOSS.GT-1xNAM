#!/usr/bin/env python3
"""Regenerate SHA-256 inventory and observation notes for preserved GT-1 photos."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PHOTO_DIR = ROOT / "firmware/work/reference/gt1-board-photos"
OUTPUT = ROOT / "firmware/work/gt1-board-photo-evidence.json"

OBSERVATIONS = {
    "IMG_3185.JPEG": "Dhvan teardown front product view.",
    "IMG_3186.JPEG": (
        "Dhvan teardown top/control board; IC2 marking visually reads "
        "ESMT M12L128168A-6T."
    ),
    "IMG_3188.JPEG": "Dhvan teardown assembly view; no chip marking used.",
    "IMG_3210.JPEG": (
        "Dhvan teardown lower/main board; PCB marking reads "
        "GT-1 PNB MAIN BOARD ASSY 5100051442; central IC1 marking is not legible."
    ),
    "IMG_3211.JPEG": "Dhvan teardown front product view.",
    "IMG_3212.JPEG": "Dhvan teardown bottom enclosure view.",
    "IMG_3213.JPEG": "Dhvan teardown rear connector view.",
    "xintrea-image1.png": (
        "Screenshot image in the 2024 Xintrea firmware article; shows a firmware "
        "hex comparison, not a board photo."
    ),
    "xintrea-image2.png": (
        "Screenshot image in the 2024 Xintrea firmware article; shows a firmware "
        "hex comparison, not a board photo."
    ),
}


def source_page(filename: str) -> str:
    if filename.startswith("IMG_"):
        return "https://dhvan-assistenciatecnica.blogspot.com/2025/03/pedaleira-boss-gt-1.html"
    return "https://webhamster.ru/mytetrashare/index/mtb0/17186974979qcubc1ew5"


def main() -> None:
    entries = []
    for path in sorted(PHOTO_DIR.iterdir()):
        if not path.is_file():
            continue
        data = path.read_bytes()
        entries.append(
            {
                "file": path.name,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "source_page": source_page(path.name),
                "observation": OBSERVATIONS.get(path.name, ""),
            }
        )

    evidence = {
        "method": (
            "SHA-256 over downloaded source image bytes; visual observations are "
            "qualitative and limited to legible markings."
        ),
        "images": entries,
    }
    OUTPUT.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(entries)} image records to {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
