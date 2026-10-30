#!/usr/bin/env python3
"""Derive the JNIEnv function-table order from the local Android header.

The engine resolves JNI functions by table slot, so every implemented handler
must be checked against the header's struct order rather than memorised offsets.
Run after adding a handler: `python3 tools/verify_jni_slots.py [header]`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JNI = ROOT / "src/runtime/jni.ts"
RESERVED = 4  # JNINativeInterface starts with four reserved pointers.


def header_slots(header: Path) -> dict[int, str]:
    source = header.read_text()
    start = source.index("struct JNINativeInterface {")
    body = source[start:source.index("};", start)]
    names = re.findall(r"\n\s*(?:[A-Za-z_][\w \t\*]*?)?\(\s*\*\s*([A-Za-z_][\w]*)\s*\)", body)
    return {index + RESERVED: name for index, name in enumerate(names)}


def implemented_slots() -> dict[int, str]:
    return {int(index): name for index, name in re.findall(r'(\d+): "([A-Za-z]+)"', JNI.read_text())}


def main() -> int:
    header = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".local/android-jni.h"
    if not header.exists():
        raise SystemExit(f"JNI header not found: {header}")
    slots, implemented = header_slots(header), implemented_slots()
    failures = 0
    for index, name in sorted(implemented.items()):
        actual = slots.get(index)
        if actual != name:
            failures += 1
            print(f"slot {index}: code says {name}, header says {actual}", file=sys.stderr)
    for index in (171, 172, 174, 200, 215):
        print(f"slot {index}: {slots.get(index)}")
    print(f"verified {len(implemented)} implemented slots against {len(slots)} header slots")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
