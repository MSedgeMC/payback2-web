#!/usr/bin/env python3
"""Print the essential fields of .local/engine-probe.json."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".local/engine-probe.json"
    report = json.loads(path.read_text())
    outer = report["result"]
    result = outer["result"]
    dependency = outer.get("dependencyInitializers") or {}
    fields = {
        "stage": outer.get("stage"),
        "status": result.get("status"),
        "blocked": result.get("blockedSymbol"),
        "library": result.get("blockedLibrary"),
        "detail": result.get("blockedDetail"),
        "initializers": f"{result.get('completedInitializers')}/{result.get('initializerCount')}",
        "dependencyInitializers": f"{dependency.get('completedInitializers')}/{dependency.get('initializerCount')}",
        "slices": result.get("sliceCount"),
        "instructions": (result.get("sliceCount") or 0) * (result.get("instructionBudget") or 0)
        // max(result.get("sliceCount") or 1, 1),
        "elapsedMs": round(result.get("elapsedMs") or 0, 1),
        "wasmMemoryMiB": round((result.get("wasmMemoryBytes") or 0) / 1048576, 1),
        "destructors": result.get("registeredDestructors"),
        "lastPc": (result.get("last") or {}).get("pc"),
        "registers": result.get("registers"),
    }
    print(json.dumps(fields, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
