#!/usr/bin/env python3
"""Rebuild the pinned ARM64-only Unicorn runtime on GitHub-hosted CI."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def replace_once(source: str, original: str, replacement: str) -> str:
    if source.count(original) != 1:
        raise ValueError("Pinned upstream build script shape changed")
    return source.replace(original, replacement)


def build(source_root: Path, output: Path) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Heavy runtime compilation belongs on GitHub-hosted Actions")
    lock = json.loads((ROOT / "runtime.lock.json").read_text())
    for directory, revision in [(source_root, lock["sourceRevision"]),
                                (source_root / "unicorn", lock["build"]["unicornRevision"])]:
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=directory, text=True).strip()
        if actual != revision:
            raise ValueError("Runtime source revision mismatch")
        if subprocess.check_output(["git", "status", "--porcelain"], cwd=directory, text=True).strip():
            raise ValueError("Runtime source checkout must be clean before applying build transforms")
    version = subprocess.check_output(["emcc", "--version"], text=True).splitlines()[0]
    if not re.search(r"\b" + re.escape(lock["build"]["emscriptenVersion"]) + r"\b", version):
        raise ValueError("Emscripten version mismatch")
    build_script = source_root / "build.py"
    source = build_script.read_text()
    source = replace_once(source, "jobs = os.cpu_count() or 1", "jobs = min(2, os.cpu_count() or 1)")
    source = replace_once(source, "'-DCMAKE_BUILD_TYPE=Release',", "'-DCMAKE_BUILD_TYPE=Debug',")
    source = replace_once(source, "'-Os',", "'-O1', '-g1', '-sASSERTIONS=2', '-sSTACK_OVERFLOW_CHECK=2', '-sSTACK_SIZE=1048576',")
    build_script.write_text(source)
    spec = importlib.util.spec_from_file_location("unicorn_build", build_script)
    if spec is None or spec.loader is None:
        raise ValueError("Cannot load the pinned runtime builder")
    module = importlib.util.module_from_spec(spec)
    os.chdir(source_root)
    spec.loader.exec_module(module)
    module.patchUnicorn()
    # Full CONFIG_DEBUG_TCG has incomplete upstream context plumbing; enable interpreter assertions directly.
    interpreter = source_root / "unicorn/qemu/tcg/tci.c"
    interpreter.write_text(replace_once(interpreter.read_text(), "# define tci_assert(cond) ((void)0)",
                                         "# define tci_assert(cond) assert(cond)"))
    module.generateConstants()
    module.compileUnicorn(["aarch64"])
    output.mkdir(parents=True, exist_ok=True)
    runtime = output / "unicorn-aarch64.cjs"
    shutil.copy2(source_root / "dist/unicorn_aarch64.js", runtime)
    shutil.copy2(source_root / "LICENSE", output / "GPL-2.0.txt")
    metadata = {
        "sourceRevision": lock["sourceRevision"], "unicornRevision": lock["build"]["unicornRevision"],
        "emscriptenVersion": lock["build"]["emscriptenVersion"], "variant": "aarch64",
        "builderSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "buildType": "Debug", "cFlags": [],
        "linkFlags": ["-O1", "-g1", "ASSERTIONS=2", "STACK_OVERFLOW_CHECK=2", "STACK_SIZE=1048576"],
        "workers": 2, "fileSha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
        "fileBytes": runtime.stat().st_size, "purpose": "Synthetic compatibility diagnostics; not a gameplay performance build",
    }
    (output / "runtime-build.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(args.source.resolve(), args.output.resolve())
