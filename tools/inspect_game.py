#!/usr/bin/env python3
"""Independently verify preserved inputs and write bounded ELF metadata privately."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import mmap
from pathlib import Path, PurePosixPath
import struct
import zipfile

BASELINE = {
    "package": "net.apex_designs.payback2", "version": "2.106.16", "version_code": 178,
    "archive_sha256": "2d206d535cff9c5c709b3769bc4fed2c5171c3cddb3bd9f42720e5acf802b09c",
    "engine_sha256": "bbb04c533f4f004d80b1460c18f6207be746d3c30fb828818b8bfc6efd23f5c7",
    "certificate_sha256": "ece9217d193bf0b25c82c8ef898a6664503844418a611b0ca002b01ce5e13649",
}
RELOCATIONS = {257: "ABS64", 1025: "GLOB_DAT", 1026: "JUMP_SLOT", 1027: "RELATIVE"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_path(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if not name or relative.is_absolute() or any(p in (".", "..") for p in relative.parts) or "\\" in name:
        raise ValueError("Unsafe manifest path")
    path = root / str(relative)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Manifest path escapes data root")
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected an original regular file")
    return path


def inspect_elf(data) -> dict:
    def bounds(offset: int, size: int) -> None:
        if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
            raise ValueError(f"ELF range outside file: {offset:#x}+{size:#x}")

    def unpack(fmt: str, offset: int):
        bounds(offset, struct.calcsize(fmt))
        return struct.unpack_from(fmt, data, offset)

    bounds(0, 64)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = unpack("<16sHHIQQQIHHHHHH", 0)
    if ident[:7] != b"\x7fELF\x02\x01\x01" or kind != 3 or machine != 183 or version != 1:
        raise ValueError("Expected a little-endian ELF64 AArch64 shared object")
    if ehsize != 64 or phsize != 56 or shsize != 64 or phnum > 256 or not 0 < shnum <= 4096:
        raise ValueError("Unsupported or excessive ELF tables")
    bounds(phoff, phnum * phsize)
    bounds(shoff, shnum * shsize)
    segments = []
    for i in range(phnum):
        ptype, perms, offset, address, physical, file_size, memory_size, alignment = unpack("<IIQQQQQQ", phoff + i * phsize)
        bounds(offset, file_size)
        if ptype == 1 and (file_size > memory_size or address + memory_size >= 2**64):
            raise ValueError("Invalid load segment")
        if alignment not in (0, 1) and (alignment & (alignment - 1) or address % alignment != offset % alignment):
            raise ValueError("Invalid segment alignment")
        segments.append({"type": ptype, "flags": perms, "offset": offset,
                         "address": address, "file_size": file_size,
                         "memory_size": memory_size, "alignment": alignment})
    loads = sorted((s for s in segments if s["type"] == 1), key=lambda s: s["address"])
    for previous, current in zip(loads, loads[1:]):
        if previous["address"] + previous["memory_size"] > current["address"]:
            raise ValueError("Overlapping load segments")

    def file_offset(address: int, size: int) -> int:
        for segment in loads:
            delta = address - segment["address"]
            if 0 <= delta <= segment["file_size"] and size <= segment["file_size"] - delta:
                return segment["offset"] + delta
        raise ValueError(f"Virtual range is not file backed: {address:#x}+{size:#x}")

    sections = []
    for i in range(shnum):
        name, stype, sflags, address, offset, size, link, info, alignment, entsize = unpack("<IIQQQQIIQQ", shoff + i * shsize)
        if stype != 8:
            bounds(offset, size)
        sections.append({"name_offset": name, "type": stype, "flags": sflags, "address": address,
                         "offset": offset, "size": size, "link": link, "entry_size": entsize})
    if shstr >= shnum:
        raise ValueError("Invalid section-name table")

    def string(table: dict, offset: int) -> str:
        if not 0 <= offset < table["size"]:
            raise ValueError("String offset outside table")
        start = table["offset"] + offset
        limit = min(table["offset"] + table["size"], start + 4096)
        end = data.find(b"\0", start, limit)
        if end < 0:
            raise ValueError("Unterminated or excessive ELF string")
        return data[start:end].decode("utf-8", "strict")

    for section in sections:
        section["name"] = string(sections[shstr], section["name_offset"])
    symbols = []
    symtab = next((s for s in sections if s["type"] == 11), None)
    if not symtab or symtab["entry_size"] != 24 or symtab["size"] % 24 or symtab["link"] >= shnum:
        raise ValueError("Missing or invalid dynamic symbol table")
    strtab = sections[symtab["link"]]
    if symtab["size"] // 24 > 100_000:
        raise ValueError("Excessive symbol count")
    for offset in range(symtab["offset"], symtab["offset"] + symtab["size"], 24):
        name, info, other, index, address, size = unpack("<IBBHQQ", offset)
        symbols.append({"name": string(strtab, name), "type": info & 15,
                        "binding": info >> 4, "section": index, "address": address, "size": size})
    dynamic = []
    for segment in segments:
        if segment["type"] != 2:
            continue
        if segment["file_size"] % 16:
            raise ValueError("Invalid dynamic table size")
        terminated = False
        for offset in range(segment["offset"], segment["offset"] + segment["file_size"], 16):
            tag, value = unpack("<qQ", offset)
            if tag == 0:
                terminated = True
                break
            dynamic.append((tag, value))
        if not terminated:
            raise ValueError("Unterminated dynamic table")
    tags = dict(dynamic)
    if 5 not in tags or 10 not in tags:
        raise ValueError("Missing dynamic string table")
    dynamic_strings = {"offset": file_offset(tags[5], tags[10]), "size": tags[10]}
    needed = [string(dynamic_strings, value) for tag, value in dynamic if tag == 1]
    relocations = []
    for section in sections:
        if section["type"] != 4:
            continue
        if section["entry_size"] != 24 or section["size"] % 24:
            raise ValueError("Invalid RELA table")
        for offset in range(section["offset"], section["offset"] + section["size"], 24):
            address, info, addend = unpack("<QQq", offset)
            symbol = info >> 32
            if symbol >= len(symbols):
                raise ValueError("Relocation symbol outside table")
            relocations.append({"address": address, "type": info & 0xffffffff,
                                "symbol": symbols[symbol]["name"], "addend": addend})
    initializers = []
    if 25 in tags:
        size = tags.get(27, 0)
        if size % 8 or size > 8192:
            raise ValueError("Invalid initialization array")
        start = file_offset(tags[25], size)
        by_address = {r["address"]: r for r in relocations}
        for i in range(size // 8):
            address = tags[25] + i * 8
            relocation = by_address.get(address)
            initializers.append({"slot": address, "file_value": unpack("<Q", start + i * 8)[0],
                                 "relocation": relocation})
    return {"architecture": "AArch64", "entry": entry, "segments": segments,
            "needed": needed, "dynamic": [{"tag": t, "value": v} for t, v in dynamic],
            "imports": [s for s in symbols if s["name"] and s["section"] == 0],
            "exports": [s for s in symbols if s["name"] and s["section"] != 0],
            "relocation_counts": dict(Counter(RELOCATIONS.get(r["type"], str(r["type"])) for r in relocations)),
            "relocations": relocations, "dt_init": tags.get(12), "initializers": initializers,
            "tls_segments": [s for s in segments if s["type"] == 7],
            "load_memory_bytes": sum(s["memory_size"] for s in loads),
            "zero_fill_bytes": sum(s["memory_size"] - s["file_size"] for s in loads)}


def inspect(root: Path, verify_assets: bool = True) -> dict:
    manifest = json.loads((root / "game/import-manifest.json").read_text())
    source = json.loads((root / "originals/net.apex_designs.payback2_2.106.16-178.source.json").read_text())
    verification = json.loads((root / "verification.json").read_text())
    for key in ("package", "version", "version_code"):
        if manifest[key] != BASELINE[key]:
            raise ValueError("Unsupported game identity")
    archive = checked_path(root, manifest["source_archive"])
    engine = checked_path(root / "game", manifest["engine"]["path"])
    archive_hash, engine_hash = sha256(archive), sha256(engine)
    if archive_hash != BASELINE["archive_sha256"] or archive_hash != source["sha256"] or archive_hash != manifest["source_archive_sha256"]:
        raise ValueError("Original archive hash mismatch")
    if engine_hash != BASELINE["engine_sha256"] or engine_hash != manifest["engine"]["sha256"] or engine.stat().st_size != manifest["engine"]["bytes"]:
        raise ValueError("Original engine hash/size mismatch")
    for apk in ("base.apk", "split_config.arm64_v8a.apk"):
        report = next((a for a in verification["apks"] if a["file"] == apk), None)
        if not report or not report["verified"] or report["signer_certificate_sha256"] != [BASELINE["certificate_sha256"]]:
            raise ValueError("Missing matching APK signature report")
    names = set()
    asset_bytes = 0
    for asset in manifest["assets"]:
        if asset["path"] in names:
            raise ValueError("Duplicate asset manifest entry")
        names.add(asset["path"])
        path = checked_path(root / "game", asset["path"])
        if path.stat().st_size != asset["bytes"]:
            raise ValueError("Original asset size mismatch")
        if verify_assets and sha256(path) != asset["sha256"]:
            raise ValueError("Original asset hash mismatch")
        asset_bytes += asset["bytes"]
    if len(names) != manifest["asset_count"] or asset_bytes != manifest["asset_bytes"]:
        raise ValueError("Asset inventory mismatch")
    with zipfile.ZipFile(archive) as package:
        entries = [{"name": i.filename, "expanded_bytes": i.file_size,
                    "compressed_bytes": i.compress_size, "method": i.compress_type}
                   for i in package.infolist()]
    with engine.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        elf = inspect_elf(data)
    return {"baseline": BASELINE, "signature_evidence": "preserved verification.json; not re-signed or freshly re-verified",
            "archive_bytes": archive.stat().st_size, "engine_bytes": engine.stat().st_size,
            "assets": {"count": len(names), "bytes": asset_bytes, "hashes_checked": verify_assets},
            "package_entries": entries, "elf": elf}


def main() -> None:
    import os
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=os.environ.get("PAYBACK2_DATA_ROOT"))
    parser.add_argument("--output", type=Path, default=Path(".local/inspection.json"))
    parser.add_argument("--skip-asset-hashes", action="store_true")
    args = parser.parse_args()
    private = Path(__file__).resolve().parent.parent / ".local"
    if not args.data_root or not args.data_root.is_absolute() or not args.output.resolve().is_relative_to(private.resolve()):
        parser.error("Data root must be absolute; inspection output must stay in ignored .local/.")
    result = inspect(args.data_root, not args.skip_asset_hashes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    elf = result["elf"]
    print(json.dumps({"verified_engine_sha256": BASELINE["engine_sha256"],
                      "assets": result["assets"], "needed": elf["needed"],
                      "import_count": len(elf["imports"]), "export_count": len(elf["exports"]),
                      "relocations": elf["relocation_counts"], "initializers": len(elf["initializers"]),
                      "load_memory_bytes": elf["load_memory_bytes"], "zero_fill_bytes": elf["zero_fill_bytes"],
                      "tls_segments": len(elf["tls_segments"]), "private_report": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
