#!/usr/bin/env python3
"""Cross-check the hand-written AArch64 decoder against Capstone on real machine code.

`tools/dump_decode.ts` decodes one small, bounded byte range with
`src/runtime/translate/arm64.ts`; this script disassembles exactly the same bytes with
the vendored Capstone, translates every Capstone rendering into the semantics our
decoder claims to model, and reports each disagreement.

Comparison rules:
  * an instruction our decoder rejects is "unsupported" and is never compared;
  * an instruction our decoder accepts is compared against Capstone's mnemonic and
    operands; a rendering our instruction model cannot express (inverted logical
    operands, 32-bit or SIMD register pairs, scaled index registers, bitfield aliases,
    ...) counts as "not compared" and is listed separately, never as a failure;
  * only the field names the decoder actually exposes are compared, so the checker keeps
    working while the decoder gains fields.

Only the requested range is read, no extracted bytes are written anywhere, and the
disassembly text printed is limited to the mismatches and unverified sightings inside
that bounded range. Exit codes: 0 = no mismatches, 1 = mismatches, 2 = tooling error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPSTONE_ROOT = ROOT / ".local/python"
DUMP_TOOL = Path(__file__).resolve().parent / "dump_decode.ts"
EXPECTED_SHA256 = "e2caf73f534e90cd08405a5db1d11dc484b5d681ac2e0654421ea4816e2ea724"
DEFAULT_FILE = ".local/dependencies/libpairipcore.so"
DEFAULT_START = 0x47C00
DEFAULT_LENGTH = 0x400
DEFAULT_MAX = 256
MAX_LENGTH = 0x4000          # 16 KiB: a bounded check, never the whole binary
MAX_MISMATCHES = 40
MAX_UNVERIFIED = 12
MASK64 = (1 << 64) - 1
CONDITION_ALIASES = {"hs": "cs", "lo": "cc"}
WIDTH_REGISTERS = {"x": 64, "xzr": 64, "sp": 64, "w": 32, "wzr": 32, "wsp": 32}
EXTEND_IDENTITY = {"uxtx", "sxtx"}          # Xm extended to 64 bits is Xm
# mnemonic -> (size, signed) or None when the size follows the destination register.
LOAD_SIZES = {
    "ldr": None, "str": None,
    "ldrb": (8, False), "strb": (8, False),
    "ldrh": (16, False), "strh": (16, False),
    "ldrsb": (8, True), "ldrsh": (16, True), "ldrsw": (32, True),
}

sys.path.insert(0, str(CAPSTONE_ROOT))
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError as error:  # pragma: no cover - environment problem, not a decoder bug
    print(f"verify_decoder: vendored Capstone is not importable from {CAPSTONE_ROOT}: {error}", file=sys.stderr)
    raise SystemExit(2)


# --------------------------------------------------------------------------- operands

def parse_integer(text: str) -> int:
    token = text.strip()
    return int(token, 16) if token.lower().startswith("0x") else int(token, 10)


def split_operands(text: str) -> list[str]:
    """Splits an operand list on top-level commas, keeping `[x1, #8]` together."""
    if not text.strip():
        return []
    parts: list[str] = []
    depth, current = 0, ""
    for character in text:
        if character == "[":
            depth += 1
        elif character == "]":
            depth -= 1
        if character == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += character
    if current.strip():
        parts.append(current.strip())
    return parts


def register(text: str) -> tuple[int, str] | None:
    """Maps an AArch64 general-purpose register name to (index, kind)."""
    name = text.strip().lower()
    if name in ("xzr", "wzr", "sp", "wsp"):
        return (31, name)
    if len(name) >= 2 and name[0] in ("x", "w") and name[1:].isdigit():
        index = int(name[1:])
        if 0 <= index <= 30:
            return (index, name[0])
    return None


def immediate_operand(text: str) -> int | None:
    token = text.strip()
    if not token.startswith("#"):
        return None
    try:
        return int(token[1:], 0)
    except ValueError:
        return None


def modifier(text: str) -> tuple[str, str, int] | None:
    """Parses `lsl #3`, `uxtb`, `sxtw #2`, ... into (class, name, amount)."""
    tokens = text.split()
    if not tokens or len(tokens) > 2:
        return None
    name = tokens[0].lower()
    amount = 0 if len(tokens) == 1 else immediate_operand(tokens[1])
    if amount is None:
        return None
    if name in ("lsl", "lsr", "asr", "ror", "msl"):
        return ("shift", name, amount)
    if name in ("uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"):
        return ("extend", name, amount)
    return None


def memory_operand(text: str) -> dict | None:
    """Parses `[x1, #8]`, `[x1]`, `[x1, x2, lsl #3]` and the `!` writeback marker."""
    token = text.strip()
    writeback = token.endswith("!")
    if writeback:
        token = token[:-1].strip()
    if not (token.startswith("[") and token.endswith("]")):
        return None
    parts = [part.strip() for part in token[1:-1].split(",")]
    base = register(parts[0])
    if base is None:
        return None
    operand = {"base": base, "offset": 0, "index": None, "scaled": False, "writeback": writeback}
    if len(parts) == 1:
        return operand
    if len(parts) == 2:
        offset = immediate_operand(parts[1])
        if offset is not None:
            operand["offset"] = offset
            return operand
        index = register(parts[1])
        if index is None:
            return None
        operand["index"] = index
        return operand
    if len(parts) == 3:
        index, applied = register(parts[1]), modifier(parts[2])
        if index is None or applied is None:
            return None
        if applied[0] == "shift" and applied[1] != "lsl":
            return None
        operand["index"] = index
        operand["scaled"] = applied[2] != 0        # `uxtw`/`lsl #0` do not scale; `uxtw #2` does
        return operand
    return None


# --------------------------------------------------------------------------- reporting

def render(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return hex(value) if value >= 0 else f"-0x{-value:x}"
    return str(value)


def number_field(ours: dict, field: str) -> int | None:
    value = ours.get(field)
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return parse_integer(value)
        except ValueError:
            return None
    return None


def check_field(problems: list[str], field: str, ours: dict, expected: object) -> None:
    actual = ours.get(field)
    if actual is None:                      # the decoder does not expose this field
        return
    if actual != expected:
        problems.append(f"{field}: ours {render(actual)} != capstone {render(expected)}")


def check_number(problems: list[str], field: str, ours: dict, expected: int) -> None:
    actual = number_field(ours, field)
    if actual is None:
        return
    if actual != expected:
        problems.append(f"{field}: ours {render(actual)} != capstone {render(expected)}")


def check_register(problems: list[str], ours: dict, field: str, parsed: tuple[int, str] | None) -> None:
    """Compares a register index; the width is carried by the kind's own `width`/`size` field."""
    actual = ours.get(field)
    if parsed is None:
        if actual is not None:
            problems.append(f"{field}: capstone operand has no general-purpose register")
        return
    index, name = parsed
    if actual is None:
        return
    if index != actual:
        problems.append(f"{field}: ours x{actual} != capstone {name}")


def check_width(problems: list[str], ours: dict, names: list[str]) -> None:
    width = number_field(ours, "width")
    if width is None or not names:
        return
    widths = {WIDTH_REGISTERS[name] for name in names if name in WIDTH_REGISTERS}
    if len(widths) == 1 and width not in widths:
        problems.append(f"width: ours {width} != capstone register(s) {', '.join(names)}")


def check_kind(problems: list[str], ours: dict, expected: str, insn) -> None:
    if ours.get("kind") != expected:
        problems.append(f"kind: ours {ours.get('kind')} but capstone renders {insn.mnemonic!r} ({expected} semantics)")


# ----------------------------------------------------------------------- comparators
# Each comparator returns True when it understood the Capstone rendering (appending any
# disagreements to `problems`) and None when the rendering is outside our model. A
# comparator may also return True after recording that our model cannot express the
# rendered instruction, which is a genuine support-claim mismatch.

def compare_arithmetic_immediate(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    mnemonic = insn.mnemonic
    register_names: list[str]
    if mnemonic in ("add", "adds", "sub", "subs"):
        if len(ops) not in (3, 4):
            return None
        dst, source, immediate = register(ops[0]), register(ops[1]), immediate_operand(ops[2])
        if dst is None or source is None or immediate is None:
            return None
        shift = 0
        if len(ops) == 4:
            applied = modifier(ops[3])
            if applied is None or applied[0] != "shift" or applied[1] != "lsl" or applied[2] not in (0, 12):
                return None
            shift = applied[2]
        subtract, flags = mnemonic.startswith("sub"), mnemonic.endswith("s")
        register_names = [dst[1], source[1]]
    elif mnemonic in ("cmp", "cmn"):
        if len(ops) not in (2, 3):
            return None
        dst, source, immediate = (31, "xzr"), register(ops[0]), immediate_operand(ops[1])
        if source is None or immediate is None:
            return None
        shift = 0
        if len(ops) == 3:
            applied = modifier(ops[2])
            if applied is None or applied[0] != "shift" or applied[1] != "lsl" or applied[2] not in (0, 12):
                return None
            shift = applied[2]
        subtract, flags = mnemonic == "cmp", True
        register_names = [source[1]]
    elif mnemonic == "mov" and len(ops) == 2:
        # MOV <Xd|SP>, <SP> is the ADD (immediate) #0 alias; MOV <Xd>, <Xm> is ORR.
        dst, source = register(ops[0]), register(ops[1])
        if dst is None or source is None or source[1] not in ("sp", "wsp"):
            return None
        immediate, shift, subtract, flags = 0, 0, False, False
        register_names = [dst[1], source[1]]
    else:
        return None
    check_kind(problems, ours, "subImm" if subtract else "addImm", insn)
    check_register(problems, ours, "rd", dst)
    check_register(problems, ours, "rn", source)
    check_number(problems, "immediate", ours, immediate << shift)
    check_field(problems, "flags", ours, flags)
    check_width(problems, ours, register_names)
    return True


def compare_arithmetic_register(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    mnemonic = insn.mnemonic
    shift, amount = "lsl", 0
    if mnemonic in ("add", "adds", "sub", "subs"):
        if len(ops) not in (3, 4):
            return None
        dst, source, third = register(ops[0]), register(ops[1]), register(ops[2])
        if dst is None or source is None or third is None:
            return None
        if len(ops) == 4:
            recognised = apply_register_modifier(problems, ours, ops[3], ops[2])
            if recognised is None:
                return None
            shift, amount = recognised
        subtract, flags = mnemonic.startswith("sub"), mnemonic.endswith("s")
        register_names = [dst[1], source[1], third[1]]
    elif mnemonic in ("cmp", "cmn"):
        if len(ops) not in (2, 3):
            return None
        dst, source, third = (31, "xzr"), register(ops[0]), register(ops[1])
        if source is None or third is None:
            return None
        if len(ops) == 3:
            recognised = apply_register_modifier(problems, ours, ops[2], ops[1])
            if recognised is None:
                return None
            shift, amount = recognised
        subtract, flags = mnemonic == "cmp", True
        register_names = [source[1], third[1]]
    else:
        return None
    check_kind(problems, ours, "subReg" if subtract else "addReg", insn)
    check_register(problems, ours, "rd", dst)
    check_register(problems, ours, "rn", source)
    check_register(problems, ours, "rm", third)
    check_field(problems, "shift", ours, shift)
    check_number(problems, "amount", ours, amount)
    check_field(problems, "flags", ours, flags)
    check_width(problems, ours, register_names)
    return True


def apply_register_modifier(problems: list[str], ours: dict, text: str, operand: str) -> tuple[str, int] | None:
    applied = modifier(text)
    if applied is None:
        return None
    if applied[0] == "shift":
        return (applied[1], applied[2])
    if applied[1] in EXTEND_IDENTITY and applied[2] == 0:
        return ("lsl", 0)                            # identity extension, same semantics
    problems.append(f"operand modifier: capstone applies {text!r} to {operand}; our {ours.get('kind')} models no extension")
    return ("lsl", 0)


def compare_logical(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    mnemonic = insn.mnemonic
    inverted = {"bic": "andReg", "bics": "andReg", "orn": "orrReg", "eon": "eorReg", "mvn": "orrReg"}
    plain = {"and": ("andReg", False), "ands": ("andReg", True), "orr": ("orrReg", None), "eor": ("eorReg", None)}
    flags: bool | None = None
    shift, amount = "lsl", 0
    if mnemonic in inverted:
        problems.append(f"capstone {mnemonic!r} inverts the third operand; our {ours.get('kind')} has no inversion")
        check_kind(problems, ours, inverted[mnemonic], insn)
        return True
    if mnemonic == "mov" and len(ops) == 2:
        # MOV <Xd>, <Xm> is ORR <Xd>, XZR, <Xm>; MOV with SP is an add-immediate rendering.
        dst, source = register(ops[0]), register(ops[1])
        if dst is None or source is None or source[1] in ("sp", "wsp"):
            return None
        expected, dst, source, third = "orrReg", dst, (31, "xzr"), source
        register_names = [dst[1], source[1]]
    elif mnemonic == "tst":
        if len(ops) not in (2, 3):
            return None
        dst, source, third = (31, "xzr"), register(ops[0]), register(ops[1])
        if source is None or third is None:
            return None
        expected, flags = "andReg", True
        register_names = [source[1], third[1]]
        if len(ops) == 3:
            applied = modifier(ops[2])
            if applied is None or applied[0] != "shift":
                return None
            shift, amount = applied[1], applied[2]
    elif mnemonic in plain:
        if len(ops) not in (3, 4):
            return None
        dst, source, third = register(ops[0]), register(ops[1]), register(ops[2])
        if dst is None or source is None or third is None:
            return None
        if len(ops) == 4:
            applied = modifier(ops[3])
            if applied is None or applied[0] != "shift":
                return None
            shift, amount = applied[1], applied[2]
        expected, flags = plain[mnemonic]
        register_names = [dst[1], source[1], third[1]]
    else:
        return None
    check_kind(problems, ours, expected, insn)
    check_register(problems, ours, "rd", dst)
    check_register(problems, ours, "rn", source)
    check_register(problems, ours, "rm", third)
    if flags is not None:
        check_field(problems, "flags", ours, flags)
    check_field(problems, "shift", ours, shift)
    check_number(problems, "amount", ours, amount)
    check_width(problems, ours, register_names)
    return True


def compare_logic_immediate(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    mnemonic = insn.mnemonic
    table = {"and": ("and", False), "ands": ("and", True), "orr": ("orr", False),
             "eor": ("eor", False), "tst": ("and", True)}
    if mnemonic == "mov" and len(ops) == 2:
        # MOV <Xd>, #imm is the ORR (immediate) alias with XZR as the source.
        dst, source, value = register(ops[0]), (31, "xzr"), immediate_operand(ops[1])
        if dst is None or value is None:
            return None
        expected_operation, flags = "orr", False
    elif mnemonic in table and len(ops) in (2, 3):
        expected_operation, flags = table[mnemonic]
        if mnemonic == "tst":
            dst, source, value = (31, "xzr"), register(ops[0]), immediate_operand(ops[1])
        else:
            dst, source, value = register(ops[0]), register(ops[1]), immediate_operand(ops[2])
        if dst is None or source is None or value is None:
            return None
    else:
        return None
    width = WIDTH_REGISTERS[source[1] if dst[0] == 31 else dst[1]]
    check_register(problems, ours, "rd", dst)
    check_register(problems, ours, "rn", source)
    check_field(problems, "operation", ours, expected_operation)
    check_number(problems, "value", ours, value & ((1 << width) - 1))
    check_field(problems, "flags", ours, flags)
    check_width(problems, ours, [source[1] if dst[0] == 31 else dst[1]])
    return True


def compare_test_bit(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic not in ("tbz", "tbnz") or len(ops) != 3:
        return None
    operand, bit, target = register(ops[0]), immediate_operand(ops[1]), immediate_operand(ops[2])
    if operand is None or bit is None or target is None:
        return None
    check_register(problems, ours, "register", operand)
    check_number(problems, "bit", ours, bit)
    check_field(problems, "branchIfSet", ours, insn.mnemonic == "tbnz")
    check_number(problems, "target", ours, target)
    check_width(problems, ours, [operand[1]])
    return True


def compare_move_wide(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    kind, mnemonic = ours.get("kind"), insn.mnemonic
    if mnemonic not in ("movz", "movk", "movn", "mov") or len(ops) not in (2, 3):
        return None
    if len(ops) == 3 and mnemonic != "movk":
        return None                                  # a shifted movz/movn renders without lsl
    dst, immediate = register(ops[0]), immediate_operand(ops[1])
    if dst is None or immediate is None:
        return None
    width = WIDTH_REGISTERS[dst[1]]
    mask = (1 << width) - 1
    explicit_shift = None
    if len(ops) == 3:
        applied = modifier(ops[2])
        if applied is None or applied[0] != "shift" or applied[1] != "lsl":
            return None
        explicit_shift = applied[2]
    if kind == "movk":
        shift = explicit_shift or 0
        expected_value = (immediate & 0xFFFF) << shift
        check_number(problems, "shift", ours, shift)
    elif kind in ("movz", "movn"):
        expected_value = immediate & mask
        check_move_wide_shift(problems, ours, kind, expected_value, width)
    else:
        return None
    check_register(problems, ours, "rd", dst)
    check_number(problems, "value", ours, expected_value)
    check_width(problems, ours, [dst[1]])
    return True


def check_move_wide_shift(problems: list[str], ours: dict, kind: str, value: int, width: int) -> None:
    """Capstone folds the MOVZ/MOVN lsl into the value, so only our value/shift pairing is checkable."""
    shift = number_field(ours, "shift")
    if shift is None or shift not in (0, 16, 32, 48):
        return
    mask = (1 << width) - 1
    field = value if kind == "movz" else (~value & mask)
    low = (1 << shift) - 1
    if (field & low) != 0 or (field >> shift) > 0xFFFF:
        problems.append(f"shift: ours {shift} does not match value {render(value)} for {kind}")


def compare_load_store(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    mnemonic = insn.mnemonic
    if mnemonic not in LOAD_SIZES or len(ops) not in (2, 3):
        return None
    target = register(ops[0])
    if target is None:
        return None
    if not ops[1].strip().startswith("["):
        return None                                  # e.g. a literal load, a different kind
    memory = memory_operand(ops[1])
    store = mnemonic.startswith("str")
    if memory is None:
        problems.append(f"addressing: our {ours.get('kind')} cannot express capstone's {insn.op_str!r}")
        return True
    if len(ops) == 3 or memory["writeback"]:
        problems.append(f"addressing: capstone renders a pre/post-index form ({insn.op_str!r}); ours models a plain offset")
        return True
    if memory["scaled"]:
        problems.append(f"addressing: capstone scales the index register ({ops[1]!r}); our {ours.get('kind')} does not model it")
        return True
    check_register(problems, ours, "rt" if store else "rd", target)
    check_register(problems, ours, "rn", memory["base"])
    fixed = LOAD_SIZES[mnemonic]
    expected_size, signed = fixed if fixed is not None else (WIDTH_REGISTERS[target[1]], False)
    check_number(problems, "size", ours, expected_size)
    if not store:
        check_field(problems, "signed", ours, signed)
    if memory["index"] is not None:
        check_register(problems, ours, "rm", memory["index"])
        check_number(problems, "indexWidth", ours, WIDTH_REGISTERS[memory["index"][1]])
        check_number(problems, "offset", ours, 0)
    else:
        check_number(problems, "offset", ours, memory["offset"])
        if "rm" in ours:
            problems.append("rm: ours reports an index register, capstone renders an immediate offset")
    return True


def compare_pair(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    load = ours.get("kind") == "loadPair"
    accepted = ("ldp", "ldnp") if load else ("stp", "stnp")
    if len(ops) not in (3, 4):
        return None
    if insn.mnemonic not in accepted:
        simd = register(ops[0]) is None and ops[0].strip()[:1] in ("q", "d", "s", "h", "b", "v")
        if simd or insn.mnemonic in ("ldpsw", "stgp", "ld64b", "st64b"):
            problems.append(f"kind: capstone renders {insn.mnemonic} {insn.op_str}, which our 64-bit pair model does not express")
            return True
        return None
    rt, rt2 = register(ops[0]), register(ops[1])
    memory = memory_operand(ops[2]) if len(ops) >= 3 else None
    if rt is None or rt2 is None or memory is None:
        return None
    offset, writeback = memory["offset"], "pre" if memory["writeback"] else "none"
    if len(ops) == 4:
        trailing = immediate_operand(ops[3])
        if trailing is None:
            return None
        offset, writeback = trailing, "post"
    if memory["index"] is not None:
        return None
    register_names = [rt[1], rt2[1]]
    if any(name in ("w", "wzr", "wsp") for name in register_names):
        problems.append(f"width: capstone renders the 32-bit pair form {insn.mnemonic} {insn.op_str}; our pair model is 64-bit only")
    check_register(problems, ours, "rt", rt)
    check_register(problems, ours, "rt2", rt2)
    check_register(problems, ours, "rn", memory["base"])
    check_number(problems, "offset", ours, offset)
    check_field(problems, "writeback", ours, writeback)
    return True


def compare_select(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    table = {"csel": (False, False), "csinc": (False, True), "csinv": (True, False), "csneg": (True, True)}
    if insn.mnemonic not in table or len(ops) != 4:
        return None
    dst, source, third = register(ops[0]), register(ops[1]), register(ops[2])
    condition = CONDITION_ALIASES.get(ops[3].strip().lower(), ops[3].strip().lower())
    if dst is None or source is None or third is None:
        return None
    check_register(problems, ours, "rd", dst)
    check_register(problems, ours, "rn", source)
    check_register(problems, ours, "rm", third)
    check_field(problems, "condition", ours, condition)
    check_field(problems, "invert", ours, table[insn.mnemonic][0])
    check_field(problems, "increment", ours, table[insn.mnemonic][1])
    check_width(problems, ours, [dst[1], source[1], third[1]])
    return True


def compare_madd(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    table = {"madd": (False, 4), "msub": (True, 4), "mul": (False, 3), "mneg": (True, 3)}
    if insn.mnemonic not in table:
        return None
    subtract, count = table[insn.mnemonic]
    if len(ops) != count:
        return None
    dst, source, third = register(ops[0]), register(ops[1]), register(ops[2])
    if dst is None or source is None or third is None:
        return None
    addend = register(ops[3]) if count == 4 else (31, "xzr")
    check_register(problems, ours, "rd", dst)
    check_register(problems, ours, "rn", source)
    check_register(problems, ours, "rm", third)
    check_register(problems, ours, "ra", addend)
    check_field(problems, "subtract", ours, subtract)
    check_width(problems, ours, [dst[1], source[1], third[1]])
    return True


def compare_divide(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic not in ("udiv", "sdiv") or len(ops) != 3:
        return None
    dst, source, third = register(ops[0]), register(ops[1]), register(ops[2])
    if dst is None or source is None or third is None:
        return None
    check_register(problems, ours, "rd", dst)
    check_register(problems, ours, "rn", source)
    check_register(problems, ours, "rm", third)
    check_field(problems, "signed", ours, insn.mnemonic == "sdiv")
    check_width(problems, ours, [dst[1], source[1], third[1]])
    return True


def compare_shift_register(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic not in ("lsl", "lsr", "asr") or len(ops) != 3:
        return None
    dst, source = register(ops[0]), register(ops[1])
    if dst is None or source is None:
        return None
    if register(ops[2]) is None:
        problems.append(f"kind: capstone renders the bitfield-immediate shift {insn.mnemonic} {insn.op_str}; ours reports shiftReg")
        return True
    check_register(problems, ours, "rd", dst)
    check_register(problems, ours, "rn", source)
    check_register(problems, ours, "rm", register(ops[2]))
    check_field(problems, "shift", ours, insn.mnemonic)
    check_width(problems, ours, [dst[1], source[1]])
    return True


def compare_address(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic not in ("adr", "adrp") or len(ops) != 2:
        return None
    dst, value = register(ops[0]), immediate_operand(ops[1])
    if dst is None or value is None:
        return None
    check_register(problems, ours, "rd", dst)
    actual = number_field(ours, "value")
    if actual is not None and actual != value:
        problems.append(f"value: ours {render(actual)} != capstone {render(value)}")
    if insn.mnemonic == "adrp" and actual is not None and actual % 0x1000:
        problems.append(f"value: ours {render(actual)} is not page aligned for adrp")
    return True


def compare_load_literal(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic != "ldr" or len(ops) != 2 or ops[1].strip().startswith("["):
        return None
    dst, value = register(ops[0]), immediate_operand(ops[1])
    if dst is None or value is None:
        return None
    check_register(problems, ours, "rd", dst)
    actual = number_field(ours, "value")
    if actual is not None and actual != value:
        problems.append(f"value: ours {render(actual)} != capstone {render(value)}")
    check_width(problems, ours, [dst[1]])
    return True


def compare_bitfield(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic not in ("sbfm", "ubfm") or len(ops) != 4:
        return None                                  # alias renderings are not inverted here
    dst, source = register(ops[0]), register(ops[1])
    low, high = immediate_operand(ops[2]), immediate_operand(ops[3])
    if dst is None or source is None or low is None or high is None:
        return None
    check_register(problems, ours, "rd", dst)
    check_register(problems, ours, "rn", source)
    check_field(problems, "operation", ours, insn.mnemonic)
    check_number(problems, "immediateR", ours, low)
    check_number(problems, "immediateS", ours, high)
    check_width(problems, ours, [dst[1], source[1]])
    return True


def compare_branch(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic != "b" or len(ops) != 1:
        return None
    target = immediate_operand(ops[0])
    if target is None:
        return None
    check_number(problems, "target", ours, target)
    return True


def compare_branch_link(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic != "bl" or len(ops) != 1:
        return None
    target = immediate_operand(ops[0])
    if target is None:
        return None
    check_number(problems, "target", ours, target)
    return True


def compare_branch_conditional(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if not insn.mnemonic.startswith("b.") or len(ops) != 1:
        return None
    target = immediate_operand(ops[0])
    if target is None:
        return None
    check_field(problems, "condition", ours, CONDITION_ALIASES.get(insn.mnemonic[2:], insn.mnemonic[2:]))
    check_number(problems, "target", ours, target)
    return True


def compare_compare_zero(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic not in ("cbz", "cbnz") or len(ops) != 2:
        return None
    operand, target = register(ops[0]), immediate_operand(ops[1])
    if operand is None or target is None:
        return None
    check_register(problems, ours, "register", operand)
    check_field(problems, "branchIfZero", ours, insn.mnemonic == "cbz")
    check_number(problems, "target", ours, target)
    check_width(problems, ours, [operand[1]])
    return True


def compare_branch_register(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic != "br" or len(ops) != 1:
        return None
    check_register(problems, ours, "rn", register(ops[0]))
    return True


def compare_branch_link_register(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic != "blr" or len(ops) != 1:
        return None
    check_register(problems, ours, "rn", register(ops[0]))
    return True


def compare_return(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic != "ret":
        return None
    if ops:
        problems.append(f"operands: ours models a plain ret, capstone renders {insn.op_str!r}")
    return True


def compare_nop(ours: dict, insn, ops: list[str], problems: list[str]) -> bool | None:
    if insn.mnemonic != "nop":
        return None
    if ops:
        problems.append(f"operands: ours models a plain nop, capstone renders {insn.op_str!r}")
    return True


COMPARATORS = {
    "addImm": compare_arithmetic_immediate, "subImm": compare_arithmetic_immediate,
    "addReg": compare_arithmetic_register, "subReg": compare_arithmetic_register,
    "andReg": compare_logical, "orrReg": compare_logical, "eorReg": compare_logical,
    "movz": compare_move_wide, "movk": compare_move_wide, "movn": compare_move_wide,
    "load": compare_load_store, "store": compare_load_store,
    "loadPair": compare_pair, "storePair": compare_pair,
    "select": compare_select, "madd": compare_madd, "divide": compare_divide,
    "shiftReg": compare_shift_register, "address": compare_address,
    "loadLiteral": compare_load_literal, "bitfield": compare_bitfield,
    "branch": compare_branch, "branchLink": compare_branch_link,
    "branchCond": compare_branch_conditional, "compareZero": compare_compare_zero,
    "branchReg": compare_branch_register, "branchLinkReg": compare_branch_link_register,
    "logicImm": compare_logic_immediate, "testBit": compare_test_bit,
    "return": compare_return, "nop": compare_nop,
}


# ------------------------------------------------------------------------------- main

def describe(entry: dict) -> str:
    fields = [f"{key}={entry[key]}" for key in sorted(entry) if key not in ("address", "word", "kind")]
    body = " ".join(fields)
    return f"{entry.get('kind')}({body})" if body else str(entry.get("kind"))


def digest_of(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare the hand-written AArch64 decoder with Capstone over a small bounded range.")
    parser.add_argument("file", nargs="?", default=DEFAULT_FILE, help=f"binary to read (default {DEFAULT_FILE})")
    parser.add_argument("start", nargs="?", default=hex(DEFAULT_START), help=f"start address/offset (default {hex(DEFAULT_START)})")
    parser.add_argument("length", nargs="?", default=hex(DEFAULT_LENGTH), help=f"byte length (default {hex(DEFAULT_LENGTH)})")
    parser.add_argument("--max", type=int, default=DEFAULT_MAX, help=f"maximum instructions to compare (default {DEFAULT_MAX})")
    arguments = parser.parse_args(argv)
    try:
        start, length = parse_integer(arguments.start), parse_integer(arguments.length)
    except ValueError:
        parser.error("start and length must be decimal or 0x-hex integers")
    if start < 0 or length <= 0 or start % 4 or length % 4:
        parser.error("start and length must be non-negative multiples of 4 with length > 0")
    if length > MAX_LENGTH:
        parser.error(f"length {length} exceeds the {MAX_LENGTH}-byte bounded-check cap")
    if arguments.max <= 0:
        parser.error("--max must be positive")

    path = Path(arguments.file).resolve()
    if not path.is_file():
        print(f"verify_decoder: no such file: {path}", file=sys.stderr)
        return 2
    if start + length > path.stat().st_size:
        print(f"verify_decoder: range {hex(start)}+{hex(length)} exceeds {path} ({path.stat().st_size} bytes)", file=sys.stderr)
        return 2
    digest = digest_of(path)
    known = digest == EXPECTED_SHA256
    if not known:
        print(f"verify_decoder: warning: {path} sha256 {digest} differs from the known build; "
              "the virtual-address == file-offset assumption may not hold", file=sys.stderr)

    node = shutil.which("node")
    if node is None:
        print("verify_decoder: node is not on PATH", file=sys.stderr)
        return 2
    command = [node, str(DUMP_TOOL), str(path), hex(start), hex(length), "--max", str(arguments.max)]
    try:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
    except subprocess.TimeoutExpired:
        print("verify_decoder: tools/dump_decode.ts timed out", file=sys.stderr)
        return 2
    if completed.returncode != 0:
        print(f"verify_decoder: tools/dump_decode.ts failed with exit code {completed.returncode}", file=sys.stderr)
        print(completed.stderr.strip(), file=sys.stderr)
        return 2
    try:
        dumped = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        print(f"verify_decoder: could not parse dump_decode output: {error}", file=sys.stderr)
        print(completed.stdout[:400], file=sys.stderr)
        return 2
    decoded = dumped.get("decoded")
    expected_words = min(length // 4, arguments.max)
    if not isinstance(decoded, list) or len(decoded) != expected_words:
        count = len(decoded) if isinstance(decoded, list) else "no"
        print(f"verify_decoder: dump_decode returned {count} entries, expected {expected_words}", file=sys.stderr)
        return 2

    with path.open("rb") as handle:            # the first PT_LOAD maps vaddr 0 at offset 0
        handle.seek(start)
        code = handle.read(length)
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    disassembler.skipdata = True
    instructions = {instruction.address: instruction for instruction in disassembler.disasm(code, start)}

    mismatches: list[tuple[int, int, str, list[str]]] = []
    unverified: list[tuple[int, int, str, str]] = []
    compared = unsupported = 0
    for entry in decoded:
        address, word = entry["address"], entry["word"]
        kind = entry.get("kind")
        if kind == "unsupported":
            unsupported += 1
            continue
        instruction = instructions.get(address)
        comparator = COMPARATORS.get(kind)
        if instruction is None or comparator is None:
            reason = "no Capstone instruction" if instruction is None else "kind not modelled by this checker"
            unverified.append((address, word, describe(entry), reason))
            continue
        problems: list[str] = []
        if not comparator(entry, instruction, split_operands(instruction.op_str), problems):
            unverified.append((address, word, describe(entry), f"capstone {instruction.mnemonic} {instruction.op_str}".strip()))
            continue
        compared += 1
        if problems:
            mismatches.append((address, word, describe(entry), problems + [f"capstone: {instruction.mnemonic} {instruction.op_str}".strip()]))

    total = len(decoded)
    print(f"file:     {path} (sha256 {digest}")
    print(f"          {'matches the known build' if known else 'DIFFERS from the known build'})")
    print(f"range:    {hex(start)} + {hex(length)} bytes ({length // 4} instructions), max {arguments.max}")
    print(f"capstone: {len(instructions)} of {len(code) // 4} four-byte units disassembled")
    print()
    print("summary")
    print(f"  total instructions                        {total}")
    print(f"  decoder supported                         {total - unsupported}")
    print(f"  compared                                  {compared}")
    print(f"  mismatched                                {len(mismatches)}")
    print(f"  not compared (decoder unsupported)        {unsupported}")
    print(f"  not compared (outside verifiable subset)  {len(unverified)}")
    print()
    if mismatches:
        print(f"mismatches ({len(mismatches)} total, listing {min(len(mismatches), MAX_MISMATCHES)})")
        for address, word, ours, notes in mismatches[:MAX_MISMATCHES]:
            print(f"  {hex(address)}  word {hex(word)}  ours: {ours}")
            for note in notes:
                print(f"      {note}")
        if len(mismatches) > MAX_MISMATCHES:
            print(f"  ... {len(mismatches) - MAX_MISMATCHES} further mismatch(es) not listed")
    else:
        print("mismatches: none")
    print()
    if unverified:
        print(f"accepted but outside the verifiable subset (not failures; {len(unverified)} total, "
              f"listing {min(len(unverified), MAX_UNVERIFIED)})")
        for address, word, ours, note in unverified[:MAX_UNVERIFIED]:
            print(f"  {hex(address)}  word {hex(word)}  ours: {ours}  |  {note}")
        if len(unverified) > MAX_UNVERIFIED:
            print(f"  ... {len(unverified) - MAX_UNVERIFIED} further instruction(s) not listed")
        print()
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
