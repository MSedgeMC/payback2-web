// AArch64 decoding for the translated subset. Anything outside the subset is reported as
// unsupported rather than guessed, so the driver can fall back instead of mis-executing.
// Width 32 operations are modelled on zero-extended 64-bit locals, which is how AArch64
// defines writes to W registers.

export type Condition = "eq" | "ne" | "cs" | "cc" | "mi" | "pl" | "vs" | "vc" | "hi" | "ls" | "ge" | "lt" | "gt" | "le" | "al" | "nv";
export type Width = 32 | 64;
export type BitfieldOp = "sbfm" | "ubfm";

export type Instruction =
  | { kind: "addImm"; rd: number; rn: number; immediate: bigint; flags: boolean; width: Width }
  | { kind: "subImm"; rd: number; rn: number; immediate: bigint; flags: boolean; width: Width }
  | { kind: "addReg"; rd: number; rn: number; rm: number; shift: "lsl" | "lsr" | "asr"; amount: number; flags: boolean; width: Width }
  | { kind: "subReg"; rd: number; rn: number; rm: number; shift: "lsl" | "lsr" | "asr"; amount: number; flags: boolean; width: Width }
  | { kind: "andReg"; rd: number; rn: number; rm: number; shift: "lsl" | "lsr" | "asr"; amount: number; flags: boolean; invert: boolean; width: Width }
  | { kind: "logicImm"; rd: number; rn: number; operation: "and" | "orr" | "eor"; value: bigint; flags: boolean; width: Width }
  | { kind: "testBit"; register: number; bit: number; target: number; branchIfSet: boolean; width: Width }
  | { kind: "orrReg"; rd: number; rn: number; rm: number; shift: "lsl" | "lsr" | "asr"; amount: number; invert: boolean; width: Width }
  | { kind: "eorReg"; rd: number; rn: number; rm: number; shift: "lsl" | "lsr" | "asr"; amount: number; invert: boolean; width: Width }
  | { kind: "madd"; rd: number; rn: number; rm: number; ra: number; subtract: boolean; width: Width }
  | { kind: "divide"; rd: number; rn: number; rm: number; signed: boolean; width: Width }
  | { kind: "multiplyLong"; rd: number; rn: number; rm: number; ra: number; subtract: boolean; signed: boolean }
  | { kind: "shiftReg"; rd: number; rn: number; rm: number; shift: "lsl" | "lsr" | "asr"; width: Width }
  | { kind: "movz"; rd: number; value: bigint; shift: number; width: Width }
  | { kind: "movk"; rd: number; value: bigint; shift: number; width: Width }
  | { kind: "movn"; rd: number; value: bigint; shift: number; width: Width }
  | { kind: "bitfield"; rd: number; rn: number; operation: BitfieldOp; immediateR: number; immediateS: number; width: Width }
  | { kind: "select"; rd: number; rn: number; rm: number; condition: Condition; invert: boolean; increment: boolean; width: Width }
  | { kind: "load"; rd: number; rn: number; rm?: number; indexWidth?: Width; offset: number; size: 8 | 16 | 32 | 64; signed: boolean; writeback?: "pre" | "post" }
  | { kind: "store"; rt: number; rn: number; rm?: number; indexWidth?: Width; offset: number; size: 8 | 16 | 32 | 64; writeback?: "pre" | "post" }
  | { kind: "loadPair"; rt: number; rt2: number; rn: number; offset: number; size: 32 | 64; signed?: boolean; writeback: "none" | "pre" | "post" }
  | { kind: "storePair"; rt: number; rt2: number; rn: number; offset: number; size: 32 | 64; writeback: "none" | "pre" | "post" }
  | { kind: "address"; rd: number; value: bigint }
  | { kind: "loadLiteral"; rd: number; value: bigint; width: Width }
  | { kind: "branch"; target: number }
  | { kind: "branchLink"; target: number }
  | { kind: "branchReg"; rn: number }
  | { kind: "branchLinkReg"; rn: number }
  | { kind: "branchCond"; condition: Condition; target: number }
  | { kind: "compareZero"; register: number; target: number; branchIfZero: boolean; width: Width }
  | { kind: "return" }
  | { kind: "nop" };

export class UnsupportedInstruction extends Error {
  readonly address: number;
  readonly word: number;
  constructor(address: number, word: number) {
    super(`Unsupported AArch64 instruction ${word.toString(16)}`);
    this.address = address; this.word = word;
  }
}

// PAC signs and BTI marks landing pads; this runtime neither verifies pointers nor enforces
// branch targets, so they carry no state we model.
const wordNoOp = new Set([0xd503201f, 0xd503203f, 0xd503205f, 0xd503209f, 0xd50320bf,
  0xd503233f, 0xd50323bf, 0xd503237f, 0xd50323ff, 0xd503241f, 0xd503245f, 0xd503249f, 0xd50324df]);

const conditions: readonly Condition[] = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"];
const shifts: readonly ("lsl" | "lsr" | "asr")[] = ["lsl", "lsr", "asr"];

/** Decodes one instruction; `address` is the guest address of `word`. */
export function decode(address: number, word: number): Instruction {
  const rd = word & 31, rn = (word >>> 5) & 31, unsigned = word >>> 0;
  if (wordNoOp.has(unsigned)) return { kind: "nop" };
  const sf = (word >>> 31) & 1, width: Width = sf === 1 ? 64 : 32;

  // Branch register and return.
  if (((unsigned & 0xfffffc1f) >>> 0) === 0xd61f0000) return { kind: "branchReg", rn };
  if (((unsigned & 0xfffffc1f) >>> 0) === 0xd63f0000) return { kind: "branchLinkReg", rn };
  if (((unsigned & 0xfffffc1f) >>> 0) === 0xd65f0000) {
    if (rn !== 30) throw new UnsupportedInstruction(address, word);
    return { kind: "return" };
  }
  // Move wide immediates.
  if (((word >>> 23) & 0x3f) === 0x25) {
    const opc = (word >>> 29) & 3, shift = ((word >>> 21) & 3) * 16;
    const immediate = BigInt((word >>> 5) & 0xffff) << BigInt(shift);
    if (opc === 2) return { kind: "movz", rd, value: immediate, shift, width };
    if (opc === 3) return { kind: "movk", rd, value: immediate, shift, width };
    if (opc === 0) {
      const mask = width === 64 ? 0xffffffffffffffffn : 0xffffffffn;
      return { kind: "movn", rd, value: (~immediate & mask), shift, width };
    }
    throw new UnsupportedInstruction(address, word);
  }
  // Bitfield operations; the common aliases are derived by the emitter.
  if (((word >>> 23) & 0x3f) === 0x26) {
    const opc = (word >>> 29) & 3;
    if (opc === 0 || opc === 2) {
      const immediateR = (word >>> 16) & 0x3f, immediateS = (word >>> 10) & 0x3f;
      if (width === 32 && (immediateR > 31 || immediateS > 31)) throw new UnsupportedInstruction(address, word);
      return { kind: "bitfield", rd, rn, operation: opc === 0 ? "sbfm" : "ubfm", immediateR, immediateS, width };
    }
    throw new UnsupportedInstruction(address, word);
  }
  // Add/subtract immediate.
  if (((word & 0x1f000000) >>> 0) === 0x11000000) {
    const subtract = ((word >>> 30) & 1) === 1, flags = ((word >>> 29) & 1) === 1, shift = (word >>> 22) & 3;
    if (shift > 1) throw new UnsupportedInstruction(address, word);
    const immediate = BigInt((word >>> 10) & 0xfff) << BigInt(shift * 12);
    return { kind: subtract ? "subImm" : "addImm", rd, rn, immediate, flags, width };
  }
  // Logical (immediate) with a bitmask immediate.
  if (((word >>> 23) & 0x3f) === 0x24) {
    const opc = (word >>> 29) & 3, n = (word >>> 22) & 1, immediateR = (word >>> 16) & 0x3f, immediateS = (word >>> 10) & 0x3f;
    const value = bitmaskImmediate(n, immediateR, immediateS, width);
    const operation = opc === 0 || opc === 3 ? "and" as const : opc === 1 ? "orr" as const : "eor" as const;
    return { kind: "logicImm", rd, rn, operation, value, flags: opc === 3, width };
  }
  // Test bit and branch.
  if (((word & 0x7e000000) >>> 0) === 0x36000000) {
    const bit = (((word >>> 31) & 1) << 5) | ((word >>> 19) & 0x1f);
    if (width === 32 && bit > 31) throw new UnsupportedInstruction(address, word);
    const branchIfSet = ((word >>> 24) & 1) === 1;
    return { kind: "testBit", register: rd, bit, target: address + signExtend((word >>> 5) & 0x3fff, 14) * 4, branchIfSet, width };
  }
  // Add/subtract shifted register.
  if (((word & 0x1f000000) >>> 0) === 0x0b000000) {
    // Bit 21 selects the extended-register form (with an extend operator) rather than a shift.
    if (((word >>> 21) & 1) === 1) throw new UnsupportedInstruction(address, word);
    const shiftCode = (word >>> 22) & 3;
    if (shiftCode > 2) throw new UnsupportedInstruction(address, word);
    const amount = (word >>> 10) & 0x3f, rm = (word >>> 16) & 31;
    if (width === 32 && amount > 31) throw new UnsupportedInstruction(address, word);
    const subtract = ((word >>> 30) & 1) === 1, flags = ((word >>> 29) & 1) === 1;
    return { kind: subtract ? "subReg" : "addReg", rd, rn, rm, shift: shifts[shiftCode]!, amount, flags, width };
  }
  // Logical shifted register.
  if (((word & 0x1f000000) >>> 0) === 0x0a000000) {
    const shiftCode = (word >>> 22) & 3;
    if (shiftCode > 2 || (word & 0x800) !== 0) throw new UnsupportedInstruction(address, word);
    const amount = (word >>> 10) & 0x3f, rm = (word >>> 16) & 31, opc = (word >>> 29) & 3;
    if (width === 32 && amount > 31) throw new UnsupportedInstruction(address, word);
    const shift = shifts[shiftCode]!, flags = opc === 3, invert = ((word >>> 21) & 1) === 1;
    if (opc === 0 || opc === 3) return { kind: "andReg", rd, rn, rm, shift, amount, flags, invert, width };
    if (opc === 1) return { kind: "orrReg", rd, rn, rm, shift, amount, invert, width };
    return { kind: "eorReg", rd, rn, rm, shift, amount, invert, width };
  }
  // Multiply-add/subtract, including the MUL/MNEG aliases (Ra = 31).
  if (((word >>> 24) & 0x1f) === 0x1b && ((word >>> 21) & 7) === 0) {
    const rm = (word >>> 16) & 31, subtract = ((word >>> 15) & 1) === 1, ra = (word >>> 10) & 31;
    return { kind: "madd", rd, rn, rm, ra, subtract, width };
  }
  // Long multiply-add/subtract (32-bit operands, 64-bit result).
  if (((word & 0xff200000) >>> 0) === 0x9b200000) {
    const rm = (word >>> 16) & 31, subtract = ((word >>> 15) & 1) === 1;
    const ra = (word >>> 10) & 31, signed = ((word >>> 23) & 1) === 0;
    return { kind: "multiplyLong", rd, rn, rm, ra, subtract, signed };
  }
  // Data-processing two source: divide and variable shift.
  if (((word & 0x1fe00000) >>> 0) === 0x1ac00000) {
    const rm = (word >>> 16) & 31, opcode = (word >>> 10) & 0x3f;
    if (opcode === 0x02) return { kind: "divide", rd, rn, rm, signed: false, width };
    if (opcode === 0x03) return { kind: "divide", rd, rn, rm, signed: true, width };
    if (opcode === 0x08) return { kind: "shiftReg", rd, rn, rm, shift: "lsl", width };
    if (opcode === 0x09) return { kind: "shiftReg", rd, rn, rm, shift: "lsr", width };
    if (opcode === 0x0a) return { kind: "shiftReg", rd, rn, rm, shift: "asr", width };
    throw new UnsupportedInstruction(address, word);
  }
  // Conditional select family.
  if (((word & 0x1fe00000) >>> 0) === 0x1a800000 && ((word >>> 10) & 3) <= 1) {
    const rm = (word >>> 16) & 31, condition = conditions[word & 0xf]!;
    if (condition === "nv") throw new UnsupportedInstruction(address, word);
    const op = (word >>> 30) & 1, increment = ((word >>> 10) & 1) === 1;
    return { kind: "select", rd, rn, rm, condition, invert: op === 1, increment, width };
  }
  // PC-relative address.
  if (((word & 0x1f000000) >>> 0) === 0x10000000) {
    const page = ((word >>> 31) & 1) === 1;
    const immediate = BigInt(signExtend(((word >>> 5) & 0x7ffff), 19)) << 2n | BigInt((word >>> 29) & 3);
    const base = BigInt(page ? address & ~0xfff : address);
    return { kind: "address", rd, value: base + (page ? immediate << 12n : immediate) };
  }
  // Load register literal.
  if (((word & 0x3b000000) >>> 0) === 0x18000000 && ((word >>> 26) & 1) === 0) {
    const opc = (word >>> 30) & 3, target = address + signExtend((word >>> 5) & 0x7ffff, 19) * 4;
    if (opc === 0 || opc === 1) return { kind: "loadLiteral", rd, value: BigInt(target), width: opc === 0 ? 32 : 64 };
    throw new UnsupportedInstruction(address, word);
  }
  // Load/store pair, 64-bit, signed offset with optional writeback.
  if (((word & 0x3a000000) >>> 0) === 0x28000000 && ((word >>> 26) & 1) === 0) {
    const load = ((word >>> 22) & 1) === 1, mode = (word >>> 23) & 3, opc = (word >>> 30) & 3;
    if (opc > 2 || (opc === 2 && !load)) throw new UnsupportedInstruction(address, word);
    const element: 32 | 64 = opc === 0 ? 32 : 64;
    const immediate = Number(BigInt(signExtend((word >>> 15) & 0x7f, 7)) * BigInt(element / 8));
    // 01 = post-index, 11 = pre-index, 00 = no-allocate and 10 = plain signed offset.
    const writeback = mode === 1 ? "post" as const : mode === 3 ? "pre" as const : "none" as const;
    const rt = word & 31, rt2 = (word >>> 10) & 31;
    if (load) return { kind: "loadPair", rt, rt2, rn, offset: immediate, size: element,
      ...(opc === 2 ? { signed: true } : {}), writeback };
    return { kind: "storePair", rt, rt2, rn, offset: immediate, size: element, writeback };
  }
  // Load/store with a signed 9-bit offset, optionally writing the base back.
  if (((word & 0x3b200000) >>> 0) === 0x38000000 && ((word >>> 26) & 1) === 0) {
    const sizeBits = (word >>> 30) & 3, opc = (word >>> 22) & 3;
    const mode = (word >>> 10) & 3;
    if (mode === 2) throw new UnsupportedInstruction(address, word);
    const size = (sizeBits === 0 ? 8 : sizeBits === 1 ? 16 : sizeBits === 2 ? 32 : 64) as 8 | 16 | 32 | 64;
    const offset = signExtend((word >>> 12) & 0x1ff, 9);
    const writeback = mode === 1 ? "post" as const : mode === 3 ? "pre" as const : undefined;
    const field = { rn, offset, size, ...(writeback ? { writeback } : {}) };
    if (opc === 0) return { kind: "store", rt: word & 31, ...field };
    if (opc === 1) return { kind: "load", rd: word & 31, ...field, signed: false };
    if (opc === 2 && size !== 64) return { kind: "load", rd: word & 31, ...field, size, signed: true };
    if (opc === 3 && size === 64) return { kind: "load", rd: word & 31, ...field, size: 64, signed: false };
    throw new UnsupportedInstruction(address, word);
  }
  // Load/store with a register offset.
  if (((word & 0x3b200c00) >>> 0) === 0x38200800 && ((word >>> 26) & 1) === 0) {
    const sizeBits = (word >>> 30) & 3, opc = (word >>> 22) & 3, rm = (word >>> 16) & 31, option = (word >>> 13) & 7;
    if (option !== 3 && option !== 2) throw new UnsupportedInstruction(address, word);
    const size = (sizeBits === 0 ? 8 : sizeBits === 1 ? 16 : sizeBits === 2 ? 32 : 64) as 8 | 16 | 32 | 64;
    const indexWidth: Width = option === 2 ? 32 : 64;
    if (opc === 0) return { kind: "store", rt: word & 31, rn, rm, indexWidth, offset: 0, size };
    if (opc === 1) return { kind: "load", rd: word & 31, rn, rm, indexWidth, offset: 0, size, signed: false };
    if (opc === 2 && size !== 64) return { kind: "load", rd: word & 31, rn, rm, indexWidth, offset: 0, size, signed: true };
    if (opc === 3 && size === 64) return { kind: "load", rd: word & 31, rn, rm, indexWidth, offset: 0, size: 64, signed: false };
    throw new UnsupportedInstruction(address, word);
  }
  // Load/store with an unsigned immediate offset.
  if (((word & 0x3b000000) >>> 0) === 0x39000000 && ((word >>> 26) & 1) === 0) {
    const sizeBits = (word >>> 30) & 3, opc = (word >>> 22) & 3;
    const size = (sizeBits === 0 ? 8 : sizeBits === 1 ? 16 : sizeBits === 2 ? 32 : 64) as 8 | 16 | 32 | 64;
    const offset = ((word >>> 10) & 0xfff) * (size / 8);
    if (opc === 0) return { kind: "store", rt: word & 31, rn, offset, size };
    if (opc === 1) return { kind: "load", rd: word & 31, rn, offset, size, signed: false };
    if (opc === 2 && size !== 64) return { kind: "load", rd: word & 31, rn, offset, size, signed: true };
    if (opc === 3 && size === 64) return { kind: "load", rd: word & 31, rn, offset, size: 64, signed: false };
    throw new UnsupportedInstruction(address, word);
  }
  // Branches.
  if (((word & 0xfc000000) >>> 0) === 0x14000000) return { kind: "branch", target: address + signExtend26((word & 0x03ffffff) << 2) };
  if (((word & 0xfc000000) >>> 0) === 0x94000000) return { kind: "branchLink", target: address + signExtend26((word & 0x03ffffff) << 2) };
  if (((word & 0xff000010) >>> 0) === 0x54000000) {
    const condition = conditions[word & 0xf]!;
    if (condition === "nv") throw new UnsupportedInstruction(address, word);
    return { kind: "branchCond", condition, target: address + signExtend19((word >>> 5) & 0x7ffff) };
  }
  if (((word & 0x7e000000) >>> 0) === 0x34000000) {
    const branchIfZero = ((word >>> 24) & 1) === 0;
    return { kind: "compareZero", register: rd, branchIfZero, target: address + signExtend19((word >>> 5) & 0x7ffff), width };
  }
  throw new UnsupportedInstruction(address, word);
}

function signExtend(value: number, bits: number): number { return (value << (32 - bits)) >> (32 - bits); }
function signExtend19(value: number): number { return signExtend(value, 19) << 2; }
function signExtend26(value: number): number { return signExtend(value, 26); }

/** Decodes the AArch64 bitmask immediate used by logical (immediate) instructions. */
function bitmaskImmediate(n: number, immediateR: number, immediateS: number, width: Width): bigint {
  const combined = (n << 6) | (~immediateS & 0x3f);
  const length = 31 - Math.clz32(combined & 0x7f);
  if (length < 1) throw new Error("Undefined bitmask immediate");
  const size = 1 << length, levels = size - 1;
  if ((immediateS & levels) === levels) throw new Error("Undefined bitmask immediate");
  const s = immediateS & levels, r = immediateR & levels, mask = (1n << BigInt(size)) - 1n;
  const element = (1n << BigInt(s + 1)) - 1n;
  const rotated = ((element >> BigInt(r)) | (element << BigInt(size - r))) & mask;
  let result = 0n;
  for (let position = 0; position < width; position += size) result |= rotated << BigInt(position);
  return result & (width === 32 ? 0xffffffffn : 0xffffffffffffffffn);
}
