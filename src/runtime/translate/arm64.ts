// AArch64 decoding for the translated subset. Anything outside the subset is reported
// as unsupported rather than guessed, so the driver can fall back instead of mis-executing.

export type Condition = "eq" | "ne" | "cs" | "cc" | "mi" | "pl" | "vs" | "vc" | "hi" | "ls" | "ge" | "lt" | "gt" | "le" | "al" | "nv";

export type Instruction =
  | { kind: "addImm"; rd: number; rn: number; immediate: bigint; flags: boolean }
  | { kind: "subImm"; rd: number; rn: number; immediate: bigint; flags: boolean }
  | { kind: "addReg"; rd: number; rn: number; rm: number; flags: boolean }
  | { kind: "subReg"; rd: number; rn: number; rm: number; flags: boolean }
  | { kind: "andReg"; rd: number; rn: number; rm: number; flags: boolean }
  | { kind: "orrReg"; rd: number; rn: number; rm: number }
  | { kind: "eorReg"; rd: number; rn: number; rm: number }
  | { kind: "movz"; rd: number; value: bigint; shift: number }
  | { kind: "movk"; rd: number; value: bigint; shift: number }
  | { kind: "load"; rd: number; rn: number; offset: number }
  | { kind: "store"; rt: number; rn: number; offset: number }
  | { kind: "branch"; target: number }
  | { kind: "branchLink"; target: number }
  | { kind: "branchCond"; condition: Condition; target: number }
  | { kind: "compareZero"; register: number; target: number; branchIfZero: boolean }
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

const conditions: readonly Condition[] = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"];

/** Decodes one instruction; `address` is the guest address of `word`. */
export function decode(address: number, word: number): Instruction {
  const rd = word & 31, rn = (word >>> 5) & 31;
  if (word === 0xd503201f) return { kind: "nop" };
  if (((word & 0xfffffc1f) >>> 0) === 0xd65f0000) {
    if (rn !== 30) throw new UnsupportedInstruction(address, word);
    return { kind: "return" };
  }
  // Move wide immediates: MOVZ / MOVK, 64-bit only for now.
  if (((word & 0xff800000) >>> 0) === 0xd2800000 || ((word & 0xff800000) >>> 0) === 0xf2800000) {
    const movz = ((word & 0xff800000) >>> 0) === 0xd2800000;
    const shift = ((word >>> 21) & 3) * 16, value = BigInt((word >>> 5) & 0xffff) << BigInt(shift);
    return movz ? { kind: "movz", rd, value, shift } : { kind: "movk", rd, value, shift };
  }
  // Add/subtract immediate, 64-bit.
  if (((word & 0x1f000000) >>> 0) === 0x11000000) {
    // 32-bit forms are a wider change to the register model, so they stay in the fallback.
    if (((word >>> 31) & 1) !== 1) throw new UnsupportedInstruction(address, word);
    const flags = ((word >>> 29) & 1) === 1, subtract = ((word >>> 30) & 1) === 1;
    const shift = (word >>> 22) & 3;
    if (shift > 1) throw new UnsupportedInstruction(address, word);
    const immediate = BigInt((word >>> 10) & 0xfff) << BigInt(shift * 12);
    return { kind: subtract ? "subImm" : "addImm", rd, rn, immediate, flags };
  }
  // Add/subtract shifted register, 64-bit, LSL #0 only.
  if (((word & 0x1f000000) >>> 0) === 0x0b000000) {
    if (((word >>> 22) & 3) !== 0 || ((word >>> 10) & 0x3f) !== 0 || (word & 0x800) !== 0) throw new UnsupportedInstruction(address, word);
    const rm = (word >>> 16) & 31, flags = ((word >>> 29) & 1) === 1, subtract = ((word >>> 30) & 1) === 1;
    return { kind: subtract ? "subReg" : "addReg", rd, rn, rm, flags };
  }
  // Logical shifted register, 64-bit, LSL #0 only.
  if (((word & 0x1f000000) >>> 0) === 0x0a000000) {
    if (((word >>> 22) & 3) !== 0 || ((word >>> 10) & 0x3f) !== 0 || (word & 0x800) !== 0) throw new UnsupportedInstruction(address, word);
    const rm = (word >>> 16) & 31, opc = (word >>> 29) & 3;
    if (opc === 0) return { kind: "andReg", rd, rn, rm, flags: false };
    if (opc === 1) return { kind: "orrReg", rd, rn, rm };
    if (opc === 2) return { kind: "eorReg", rd, rn, rm };
    if (opc === 3) return { kind: "andReg", rd, rn, rm, flags: true };
    throw new UnsupportedInstruction(address, word);
  }
  // Load/store unsigned offset, 64-bit general registers.
  if (((word & 0xffc00000) >>> 0) === 0xf9400000) {
    return { kind: "load", rd: word & 31, rn, offset: ((word >>> 10) & 0xfff) * 8 };
  }
  if (((word & 0xffc00000) >>> 0) === 0xf9000000) {
    return { kind: "store", rt: word & 31, rn, offset: ((word >>> 10) & 0xfff) * 8 };
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
    const is64 = ((word >>> 31) & 1) === 1, branchIfZero = ((word >>> 24) & 1) === 0;
    if (!is64) throw new UnsupportedInstruction(address, word);
    return { kind: "compareZero", register: rd, branchIfZero, target: address + signExtend19((word >>> 5) & 0x7ffff) };
  }
  throw new UnsupportedInstruction(address, word);
}

function signExtend19(value: number): number { return (value << 13) >> 13 << 2; }
function signExtend26(value: number): number { return (value << 6) >> 6; }
