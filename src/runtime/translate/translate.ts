import { Code, I64, OP, buildModule } from "./wasm.ts";
import type { LoadKind, StoreKind } from "./wasm.ts";
import { decode, UnsupportedInstruction } from "./arm64.ts";
import type { Condition, Instruction } from "./arm64.ts";

// The register file lives in linear memory so the host can seed and inspect it.
// Offsets: x0..x30 = 0..247, sp = 248, nzcv = 256, pc = 264.
export const REGISTER_FILE_BYTES = 34 * 8, STACK_POINTER_OFFSET = 31 * 8, FLAGS_OFFSET = 32 * 8, PC_OFFSET = 33 * 8;
const SP = 31, FLAGS = 32, PC = 33, T0 = 34, T1 = 35, T2 = 36, T3 = 37, INDEX = 38;
const LOCAL_COUNT = 39;
const FLAG_N = 1n << 31n, FLAG_Z = 1n << 30n, FLAG_C = 1n << 29n, FLAG_V = 1n << 28n;
const I64_AND = 0x83, I64_SHR_U = 0x88, I32_AND = 0x71, I32_OR = 0x72;

type Decoded = (Instruction | { kind: "unsupported" }) & { address: number; word: number };
export type UnsupportedSite = { address: number; word: number };
export type TranslationResult = { module: WebAssembly.Module; entry: number; blocks: number; instructions: number; unsupported: UnsupportedSite[] };

/** Translates [start, end) into one WASM function with an in-module basic block dispatcher. */
export function translate(bytes: Uint8Array, start: number, end: number, memoryPages = 1): TranslationResult {
  if (!Number.isInteger(start) || !Number.isInteger(end) || start % 4 || end % 4 || start < 0 || end > bytes.length || start >= end) {
    throw new RangeError("Invalid translation range");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const decoded: Decoded[] = [], unsupported: UnsupportedSite[] = [], leaders = new Set<number>([start]);
  for (let address = start; address < end; address += 4) {
    const word = view.getUint32(address, true);
    let instruction: Instruction | undefined;
    try { instruction = decode(address, word); }
    catch (error) {
      if (!(error instanceof UnsupportedInstruction)) throw error;
      unsupported.push({ address, word }); leaders.add(address + 4);
      decoded.push({ kind: "unsupported", address, word }); continue;
    }
    decoded.push({ ...instruction, address, word });
    if (instruction.kind === "branch" || instruction.kind === "branchCond" || instruction.kind === "compareZero") {
      leaders.add(instruction.target); leaders.add(address + 4);
    } else if (instruction.kind === "branchLink" || instruction.kind === "return") leaders.add(address + 4);
  }
  const addresses = [...leaders].filter(address => address >= start && address < end).sort((a, b) => a - b);
  const indexOf = new Map(addresses.map((address, index) => [address, index]));
  const blocks: Decoded[][] = addresses.map(() => []);
  let current = 0;
  for (const instruction of decoded) {
    while (current + 1 < addresses.length && addresses[current + 1]! <= instruction.address) current++;
    blocks[current]!.push(instruction);
    if (instruction.kind === "branch" || instruction.kind === "return" || instruction.kind === "unsupported") {
      current = Math.min(current + 1, addresses.length - 1);
    }
  }

  const count = blocks.length, body = new Code();
  for (let local = 0; local < 34; local++) { body.i32(local * 8); body.load("i64", 0); body.set(local); }
  // Dispatch on a block index, resolving the entry pc once per call so that re-entry at an
  // arbitrary address (a returned-to caller) still lands on the right block.
  body.i64(0n); body.set(INDEX);
  for (let index = 1; index < count; index++) {
    body.get(PC); body.i64(BigInt(addresses[index]!)); body.raw(OP.eq64);
    body.ifThen(); body.i64(BigInt(index)); body.set(INDEX); body.end();
  }
  body.block();                                   // EXIT
  body.loop();                                    // DISPATCH
  for (let index = count - 1; index >= 0; index--) body.block();
  body.get(INDEX); body.raw(OP.wrapI64);
  body.brTable(Array.from({ length: count }, (_, index) => index), count + 1);
  const dispatchDepth = (index: number): number => count - 1 - index;
  const exitDepth = (index: number): number => count - index;
  blocks.forEach((block, index) => {
    body.end();
    emitBlock(body, block, { dispatch: dispatchDepth(index), exit: exitDepth(index), indexOf, addresses, index });
  });
  body.end();                                     // DISPATCH
  body.end();                                     // EXIT
  for (let local = 0; local < 34; local++) { body.i32(local * 8); body.get(local); body.store("i64", 0); }
  // buildModule appends the function's terminating end.
  const binary = buildModule(body, [{ count: LOCAL_COUNT, type: I64 }], memoryPages);
  const module = new WebAssembly.Module(binary.buffer.slice(binary.byteOffset, binary.byteOffset + binary.byteLength) as ArrayBuffer);
  return { module, entry: start, blocks: count, instructions: decoded.length, unsupported };
}

function emitBlock(body: Code, block: Decoded[], context: {
  dispatch: number; exit: number; indexOf: Map<number, number>; addresses: number[]; index: number;
}): void {
  // Branches emitted inside an `if` sit one scope deeper, so the depth must account for it.
  const jump = (target: number, nested = 0): void => {
    const block = context.indexOf.get(target);
    if (block === undefined) { body.i64(BigInt(target)); body.set(PC); body.br(context.exit + nested); return; }
    body.i64(BigInt(block)); body.set(INDEX); body.br(context.dispatch + nested);
  };
  const leave = (pc: number): void => { body.i64(BigInt(pc)); body.set(PC); body.br(context.exit); };
  const widthMask = (local: number, width: 32 | 64): void => {
    if (width === 64) return;
    body.get(local); body.i64(0xffffffffn); body.raw(I64_AND); body.set(local);
  };
  // Register 31 is SP in add/sub immediate form and ZR elsewhere.
  const operand = (register: number, spIsOperand: boolean): void => {
    if (register === 31) { if (spIsOperand) body.get(SP); else body.i64(0n); } else body.get(register);
  };
  const shifted = (register: number, shift: "lsl" | "lsr" | "asr", amount: number): void => {
    operand(register, false);
    if (!amount) return;
    body.i64(BigInt(amount));
    body.raw(shift === "lsl" ? OP.shl64 : shift === "lsr" ? OP.shrU64 : OP.shrS64);
  };
  const store = (rd: number, spIsOperand: boolean, width: 32 | 64): void => {
    widthMask(T2, width);
    if (rd === 31) { if (spIsOperand) { body.get(T2); body.set(SP); } return; }
    body.get(T2); body.set(rd);
  };

  for (const instruction of block) {
    switch (instruction.kind) {
      case "nop": break;
      case "unsupported": leave(instruction.address); return;
      case "return": body.get(30); body.set(PC); body.br(context.exit); return;
      case "branchReg": body.get(instruction.rn); body.set(PC); body.br(context.exit); return;
      case "branchLinkReg":
        body.i64(BigInt(instruction.address + 4)); body.set(30);
        body.get(instruction.rn); body.set(PC); body.br(context.exit); return;
      case "branchLink":
        // The driver re-enters for the callee, which keeps the guest call stack in one place.
        body.i64(BigInt(instruction.address + 4)); body.set(30);
        leave(instruction.target); return;
      case "branch": jump(instruction.target); return;
      case "branchCond":
        emitCondition(body, instruction.condition);
        body.ifThen(); jump(instruction.target, 1); body.end();
        continue;
      case "compareZero":
        body.get(instruction.register);
        if (instruction.width === 32) { body.i64(0xffffffffn); body.raw(I64_AND); }
        body.raw(OP.eqz64);
        if (!instruction.branchIfZero) body.raw(OP.eqz32);
        body.ifThen(); jump(instruction.target, 1); body.end();
        continue;
      case "movz": case "movn":
        if (instruction.rd === 31) break;
        body.i64(instruction.value); body.set(instruction.rd); break;
      case "movk": {
        if (instruction.rd === 31) break;
        // The complement must be masked back into 64 bits or it exceeds the i64 range.
        const mask = (~(0xffffn << BigInt(instruction.shift))) & 0xffffffffffffffffn;
        body.get(instruction.rd); body.i64(mask); body.raw(I64_AND);
        body.i64(instruction.value); body.raw(OP.or64); body.set(instruction.rd);
        break;
      }
      case "addImm": case "subImm": case "addReg": case "subReg": {
        const subtract = instruction.kind === "subImm" || instruction.kind === "subReg";
        const immediateForm = instruction.kind === "addImm" || instruction.kind === "subImm";
        operand(instruction.rn, immediateForm);
        body.set(T0);
        if (immediateForm) body.i64(instruction.immediate);
        else shifted(instruction.rm, instruction.shift, instruction.amount);
        body.set(T1);
        body.get(T0); body.get(T1); body.raw(subtract ? OP.sub64 : OP.add64); body.set(T2);
        store(instruction.rd, immediateForm && !instruction.flags, instruction.width);
        // A 32-bit operation sets N and Z from the 32-bit result.
        if (instruction.flags) emitFlags(body, subtract, T0, T1, T2, instruction.width);
        break;
      }
      case "andReg": case "orrReg": case "eorReg": {
        // Both operands must stay on the operand stack for the binary instruction.
        operand(instruction.rn, false);
        shifted(instruction.rm, instruction.shift, instruction.amount);
        body.raw(instruction.kind === "andReg" ? I64_AND : instruction.kind === "orrReg" ? OP.or64 : OP.xor64);
        body.set(T2);
        store(instruction.rd, false, instruction.width);
        if (instruction.kind === "andReg" && instruction.flags) emitLogicFlags(body, T2, instruction.width);
        break;
      }
      case "logicImm": {
        operand(instruction.rn, false);
        body.i64(instruction.value);
        body.raw(instruction.operation === "and" ? I64_AND : instruction.operation === "orr" ? OP.or64 : OP.xor64);
        body.set(T2);
        store(instruction.rd, false, instruction.width);
        if (instruction.flags) emitLogicFlags(body, T2, instruction.width);
        break;
      }
      case "testBit": {
        operand(instruction.register, false);
        body.i64(BigInt(instruction.bit)); body.raw(I64_SHR_U); body.i64(1n); body.raw(I64_AND);
        body.raw(OP.eqz64);
        if (instruction.branchIfSet) body.raw(OP.eqz32);
        body.ifThen(); jump(instruction.target, 1); body.end();
        continue;
      }
      case "madd": {
        operand(instruction.rn, false); body.set(T0);
        operand(instruction.rm, false); body.set(T1);
        body.get(T0); body.get(T1); body.raw(OP.mul64); body.set(T2);
        // MUL/MNEG use Ra = 31, which means the addend is zero (or the product is negated).
        if (instruction.ra !== 31) { body.get(T2); body.get(instruction.ra); body.raw(instruction.subtract ? OP.sub64 : OP.add64); body.set(T2); }
        else if (instruction.subtract) { body.i64(0n); body.get(T2); body.raw(OP.sub64); body.set(T2); }
        store(instruction.rd, false, instruction.width);
        break;
      }
      case "divide": {
        // 32-bit signed division needs sign-extended operands, not zero-extended ones.
        const extend = (register: number, target: number): void => {
          operand(register, false); body.set(target);
          if (instruction.width === 32 && instruction.signed) {
            body.get(target); body.i64(32n); body.raw(OP.shl64); body.i64(32n); body.raw(OP.shrS64); body.set(target);
          } else if (instruction.width === 32) {
            body.get(target); body.i64(0xffffffffn); body.raw(I64_AND); body.set(target);
          }
        };
        extend(instruction.rn, T0); extend(instruction.rm, T1);
        body.get(T0); body.get(T1); body.raw(instruction.signed ? OP.divS64 : OP.divU64); body.set(T2);
        store(instruction.rd, false, instruction.width);
        break;
      }
      case "shiftReg": {
        operand(instruction.rn, false); body.set(T0);
        operand(instruction.rm, false); body.set(T1);
        body.get(T0); body.get(T1); body.raw(instruction.shift === "lsl" ? OP.shl64 : instruction.shift === "lsr" ? OP.shrU64 : OP.shrS64);
        body.set(T2);
        store(instruction.rd, false, instruction.width);
        break;
      }
      case "bitfield": {
        operand(instruction.rn, false); body.set(T0);
        const bits = instruction.width, immr = instruction.immediateR, imms = instruction.immediateS;
        const maskOf = (count: number): bigint => (1n << BigInt(count)) - 1n;
        const fieldWidth = imms >= immr ? imms - immr + 1 : imms + 1;
        if (imms >= immr) { body.get(T0); body.i64(BigInt(immr)); body.raw(OP.shrU64); }
        else { body.get(T0); body.i64(maskOf(fieldWidth)); body.raw(I64_AND); body.i64(BigInt(bits - immr)); body.raw(OP.shl64); }
        body.i64(maskOf(fieldWidth)); body.raw(I64_AND);
        body.set(T2);
        if (instruction.operation === "sbfm") {
          const topBit = (imms >= immr ? fieldWidth - 1 : fieldWidth - 1 + (bits - immr));
          const shift = 64 - (topBit + 1);
          if (shift > 0) {
            body.get(T2); body.i64(BigInt(shift)); body.raw(OP.shl64);
            body.i64(BigInt(shift)); body.raw(OP.shrS64); body.set(T2);
          }
        }
        store(instruction.rd, false, instruction.width);
        break;
      }
      case "select": {
        operand(instruction.rn, false); body.set(T0);
        operand(instruction.rm, false); body.set(T1);
        if (instruction.increment) { body.get(T1); body.i64(1n); body.raw(OP.add64); body.set(T1); }
        if (instruction.invert) { body.get(T1); body.i64(-1n); body.raw(OP.xor64); body.set(T1); }
        body.get(T0); body.get(T1);
        emitCondition(body, instruction.condition); body.raw(OP.select);
        body.set(T2);
        store(instruction.rd, false, instruction.width);
        break;
      }
      case "load": {
        if (instruction.rd === 31) break;
        operand(instruction.rn, true);
        if (instruction.rm !== undefined) {
          body.get(instruction.rm);
          if (instruction.indexWidth === 32) { body.i64(0xffffffffn); body.raw(I64_AND); }
          body.raw(OP.add64);
        }
        body.set(T3);
        // Pre-index folds the offset into the base before the access.
        if (instruction.writeback === "pre") {
          body.get(T3); body.i64(BigInt(instruction.offset)); body.raw(OP.add64); body.set(T3);
          body.get(T3); body.set(instruction.rn === 31 ? SP : instruction.rn);
        }
        body.get(T3); body.raw(OP.wrapI64);
        body.load(loadKind(instruction.size, instruction.signed), instruction.writeback === "pre" ? 0 : instruction.offset);
        body.set(instruction.rd);
        if (instruction.writeback === "post") {
          body.get(T3); body.i64(BigInt(instruction.offset)); body.raw(OP.add64);
          body.set(instruction.rn === 31 ? SP : instruction.rn);
        }
        break;
      }
      case "store": {
        operand(instruction.rn, true);
        if (instruction.rm !== undefined) {
          body.get(instruction.rm);
          if (instruction.indexWidth === 32) { body.i64(0xffffffffn); body.raw(I64_AND); }
          body.raw(OP.add64);
        }
        body.set(T3);
        if (instruction.writeback === "pre") {
          body.get(T3); body.i64(BigInt(instruction.offset)); body.raw(OP.add64); body.set(T3);
          body.get(T3); body.set(instruction.rn === 31 ? SP : instruction.rn);
        }
        body.get(T3); body.raw(OP.wrapI64);
        if (instruction.rt === 31) body.i64(0n); else body.get(instruction.rt);
        body.store(storeKind(instruction.size), instruction.writeback === "pre" ? 0 : instruction.offset);
        if (instruction.writeback === "post") {
          body.get(T3); body.i64(BigInt(instruction.offset)); body.raw(OP.add64);
          body.set(instruction.rn === 31 ? SP : instruction.rn);
        }
        break;
      }
      case "loadPair": case "storePair": {
        const stride = instruction.size / 8;
        operand(instruction.rn, true); body.set(T3);
        const address = (extra: number): void => { body.get(T3); if (extra) { body.i64(BigInt(extra)); body.raw(OP.add64); } body.raw(OP.wrapI64); };
        const kind = instruction.kind === "loadPair" && instruction.signed ? "i64_32s" as const
          : instruction.size === 64 ? "i64" as const : "i64_32u" as const;
        if (instruction.kind === "loadPair") {
          if (instruction.rt !== 31) { address(instruction.offset); body.load(kind, 0); body.set(instruction.rt); }
          if (instruction.rt2 !== 31) { address(instruction.offset + stride); body.load(kind, 0); body.set(instruction.rt2); }
        } else {
          address(instruction.offset); if (instruction.rt === 31) body.i64(0n); else body.get(instruction.rt);
          body.store(instruction.size === 64 ? "i64" : "i64_32", 0);
          address(instruction.offset + stride); if (instruction.rt2 === 31) body.i64(0n); else body.get(instruction.rt2);
          body.store(instruction.size === 64 ? "i64" : "i64_32", 0);
        }
        if (instruction.writeback !== "none") {
          const adjustment = instruction.writeback === "post" ? instruction.offset : instruction.offset;
          body.get(instruction.rn === 31 ? SP : instruction.rn);
          body.i64(BigInt(adjustment)); body.raw(OP.add64);
          body.set(instruction.rn === 31 ? SP : instruction.rn);
        }
        break;
      }
      case "address":
        if (instruction.rd !== 31) { body.i64(instruction.value); body.set(instruction.rd); }
        break;
      case "loadLiteral":
        if (instruction.rd !== 31) { body.i64(instruction.value); body.set(instruction.rd); }
        break;
      default: throw new Error(`Translator cannot emit ${(instruction as Decoded).kind}`);
    }
  }
  const next = context.addresses[context.index]! + block.length * 4;
  jump(next);
}

function emitCondition(body: Code, condition: Condition): void {
  const bitSet = (bit: bigint): void => { body.get(FLAGS); body.i64(bit); body.raw(I64_AND); body.raw(OP.eqz64); body.raw(OP.eqz32); };
  const bitClear = (bit: bigint): void => { body.get(FLAGS); body.i64(bit); body.raw(I64_AND); body.raw(OP.eqz64); };
  // V sits at bit 28, so each flag must be masked to one bit before comparing N with V.
  const flagEquals = (): void => {
    const bit = (shift: bigint): void => {
      body.get(FLAGS); body.i64(shift); body.raw(I64_SHR_U); body.i64(1n); body.raw(I64_AND);
    };
    bit(31n); bit(28n); body.raw(OP.eq64);
  };
  switch (condition) {
    case "al": body.i64(1n); body.raw(OP.wrapI64); return;
    case "eq": bitSet(FLAG_Z); return;
    case "ne": bitClear(FLAG_Z); return;
    case "cs": bitSet(FLAG_C); return;
    case "cc": bitClear(FLAG_C); return;
    case "mi": bitSet(FLAG_N); return;
    case "pl": bitClear(FLAG_N); return;
    case "vs": bitSet(FLAG_V); return;
    case "vc": bitClear(FLAG_V); return;
    case "hi": bitSet(FLAG_C); bitClear(FLAG_Z); body.raw(I32_AND); return;
    case "ls": bitClear(FLAG_C); bitSet(FLAG_Z); body.raw(I32_OR); return;
    case "ge": flagEquals(); return;
    case "lt": flagEquals(); body.raw(OP.eqz32); return;
    case "gt": bitClear(FLAG_Z); flagEquals(); body.raw(I32_AND); return;
    case "le": bitSet(FLAG_Z); flagEquals(); body.raw(OP.eqz32); body.raw(I32_OR); return;
    default: throw new Error(`Translator cannot emit condition ${condition as string}`);
  }
}

function loadKind(size: 8 | 16 | 32 | 64, signed: boolean): LoadKind {
  if (size === 64) return "i64";
  if (size === 32) return signed ? "i64_32s" : "i64_32u";
  if (size === 16) return signed ? "i64_16s" : "i64_16u";
  return signed ? "i64_8s" : "i64_8u";
}
function storeKind(size: 8 | 16 | 32 | 64): StoreKind {
  return size === 64 ? "i64" : size === 32 ? "i64_32" : size === 16 ? "i64_16" : "i64_8";
}

/** Emits NZCV for an add or subtract from saved operands and the saved result. */
function emitFlags(body: Code, subtract: boolean, aLocal: number, bLocal: number, rLocal: number, width: 32 | 64 = 64): void {
  const signBit = BigInt(width - 1);
  // N: sign of the result.
  body.get(rLocal); body.i64(signBit); body.raw(I64_SHR_U); body.i64(31n); body.raw(OP.shl64);
  // Z: result is zero.
  body.get(rLocal); body.raw(OP.eqz64); body.raw(OP.extendI32U); body.i64(30n); body.raw(OP.shl64);
  body.raw(OP.or64);
  // C: unsigned borrow for subtraction, unsigned carry out for addition.
  if (subtract) { body.get(aLocal); body.get(bLocal); body.raw(OP.geU64); }
  else { body.get(rLocal); body.get(aLocal); body.raw(OP.ltU64); }
  body.raw(OP.extendI32U); body.i64(29n); body.raw(OP.shl64); body.raw(OP.or64);
  // V: signed overflow from the operands and the result.
  if (subtract) { body.get(aLocal); body.get(bLocal); body.raw(OP.xor64); body.get(aLocal); body.get(rLocal); body.raw(OP.xor64); }
  else { body.get(aLocal); body.get(rLocal); body.raw(OP.xor64); body.get(bLocal); body.get(rLocal); body.raw(OP.xor64); }
  body.raw(I64_AND); body.i64(signBit); body.raw(I64_SHR_U); body.i64(28n); body.raw(OP.shl64); body.raw(OP.or64);
  body.set(FLAGS);
}

/** Logical operations define N and Z only; C and V are cleared. */
function emitLogicFlags(body: Code, rLocal: number, width: 32 | 64 = 64): void {
  body.get(rLocal); body.i64(BigInt(width - 1)); body.raw(I64_SHR_U); body.i64(31n); body.raw(OP.shl64);
  body.get(rLocal); body.raw(OP.eqz64); body.raw(OP.extendI32U); body.i64(30n); body.raw(OP.shl64);
  body.raw(OP.or64); body.set(FLAGS);
}
