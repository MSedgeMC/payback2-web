import { Code, I64, OP, buildModule } from "./wasm.ts";
import { decode, UnsupportedInstruction } from "./arm64.ts";
import type { Condition, Instruction } from "./arm64.ts";

// The register file lives in linear memory so the host can seed and inspect it.
// Offsets: x0..x30 = 0..247, sp = 248, nzcv = 256, pc = 264.
export const REGISTER_FILE_BYTES = 34 * 8, STACK_POINTER_OFFSET = 31 * 8, FLAGS_OFFSET = 32 * 8, PC_OFFSET = 33 * 8;
const SP = 31, FLAGS = 32, PC = 33, T0 = 34, T1 = 35, T2 = 36;
const LOCAL_COUNT = 37;
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
  body.block();                                   // EXIT
  body.loop();                                    // DISPATCH
  for (let index = count - 1; index >= 0; index--) body.block();
  body.get(PC); body.raw(OP.wrapI64);
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
    body.i64(BigInt(target)); body.set(PC);
    body.br((context.indexOf.has(target) ? context.dispatch : context.exit) + nested);
  };
  for (const instruction of block) {
    switch (instruction.kind) {
      case "nop": break;
      case "unsupported":
        // Leave the address program counter intact so the interpreter handles it.
        body.i64(BigInt(instruction.address)); body.set(PC); body.br(context.exit); return;
      case "branchLink": body.i64(BigInt(instruction.address)); body.set(PC); body.br(context.exit); return;
      case "return": body.get(30); body.set(PC); body.br(context.exit); return;
      case "branch": jump(instruction.target); return;
      case "branchCond": {
        emitCondition(body, instruction.condition);
        body.ifThen(); jump(instruction.target, 1); body.end();
        continue;
      }
      case "compareZero": {
        body.get(instruction.register);
        body.raw(OP.eqz64);
        if (!instruction.branchIfZero) body.raw(OP.eqz32);
        body.ifThen(); jump(instruction.target, 1); body.end();
        continue;
      }
      case "movz": body.i64(instruction.value); if (instruction.rd !== 31) body.set(instruction.rd); else body.drop(); break;
      case "movk": {
        if (instruction.rd === 31) break;
        const mask = ~((0xffffn << BigInt(instruction.shift)) & 0xffffffffffffffffn);
        body.get(instruction.rd); body.i64(mask); body.raw(I64_AND);
        body.i64(instruction.value); body.raw(OP.or64); body.set(instruction.rd);
        break;
      }
      case "addImm": case "subImm": case "addReg": case "subReg": {
        const left = instruction.rn === 31 ? SP : instruction.rn;
        const subtract = instruction.kind === "subImm" || instruction.kind === "subReg";
        body.get(left); body.set(T0);                                      // a survives a clobber of rn
        if (instruction.kind === "addImm" || instruction.kind === "subImm") body.i64(instruction.immediate);
        else body.get(instruction.rm);
        body.set(T1);                                                      // b survives a clobber of rm
        body.get(T0); body.get(T1); body.raw(subtract ? OP.sub64 : OP.add64); body.set(T2);
        if (instruction.rd !== 31) { body.get(T2); body.set(instruction.rd); }
        if (instruction.flags) emitFlags(body, subtract, T0, T1, T2);
        break;
      }
      case "andReg": case "orrReg": case "eorReg": {
        body.get(instruction.rn); body.set(T0);
        body.get(instruction.kind === "orrReg" ? instruction.rm : instruction.rm);
        const operation = instruction.kind === "andReg" ? I64_AND : instruction.kind === "orrReg" ? OP.or64 : OP.xor64;
        body.raw(operation); body.set(T2);
        if (instruction.rd !== 31) { body.get(T2); body.set(instruction.rd); }
        if (instruction.kind === "andReg" && instruction.flags) emitLogicFlags(body, T2);
        break;
      }
      case "load": {
        body.get(instruction.rn === 31 ? SP : instruction.rn); body.raw(OP.wrapI64);
        body.load("i64", instruction.offset);
        if (instruction.rd !== 31) body.set(instruction.rd); else body.drop();
        break;
      }
      case "store": {
        body.get(instruction.rn === 31 ? SP : instruction.rn); body.raw(OP.wrapI64);
        if (instruction.rt === 31) body.i64(0n); else body.get(instruction.rt);
        body.store("i64", instruction.offset);
        break;
      }
      default: throw new Error(`Translator cannot emit ${(instruction as Decoded).kind}`);
    }
  }
  const next = context.addresses[context.index]! + block.length * 4;
  jump(next);
}

function emitCondition(body: Code, condition: Condition): void {
  const bitSet = (bit: bigint): void => { body.get(FLAGS); body.i64(bit); body.raw(I64_AND); body.raw(OP.eqz64); body.raw(OP.eqz32); };
  const bitClear = (bit: bigint): void => { body.get(FLAGS); body.i64(bit); body.raw(I64_AND); body.raw(OP.eqz64); };
  const flagEquals = (): void => {
    body.get(FLAGS); body.i64(FLAG_N); body.raw(I64_SHR_U);
    body.get(FLAGS); body.i64(FLAG_V); body.raw(I64_SHR_U); body.raw(OP.eq64);
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

/** Emits NZCV for an add or subtract from saved operands and the saved result. */
function emitFlags(body: Code, subtract: boolean, aLocal: number, bLocal: number, rLocal: number): void {
  // N: sign of the result.
  body.get(rLocal); body.i64(63n); body.raw(I64_SHR_U); body.i64(31n); body.raw(OP.shl64);
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
  body.raw(I64_AND); body.i64(63n); body.raw(I64_SHR_U); body.i64(28n); body.raw(OP.shl64); body.raw(OP.or64);
  body.set(FLAGS);
}

/** Logical operations define N and Z only; C and V are cleared. */
function emitLogicFlags(body: Code, rLocal: number): void {
  body.get(rLocal); body.i64(63n); body.raw(I64_SHR_U); body.i64(31n); body.raw(OP.shl64);
  body.get(rLocal); body.raw(OP.eqz64); body.raw(OP.extendI32U); body.i64(30n); body.raw(OP.shl64);
  body.raw(OP.or64); body.set(FLAGS);
}
