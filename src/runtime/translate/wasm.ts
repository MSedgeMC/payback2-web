// Minimal WebAssembly binary builder for translated guest code.
// Only the sections a translation unit needs are emitted: one function, its memory,
// and the two exports the driver uses.

export const I32 = 0x7f, I64 = 0x7e, F32 = 0x7d, F64 = 0x7c, V128 = 0x7b, EMPTY_BLOCK = 0x40;

export type LoadKind = "f32" | "f64" | "i32" | "i64" | "i64_8s" | "i64_8u" | "i64_16s" | "i64_16u" | "i64_32s" | "i64_32u";
export type StoreKind = "f32" | "f64" | "i32" | "i64" | "i64_8" | "i64_16" | "i64_32";
const LOAD_OPCODES: Record<LoadKind, number> = { f32: 0x2a, f64: 0x2b, i32: 0x28, i64: 0x29, i64_8s: 0x30, i64_8u: 0x31, i64_16s: 0x32, i64_16u: 0x33, i64_32s: 0x34, i64_32u: 0x35 };
const STORE_OPCODES: Record<StoreKind, number> = { f32: 0x38, f64: 0x39, i32: 0x36, i64: 0x37, i64_8: 0x3c, i64_16: 0x3d, i64_32: 0x3e };
// Natural alignment in bytes is expressed as log2 for the memarg immediate.
const ALIGN: Record<number, number> = { 0x2a: 2, 0x38: 2, 0x2b: 3, 0x39: 3, 0x28: 2, 0x29: 3, 0x30: 0, 0x31: 0, 0x32: 1, 0x33: 1, 0x34: 2, 0x35: 2, 0x36: 2, 0x37: 3, 0x3c: 0, 0x3d: 1, 0x3e: 2 };

export function uleb(value: number): number[] {
  if (!Number.isInteger(value) || value < 0) throw new RangeError("uleb expects a non-negative integer");
  const bytes: number[] = [];
  let remaining = value;
  do { let byte = remaining & 0x7f; remaining = Math.floor(remaining / 128); if (remaining) byte |= 0x80; bytes.push(byte); } while (remaining);
  return bytes;
}

export function sleb(value: bigint): number[] {
  const bytes: number[] = [];
  let remaining = value, more = true;
  while (more) {
    const byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    const sign = (byte & 0x40) !== 0;
    more = !((remaining === 0n && !sign) || (remaining === -1n && sign));
    bytes.push(more ? byte | 0x80 : byte);
  }
  return bytes;
}

/** Instruction and section assembler. */
export class Code {
  readonly bytes: number[] = [];

  raw(...values: number[]): this { this.bytes.push(...values); return this; }
  u32(value: number): this { this.bytes.push(...uleb(value)); return this; }
  // i64.const is a signed LEB128, so a 64-bit pattern with the top bit set must be
  // encoded as the equivalent negative value or the varint grows past 64 bits.
  i64(value: bigint): this { this.bytes.push(0x42, ...sleb(BigInt.asIntN(64, value))); return this; }
  i32(value: number): this { this.bytes.push(0x41, ...sleb(BigInt(value))); return this; }
  op(code: number): this { this.bytes.push(code); return this; }
  get(index: number): this { this.bytes.push(0x20, ...uleb(index)); return this; }
  set(index: number): this { this.bytes.push(0x21, ...uleb(index)); return this; }
  tee(index: number): this { this.bytes.push(0x22, ...uleb(index)); return this; }
  block(): this { this.bytes.push(0x02, EMPTY_BLOCK); return this; }
  loop(): this { this.bytes.push(0x03, EMPTY_BLOCK); return this; }
  ifThen(): this { this.bytes.push(0x04, EMPTY_BLOCK); return this; }
  end(): this { this.bytes.push(0x0b); return this; }
  br(depth: number): this { this.bytes.push(0x0c, ...uleb(depth)); return this; }
  brIf(depth: number): this { this.bytes.push(0x0d, ...uleb(depth)); return this; }
  brTable(labels: readonly number[], fallback: number): this {
    this.bytes.push(0x0e, ...uleb(labels.length));
    for (const label of labels) this.bytes.push(...uleb(label));
    this.bytes.push(...uleb(fallback));
    return this;
  }
  call(index: number): this { this.bytes.push(0x10, ...uleb(index)); return this; }
  drop(): this { this.bytes.push(0x1a); return this; }
  ret(): this { this.bytes.push(0x0f); return this; }
  f64(value: number): this { this.bytes.push(0x44); for (const byte of new Uint8Array(new Float64Array([value]).buffer)) this.bytes.push(byte); return this; }
  getF(index: number): this { this.bytes.push(0x20, ...uleb(index)); return this; }
  setF(index: number): this { this.bytes.push(0x21, ...uleb(index)); return this; }
  /** Saturating float-to-integer conversions never trap on out-of-range values. */
  truncSat(kind: "i64_s" | "i64_u" | "i64_f32_s" | "i64_f32_u"): this {
    const opcode = { i64_s: 6, i64_u: 7, i64_f32_s: 4, i64_f32_u: 5 }[kind];
    this.bytes.push(0xfc, ...uleb(opcode));
    return this;
  }
  load(kind: LoadKind, offset: number): this {
    this.bytes.push(LOAD_OPCODES[kind], ...uleb(ALIGN[LOAD_OPCODES[kind]!] ?? 0), ...uleb(offset));
    return this;
  }
  store(kind: StoreKind, offset: number): this {
    this.bytes.push(STORE_OPCODES[kind], ...uleb(ALIGN[STORE_OPCODES[kind]!] ?? 0), ...uleb(offset));
    return this;
  }
}

// Instruction opcodes used by the translator.
export const OP = {
  eqz64: 0x50, eq64: 0x51, ne64: 0x52, ltS64: 0x53, ltU64: 0x54, gtS64: 0x55, gtU64: 0x56,
  leS64: 0x57, leU64: 0x58, geS64: 0x59, geU64: 0x5a,
  eqz32: 0x45, ne32: 0x47, divS64: 0x7f, divU64: 0x80, select: 0x1b,
  // Floating point, all operating on f64 locals.
  f64abs: 0x99, f64neg: 0x9a, f64sqrt: 0x9f, f64add: 0xa0, f64sub: 0xa1, f64mul: 0xa2, f64div: 0xa3,
  f64min: 0xa4, f64max: 0xa5, f64eq: 0x61, f64ne: 0x62, f64lt: 0x63, f64gt: 0x64, f64le: 0x65, f64ge: 0x66,
  f32abs: 0x8b, f32neg: 0x8c, f32sqrt: 0x91, f32add: 0x92, f32sub: 0x93, f32mul: 0x94, f32div: 0x95,
  f32min: 0x96, f32max: 0x97, f32eq: 0x5b, f32ne: 0x5c, f32lt: 0x5d, f32gt: 0x5e, f32le: 0x5f, f32ge: 0x60,
  f32demote: 0xb6, f64promote: 0xbb, f32convertIS: 0xb4, f32convertIU: 0xb5,
  i32reinterpretF32: 0xbe, f32reinterpretI32: 0xbf,
  f64convertIS: 0xb9, f64convertIU: 0xba, i64truncFS: 0xb0, i64truncFU: 0xb1,
  i64reinterpretF64: 0xbc, f64reinterpretI64: 0xbd, i32wrapI64x: 0xa7,
  add64: 0x7c, sub64: 0x7d, mul64: 0x7e, and64: 0x83, or64: 0x84, xor64: 0x85,
  shl64: 0x86, shrS64: 0x87, shrU64: 0x88,
  wrapI64: 0xa7, extendI32U: 0xad, extendI32S: 0xac,
} as const;

export type LocalGroup = { count: number; type: number };

/**
 * Builds a module exporting `run` (the translated entry). When `shareMemory` is set the
 * module imports `env.memory` instead of defining one, so every translated region sees the
 * same guest memory.
 */
export function buildModule(body: Code, locals: readonly LocalGroup[], memoryPages: number, shareMemory = false): Uint8Array {
  const section = (id: number, content: number[]): number[] => [id, ...uleb(content.length), ...content];
  const vector = (items: number[][]): number[] => [...uleb(items.length), ...items.flat()];
  const name = (text: string): number[] => {
    const bytes = [...new TextEncoder().encode(text)];
    return [...uleb(bytes.length), ...bytes];
  };
  const type = [0x60, ...uleb(0), ...uleb(0)]; // () -> ()
  const bodyBytes = [...uleb(locals.length), ...locals.flatMap(group => [...uleb(group.count), group.type]),
    ...body.bytes, 0x0b];
  const memoryEntry = [0x00, ...uleb(memoryPages)];
  const imports = shareMemory ? [[...name("env"), ...name("memory"), 0x02, ...memoryEntry]] : [];
  const exports = shareMemory ? [[...name("run"), 0x00, 0x00]] : [[...name("run"), 0x00, 0x00], [...name("memory"), 0x02, 0x00]];
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(1, vector([type])),
    ...(shareMemory ? section(2, vector(imports)) : []),
    ...section(3, vector([[0]])),
    ...(shareMemory ? [] : section(5, vector([memoryEntry]))),
    ...section(7, vector(exports)),
    ...section(10, vector([[...uleb(bodyBytes.length), ...bodyBytes]])),
  ]);
}
