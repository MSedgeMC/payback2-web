// Minimal WebAssembly binary builder for translated guest code.
// Only the sections a translation unit needs are emitted: one function, its memory,
// and the two exports the driver uses.

export const I32 = 0x7f, I64 = 0x7e, EMPTY_BLOCK = 0x40;

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
  i64(value: bigint): this { this.bytes.push(0x42, ...sleb(value)); return this; }
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
  load(kind: "i32" | "i64" | "i64_32u", offset: number): this {
    this.bytes.push(kind === "i32" ? 0x28 : kind === "i64" ? 0x29 : 0x35, ...uleb(3), ...uleb(offset));
    return this;
  }
  store(kind: "i32" | "i64" | "i64_32", offset: number): this {
    this.bytes.push(kind === "i32" ? 0x36 : kind === "i64" ? 0x37 : 0x3e, ...uleb(3), ...uleb(offset));
    return this;
  }
}

// Instruction opcodes used by the translator.
export const OP = {
  eqz64: 0x50, eq64: 0x51, ne64: 0x52, ltS64: 0x53, ltU64: 0x54, gtS64: 0x55, gtU64: 0x56,
  leS64: 0x57, leU64: 0x58, geS64: 0x59, geU64: 0x5a,
  eqz32: 0x45, ne32: 0x47,
  add64: 0x7c, sub64: 0x7d, mul64: 0x7e, and64: 0x83, or64: 0x84, xor64: 0x85,
  shl64: 0x86, shrS64: 0x87, shrU64: 0x88,
  wrapI64: 0xa7, extendI32U: 0xad, extendI32S: 0xac,
} as const;

export type LocalGroup = { count: number; type: number };

/** Builds a module exporting `run` (the translated entry) and its linear memory. */
export function buildModule(body: Code, locals: readonly LocalGroup[], memoryPages: number): Uint8Array {
  const section = (id: number, content: number[]): number[] => [id, ...uleb(content.length), ...content];
  const vector = (items: number[][]): number[] => [...uleb(items.length), ...items.flat()];
  const name = (text: string): number[] => {
    const bytes = [...new TextEncoder().encode(text)];
    return [...uleb(bytes.length), ...bytes];
  };
  const type = [0x60, ...uleb(0), ...uleb(0)]; // () -> ()
  const bodyBytes = [...uleb(locals.length), ...locals.flatMap(group => [...uleb(group.count), group.type]),
    ...body.bytes, 0x0b];
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(1, vector([type])),
    ...section(3, vector([[0]])),
    ...section(5, vector([[0x00, ...uleb(memoryPages)]])),
    ...section(7, vector([[...name("run"), 0x00, 0x00], [...name("memory"), 0x02, 0x00]])),
    ...section(10, vector([[...uleb(bodyBytes.length), ...bodyBytes]])),
  ]);
}
