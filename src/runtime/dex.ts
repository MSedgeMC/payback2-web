export type JavaClass = {
  name: string;
  methods: { name: string; descriptor: string; isStatic: boolean; isNative: boolean }[];
};

export function readDexClass(bytes: Uint8Array, name: string): JavaClass {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const bounds = (offset: number, size: number): void => {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 ||
        offset > bytes.length || size > bytes.length - offset) throw new RangeError("DEX range is outside its file");
  };
  const u32 = (offset: number): number => { bounds(offset, 4); return view.getUint32(offset, true); };
  const u16 = (offset: number): number => { bounds(offset, 2); return view.getUint16(offset, true); };
  const uleb = (offset: number): [number, number] => {
    let value = 0;
    for (let index = 0; index < 5; index++) {
      bounds(offset, 1); const byte = bytes[offset++]!;
      if (index === 4 && byte >= 16) throw new Error("DEX integer exceeds 32 bits");
      value += (byte & 127) * 2 ** (index * 7);
      if (byte < 128) return [value, offset];
    }
    throw new Error("DEX integer is unterminated");
  };
  bounds(0, 112);
  const magic = new TextDecoder().decode(bytes.subarray(0, 8));
  if (!/^dex\n(?:035|037|038|039|040)\x00$/.test(magic) || bytes.length > 32 * 1024 * 1024 ||
      u32(32) !== bytes.length || u32(36) !== 112 || u32(40) !== 0x12345678) throw new Error("Unsupported DEX identity or size");
  if (!/^[A-Za-z_$][\w$]*(?:\/[A-Za-z_$][\w$]*)*$/.test(name) || name.length > 256) throw new Error("Invalid Java class name");
  const widths = [4, 4, 12, 8, 8, 32], tables = widths.map((width, index) => {
    const count = u32(56 + index * 8), start = u32(60 + index * 8);
    if (count > 1_000_000 || count && (start < 112 || start % 4)) throw new Error("Invalid DEX table");
    bounds(start, count * width); return { count, start, width };
  });
  const item = (table: number, index: number): number => {
    const { count, start, width } = tables[table]!;
    if (!Number.isInteger(index) || index < 0 || index >= count) throw new RangeError("DEX table index is outside bounds");
    return start + index * width;
  };
  const stringBytes = (index: number): Uint8Array => {
    const [length, offset] = uleb(u32(item(0, index)));
    if (length > 4096) throw new Error("DEX declaration string exceeds its limit");
    const end = bytes.subarray(offset, Math.min(offset + 4096, bytes.length)).indexOf(0);
    if (end < 0) throw new Error("DEX declaration string is unterminated");
    return bytes.subarray(offset, offset + end);
  };
  const string = (index: number): string => {
    const value = stringBytes(index);
    // shortcut: ASCII declarations from the pinned startup DEX; add modified UTF-8 when a supported class needs it.
    if (value.some(byte => byte > 127)) throw new Error("Non-ASCII DEX declarations are unsupported");
    const [length] = uleb(u32(item(0, index)));
    if (value.length !== length) throw new Error("DEX declaration string length mismatch");
    return new TextDecoder().decode(value);
  };
  const type = (index: number): string => string(u32(item(1, index)));
  const prototype = (index: number): string => {
    const offset = item(2, index), parameters = u32(offset + 8), arguments_: string[] = [];
    if (parameters) {
      const count = u32(parameters);
      if (count > 256 || parameters % 4) throw new Error("DEX method parameters exceed limits or alignment");
      bounds(parameters + 4, count * 2);
      for (let index = 0; index < count; index++) arguments_.push(type(u16(parameters + 4 + index * 2)));
    }
    return `(${arguments_.join("")})${type(u32(offset + 4))}`;
  };
  const target = new TextEncoder().encode(`L${name};`);
  for (let index = 0; index < tables[5]!.count; index++) {
    const offset = item(5, index), classIndex = u32(offset), candidate = stringBytes(u32(item(1, classIndex)));
    if (candidate.length !== target.length || !candidate.every((byte, index) => byte === target[index])) continue;
    string(u32(item(1, classIndex)));
    let cursor = u32(offset + 24);
    if (!cursor) return { name, methods: [] };
    const counts: number[] = [];
    for (let index = 0; index < 4; index++) {
      const [count, next] = uleb(cursor); cursor = next;
      if (count > 256) throw new Error("DEX class member limit exceeded");
      counts.push(count);
    }
    if (counts[2]! + counts[3]! > 256) throw new Error("DEX method declaration limit exceeded");
    for (const count of counts.slice(0, 2)) {
      let field = 0;
      for (let index = 0; index < count; index++) {
        const [delta, next] = uleb(cursor), [, end] = uleb(next); cursor = end; field += delta;
        if (u16(item(3, field)) !== classIndex) throw new Error("DEX field belongs to a different class");
      }
    }
    const methods: JavaClass["methods"] = [];
    for (const count of counts.slice(2)) {
      let method = 0;
      for (let index = 0; index < count; index++) {
        const [delta, next] = uleb(cursor), [flags, afterFlags] = uleb(next), [code, end] = uleb(afterFlags);
        if (index && !delta) throw new Error("Duplicate DEX method declaration");
        cursor = end; method += delta;
        const offset = item(4, method);
        if (u16(offset) !== classIndex) throw new Error("DEX method belongs to a different class");
        if (flags & (256 | 1024) ? code !== 0 : code === 0) throw new Error("DEX method code disagrees with native or abstract flags");
        if (code) {
          if (code % 4) throw new Error("DEX method code is not aligned");
          bounds(code, 16); bounds(code + 16, u32(code + 12) * 2);
        }
        methods.push({ name: string(u32(offset + 4)), descriptor: prototype(u16(offset + 2)),
          isStatic: !!(flags & 8), isNative: !!(flags & 256) });
      }
    }
    return { name, methods };
  }
  throw new Error(`Required Java class ${name} is missing from the DEX`);
}
