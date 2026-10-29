import { decodeModifiedUtf8 } from "./modified-utf8.ts";

export type JavaClass = {
  name: string;
  methods: { name: string; descriptor: string; isStatic: boolean; isNative: boolean }[];
};
export type DexMethodReference = { className: string; name: string; descriptor: string };
export type DexFieldReference = DexMethodReference;
export type DexTry = { start: number; length: number; catches: { className: string | null; target: number }[] };
export type DexCode = { registers: number; inputs: number; outputs: number; instructions: Uint16Array; tries: DexTry[] };
export type DexClass = { name: string; superclass: string | null;
  methods: (JavaClass["methods"][number] & { code?: DexCode })[];
  fields: (DexFieldReference & { isStatic: boolean; value: number | bigint | string | null })[] };
export type DexFile = {
  readClass(name: string): DexClass;
  string(index: number): string;
  type(index: number): string;
  method(index: number): DexMethodReference;
  field(index: number): DexFieldReference;
};

export function readDex(bytes: Uint8Array): DexFile {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const bounds = (offset: number, size: number): void => {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 ||
        offset > bytes.length || size > bytes.length - offset) throw new RangeError("DEX range is outside its file");
  };
  const u32 = (offset: number): number => { bounds(offset, 4); return view.getUint32(offset, true); };
  const u16 = (offset: number): number => { bounds(offset, 2); return view.getUint16(offset, true); };
  const leb = (offset: number, signed = false): [number, number] => {
    let value = 0;
    for (let index = 0; index < 5; index++) {
      bounds(offset, 1); const byte = bytes[offset++]!;
      if (index === 4 && (signed ? byte & 128 || (byte & 112) !== 0 && (byte & 112) !== 112 : byte >= 16)) throw new Error("DEX integer exceeds 32 bits");
      value += (byte & 127) * 2 ** (index * 7);
      if (byte < 128) {
        if (signed && byte & 64) value -= 2 ** ((index + 1) * 7);
        if (signed && (value < -0x80000000 || value > 0x7fffffff)) throw new Error("DEX signed integer exceeds 32 bits");
        return [value, offset];
      }
    }
    throw new Error("DEX integer is unterminated");
  };
  const uleb = (offset: number): [number, number] => leb(offset);
  bounds(0, 112);
  const magic = new TextDecoder().decode(bytes.subarray(0, 8));
  if (!/^dex\n(?:035|037|038|039|040)\x00$/.test(magic) || bytes.length > 32 * 1024 * 1024 ||
      u32(32) !== bytes.length || u32(36) !== 112 || u32(40) !== 0x12345678) throw new Error("Unsupported DEX identity or size");
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
    const end = bytes.subarray(offset, Math.min(offset + 12_289, bytes.length)).indexOf(0);
    if (end < 0) throw new Error("DEX declaration string is unterminated");
    return bytes.subarray(offset, offset + end);
  };
  const string = (index: number): string => {
    const value = stringBytes(index);
    const decoded = decodeModifiedUtf8(value);
    const [length] = uleb(u32(item(0, index)));
    if (decoded.length !== length) throw new Error("DEX declaration string length mismatch");
    return decoded;
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
  const className = (index: number): string => {
    const descriptor = type(index);
    if (!/^L[A-Za-z_$][\w$]*(?:\/[A-Za-z_$][\w$]*)*;$/.test(descriptor) || descriptor.length > 258) throw new Error("Invalid DEX class descriptor");
    return descriptor.slice(1, -1);
  };
  const member = (table: number, index: number): DexMethodReference => {
    const offset = item(table, index);
    return { className: className(u16(offset)), name: string(u32(offset + 4)),
      descriptor: table === 4 ? prototype(u16(offset + 2)) : type(u16(offset + 2)) };
  };
  const codeItem = (offset: number): DexCode => {
    if (offset % 4) throw new Error("DEX method code is not aligned");
    bounds(offset, 16);
    const registers = u16(offset), inputs = u16(offset + 2), outputs = u16(offset + 4), tryCount = u16(offset + 6), count = u32(offset + 12);
    if (registers > 256 || inputs > registers || outputs > 256 || tryCount > 32 || count === 0 || count > 4096) throw new Error("DEX method code exceeds startup limits");
    bounds(offset + 16, count * 2);
    const instructions = new Uint16Array(count);
    for (let index = 0; index < count; index++) instructions[index] = u16(offset + 16 + index * 2);
    const tries: DexTry[] = [], tryStart = offset + 16 + count * 2 + (tryCount && count % 2 ? 2 : 0);
    bounds(tryStart, tryCount * 8);
    const handlerStart = tryStart + tryCount * 8;
    const handlers = new Map<number, DexTry["catches"]>();
    if (tryCount) {
      let [handlerCount, cursor] = uleb(handlerStart);
      if (handlerCount === 0 || handlerCount > 64) throw new Error("DEX catch handler count exceeds limits");
      for (let index = 0; index < handlerCount; index++) {
        const relative = cursor - handlerStart, [size, next] = leb(cursor, true); cursor = next;
        if (Math.abs(size) > 64) throw new Error("DEX catch types exceed their limit");
        const catches: DexTry["catches"] = [];
        for (let index = 0; index < Math.abs(size); index++) {
          const [typeIndex, next] = uleb(cursor), [target, end] = uleb(next); cursor = end;
          if (target >= count) throw new Error("DEX catch target is outside method code");
          catches.push({ className: className(typeIndex), target });
        }
        if (size <= 0) {
          const [target, next] = uleb(cursor); cursor = next;
          if (target >= count) throw new Error("DEX catch target is outside method code");
          catches.push({ className: null, target });
        }
        handlers.set(relative, catches);
      }
    }
    let previousEnd = 0;
    for (let index = 0; index < tryCount; index++) {
      const entry = tryStart + index * 8, start = u32(entry), length = u16(entry + 4), catches = handlers.get(u16(entry + 6));
      if (!length || start < previousEnd || start + length > count || !catches) throw new Error("Invalid DEX try range or handler offset");
      tries.push({ start, length, catches }); previousEnd = start + length;
    }
    return { registers, inputs, outputs, instructions, tries };
  };
  const encodedValue = (offset: number): [number | bigint | string | null, number] => {
    bounds(offset, 1);
    const header = bytes[offset++]!, tag = header & 31, width = (header >>> 5) + 1;
    if (tag === 30 && width === 1) return [null, offset];
    if (tag === 31 && width <= 2) return [width - 1, offset];
    const maximum = tag === 0 ? 1 : tag === 2 || tag === 3 ? 2 : tag === 4 || tag === 23 ? 4 : tag === 6 ? 8 : 0;
    if (!maximum || width > maximum) throw new Error("Unsupported DEX static value type or width");
    bounds(offset, width);
    let value = 0n;
    for (let index = 0; index < width; index++) value |= BigInt(bytes[offset + index]!) << BigInt(index * 8);
    const decoded = tag === 23 ? string(Number(value)) : tag === 3 ? Number(value) : tag === 6 ? BigInt.asIntN(width * 8, value) : Number(BigInt.asIntN(width * 8, value));
    return [decoded, offset + width];
  };
  const cache = new Map<string, DexClass>();
  const readClass = (name: string): DexClass => {
    if (!/^[A-Za-z_$][\w$]*(?:\/[A-Za-z_$][\w$]*)*$/.test(name) || name.length > 256) throw new Error("Invalid Java class name");
    const cached = cache.get(name); if (cached) return cached;
    if (cache.size >= 16) throw new Error("DEX startup class limit exceeded");
    const target = new TextEncoder().encode(`L${name};`);
  for (let index = 0; index < tables[5]!.count; index++) {
    const offset = item(5, index), classIndex = u32(offset), candidate = stringBytes(u32(item(1, classIndex)));
    if (candidate.length !== target.length || !candidate.every((byte, index) => byte === target[index])) continue;
    string(u32(item(1, classIndex)));
    let cursor = u32(offset + 24);
    const superclassIndex = u32(offset + 8), superclass = superclassIndex === 0xffffffff ? null : className(superclassIndex);
    const fields: DexClass["fields"] = [], methods: DexClass["methods"] = [];
    if (!cursor) { const empty = { name, superclass, fields, methods }; cache.set(name, empty); return empty; }
    const counts: number[] = [];
    for (let index = 0; index < 4; index++) {
      const [count, next] = uleb(cursor); cursor = next;
      if (count > 256) throw new Error("DEX class member limit exceeded");
      counts.push(count);
    }
    if (counts[0]! + counts[1]! > 256 || counts[2]! + counts[3]! > 256) throw new Error("DEX member declaration limit exceeded");
    for (const [group, count] of counts.slice(0, 2).entries()) {
      let field = 0;
      for (let index = 0; index < count; index++) {
        const [delta, next] = uleb(cursor), [, end] = uleb(next); cursor = end; field += delta;
        if (index && !delta) throw new Error("Duplicate DEX field declaration");
        if (u16(item(3, field)) !== classIndex) throw new Error("DEX field belongs to a different class");
        const reference = member(3, field);
        fields.push({ ...reference, isStatic: group === 0, value: reference.descriptor === "J" ? 0n : reference.descriptor.startsWith("L") || reference.descriptor.startsWith("[") ? null : 0 });
      }
    }
    for (const count of counts.slice(2)) {
      let method = 0;
      for (let index = 0; index < count; index++) {
        const [delta, next] = uleb(cursor), [flags, afterFlags] = uleb(next), [code, end] = uleb(afterFlags);
        if (index && !delta) throw new Error("Duplicate DEX method declaration");
        cursor = end; method += delta;
        const offset = item(4, method);
        if (u16(offset) !== classIndex) throw new Error("DEX method belongs to a different class");
        if (flags & (256 | 1024) ? code !== 0 : code === 0) throw new Error("DEX method code disagrees with native or abstract flags");
        methods.push({ name: string(u32(offset + 4)), descriptor: prototype(u16(offset + 2)),
          isStatic: !!(flags & 8), isNative: !!(flags & 256), ...(code ? { code: codeItem(code) } : {}) });
      }
    }
    let values = u32(offset + 28);
    if (values) {
      const [count, next] = uleb(values); values = next;
      const statics = fields.filter(field => field.isStatic);
      if (count > statics.length) throw new Error("DEX static values exceed declared fields");
      for (let index = 0; index < count; index++) {
        const [value, next] = encodedValue(values); values = next; statics[index]!.value = value;
      }
    }
    const result = { name, superclass, fields, methods }; cache.set(name, result); return result;
  }
  throw new Error(`Required Java class ${name} is missing from the DEX`);
  };
  return { readClass, string, type, method: index => member(4, index), field: index => member(3, index) };
}

export function readDexClass(bytes: Uint8Array, name: string): JavaClass {
  const definition = readDex(bytes).readClass(name);
  return { name: definition.name, methods: definition.methods.map(({ name, descriptor, isStatic, isNative }) => ({ name, descriptor, isStatic, isNative })) };
}
