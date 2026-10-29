import {
  MAX_GUEST_BYTES, MAX_TRANSFER_BYTES, PAGE_SIZE, U64_LIMIT, validateRange,
} from "./adapter.ts";
import type { Region, RuntimeAdapter } from "./adapter.ts";

const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_SYMBOLS = 65_536;
const MAX_RELOCATIONS = 65_536;
const decoder = new TextDecoder("utf-8", { fatal: true });

export type Segment = {
  type: number; flags: number; offset: number; address: bigint;
  fileSize: number; memorySize: bigint; alignment: bigint;
};
export type SymbolVersion = { name: string; library: string };
export type ElfSymbol = {
  name: string; type: number; binding: number; visibility: number; section: number;
  address: bigint; size: bigint; version?: SymbolVersion;
};
export type Relocation = { address: bigint; type: number; symbolIndex: number; addend: bigint };
export type ElfImage = {
  bytes: Uint8Array;
  segments: Segment[];
  symbols: ElfSymbol[];
  relocations: Relocation[];
  needed: string[];
  init: bigint | undefined;
  initArray: { address: bigint; count: number } | undefined;
  fini: bigint | undefined;
  finiArray: { address: bigint; count: number } | undefined;
};
export type SymbolResolver = (symbol: ElfSymbol) => bigint;
export type LoadedElf = {
  image: ElfImage;
  base: bigint;
  initializers: bigint[];
  lookupExport(name: string): bigint;
  dispose(): void;
};

export class ElfError extends Error {
  constructor(message: string) { super(message); this.name = "ElfError"; }
}

function safeNumber(value: bigint, description: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new ElfError(`${description} exceeds a safe file index`);
  return Number(value);
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new ElfError(message);
}

export function parseElf(bytes: Uint8Array): ElfImage {
  assert(bytes.byteLength >= 64 && bytes.byteLength <= MAX_FILE_BYTES, "ELF size must be between 64 bytes and 64 MiB");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const bounds = (offset: number, size: number): void => {
    assert(Number.isSafeInteger(offset) && Number.isSafeInteger(size) && offset >= 0 && size >= 0 &&
           offset <= bytes.byteLength && size <= bytes.byteLength - offset, "ELF file range is out of bounds");
  };
  const u16 = (offset: number): number => { bounds(offset, 2); return view.getUint16(offset, true); };
  const u32 = (offset: number): number => { bounds(offset, 4); return view.getUint32(offset, true); };
  const u64 = (offset: number): bigint => { bounds(offset, 8); return view.getBigUint64(offset, true); };
  const i64 = (offset: number): bigint => { bounds(offset, 8); return view.getBigInt64(offset, true); };
  assert(u32(0) === 0x464c457f && bytes[4] === 2 && bytes[5] === 1 && bytes[6] === 1,
         "Expected little-endian ELF64 version 1");
  assert(u16(16) === 3 && u16(18) === 183 && u32(20) === 1, "Expected an AArch64 shared object");
  assert(u16(52) === 64 && u16(54) === 56, "Unsupported ELF header sizes");
  const phnum = u16(56);
  assert(phnum > 0 && phnum <= 128, "Invalid or excessive program header count");
  const phoff = safeNumber(u64(32), "Program header offset");
  bounds(phoff, phnum * 56);
  const segments: Segment[] = [];
  for (let index = 0; index < phnum; index++) {
    const offset = phoff + index * 56;
    const segment: Segment = {
      type: u32(offset), flags: u32(offset + 4), offset: safeNumber(u64(offset + 8), "Segment file offset"),
      address: u64(offset + 16), fileSize: safeNumber(u64(offset + 32), "Segment file size"),
      memorySize: u64(offset + 40), alignment: u64(offset + 48),
    };
    bounds(segment.offset, segment.fileSize);
    validateRange(segment.address, segment.memorySize);
    assert(segment.flags <= 7, "Unsupported segment permission flags");
    if (segment.alignment > 1n) {
      assert((segment.alignment & (segment.alignment - 1n)) === 0n &&
             segment.address % segment.alignment === BigInt(segment.offset) % segment.alignment,
             "Invalid segment alignment");
    }
    if (segment.type === 1) assert(BigInt(segment.fileSize) <= segment.memorySize, "File segment is larger than memory segment");
    assert(segment.type !== 3, "ELF interpreters are unsupported");
    assert(segment.type !== 7, "ELF TLS segments are unsupported");
    if (segment.type === 0x6474e551) assert(!(segment.flags & 1), "Executable guest stacks are unsupported");
    segments.push(segment);
  }
  const loads = segments.filter(s => s.type === 1 && s.memorySize > 0n).sort((a, b) => a.address < b.address ? -1 : 1);
  assert(loads.length > 0 && loads.some(s => s.flags & 1), "ELF has no executable load segment");
  let mappedBytes = 0n;
  for (let index = 0; index < loads.length; index++) {
    const segment = loads[index]!;
    const previous = loads[index - 1];
    if (previous) assert(previous.address + previous.memorySize <= segment.address, "Overlapping ELF load segments");
    const start = segment.address / PAGE_SIZE * PAGE_SIZE;
    const end = (segment.address + segment.memorySize + PAGE_SIZE - 1n) / PAGE_SIZE * PAGE_SIZE;
    if (previous) {
      const previousEnd = (previous.address + previous.memorySize + PAGE_SIZE - 1n) / PAGE_SIZE * PAGE_SIZE;
      assert(previousEnd <= start, "ELF load segments share a page; this mapping layout is unsupported");
    }
    mappedBytes += end - start;
  }
  assert(mappedBytes <= BigInt(MAX_GUEST_BYTES), "ELF exceeds guest memory budget");
  assert(loads.at(-1)!.address + loads.at(-1)!.memorySize - loads[0]!.address <= 128n * 1024n * 1024n,
         "ELF address span exceeds 128 MiB");

  const fileOffset = (address: bigint, size: number): number => {
    assert(Number.isSafeInteger(size) && size >= 0, "Invalid virtual file range size");
    const segment = loads.find(s => address >= s.address && address - s.address <= BigInt(s.fileSize) &&
                                   BigInt(size) <= BigInt(s.fileSize) - (address - s.address));
    assert(segment, `ELF virtual range at 0x${address.toString(16)} is not file backed`);
    return segment.offset + safeNumber(address - segment.address, "Segment-relative offset");
  };
  const memoryContains = (address: bigint, size: bigint): boolean =>
    loads.some(s => address >= s.address && address - s.address <= s.memorySize && size <= s.memorySize - (address - s.address));
  const executable = (address: bigint): boolean => loads.some(s => !!(s.flags & 1) && address >= s.address && address < s.address + s.memorySize);
  const dynamicSegments = segments.filter(s => s.type === 2);
  assert(dynamicSegments.length === 1, "Expected exactly one dynamic segment");
  const dynamic = dynamicSegments[0]!;
  assert(dynamic.fileSize % 16 === 0 && dynamic.fileSize <= 16 * 1024, "Invalid dynamic table size");
  assert(fileOffset(dynamic.address, dynamic.fileSize) === dynamic.offset, "Dynamic segment disagrees with load segments");
  const tags = new Map<bigint, bigint>();
  const neededOffsets: bigint[] = [];
  let terminated = false;
  for (let index = 0; index < dynamic.fileSize / 16; index++) {
    const offset = dynamic.offset + index * 16;
    const tag = i64(offset), value = u64(offset + 8);
    if (tag === 0n) { terminated = true; break; }
    if (tag === 1n) neededOffsets.push(value);
    else { assert(!tags.has(tag), `Duplicate ELF dynamic tag ${tag}`); tags.set(tag, value); }
  }
  assert(terminated, "Unterminated ELF dynamic table");
  for (const tag of [17n, 18n, 19n, 35n, 36n, 37n, 0x6000000fn, 0x60000010n, 0x60000011n, 0x60000012n]) {
    assert(!tags.has(tag), "REL, RELR, and Android packed relocations are unsupported");
  }
  assert(!tags.has(0x6ffffffcn), "Symbol version definitions are unsupported");
  const required = (tag: bigint): bigint => {
    const value = tags.get(tag); assert(value !== undefined, `Missing ELF dynamic tag ${tag}`); return value;
  };
  const strsize = safeNumber(required(10n), "Dynamic string table size");
  assert(strsize > 0 && strsize <= 4 * 1024 * 1024, "Invalid dynamic string table size");
  const stroff = fileOffset(required(5n), strsize);
  const string = (index: number): string => {
    assert(Number.isInteger(index) && index >= 0 && index < strsize, "ELF string index is out of bounds");
    const start = stroff + index, limit = Math.min(stroff + strsize, start + 4096);
    let end = start;
    while (end < limit && bytes[end] !== 0) end++;
    assert(end < limit, "Unterminated or excessive ELF string");
    return decoder.decode(bytes.subarray(start, end));
  };
  const needed = neededOffsets.map(value => string(safeNumber(value, "Dependency string offset")));
  assert(new Set(needed).size === needed.length && needed.length <= 128, "Duplicate or excessive ELF dependencies");

  let symbolCount: number;
  if (tags.has(4n)) {
    const hash = fileOffset(required(4n), 8);
    const buckets = u32(hash), chains = u32(hash + 4);
    assert(buckets > 0 && buckets <= MAX_SYMBOLS && chains > 0 && chains <= MAX_SYMBOLS, "Invalid SysV hash table");
    fileOffset(required(4n), 8 + (buckets + chains) * 4);
    symbolCount = chains;
  } else {
    const address = required(0x6ffffef5n), hash = fileOffset(address, 16);
    const buckets = u32(hash), first = u32(hash + 4), bloom = u32(hash + 8);
    assert(buckets > 0 && buckets <= MAX_SYMBOLS && bloom > 0 && bloom <= MAX_SYMBOLS && first <= MAX_SYMBOLS,
           "Invalid GNU hash table");
    fileOffset(address, 16 + bloom * 8 + buckets * 4);
    let highest = 0;
    for (let index = 0; index < buckets; index++) {
      const bucket = u32(hash + 16 + bloom * 8 + index * 4);
      assert(bucket === 0 || bucket >= first && bucket < MAX_SYMBOLS, "Invalid GNU hash bucket");
      highest = Math.max(highest, bucket);
    }
    symbolCount = first;
    if (highest) {
      const chains = address + BigInt(16 + bloom * 8 + buckets * 4);
      let index = highest;
      while (true) {
        assert(index < MAX_SYMBOLS, "GNU hash chain exceeds symbol limit");
        const value = u32(fileOffset(chains + BigInt((index - first) * 4), 4));
        index++;
        if (value & 1) { symbolCount = index; break; }
      }
    }
  }
  assert(symbolCount > 0 && symbolCount <= MAX_SYMBOLS && required(11n) === 24n, "Unsupported dynamic symbol table");
  const symoff = fileOffset(required(6n), symbolCount * 24);
  const versions = new Map<number, SymbolVersion>();
  if (tags.has(0x6ffffffen)) {
    let address = required(0x6ffffffen);
    const count = safeNumber(required(0x6fffffffn), "Version dependency count");
    assert(count > 0 && count <= 128, "Invalid version dependency count");
    const visited = new Set<bigint>();
    for (let index = 0; index < count; index++) {
      assert(!visited.has(address), "Cyclic version dependency table"); visited.add(address);
      const offset = fileOffset(address, 16), auxCount = u16(offset + 2);
      assert(u16(offset) === 1 && auxCount > 0 && auxCount <= 128, "Invalid version dependency record");
      const library = string(u32(offset + 4));
      assert(needed.includes(library), "Version dependency has no matching DT_NEEDED entry");
      let auxiliary = address + BigInt(u32(offset + 8));
      const auxVisited = new Set<bigint>();
      for (let auxIndex = 0; auxIndex < auxCount; auxIndex++) {
        assert(!auxVisited.has(auxiliary), "Cyclic version auxiliary table"); auxVisited.add(auxiliary);
        const aux = fileOffset(auxiliary, 16), version = u16(aux + 6) & 0x7fff;
        assert(version >= 2 && !versions.has(version), "Invalid or duplicate symbol version index");
        versions.set(version, { name: string(u32(aux + 8)), library });
        const next = u32(aux + 12);
        assert(auxIndex + 1 === auxCount ? next === 0 : next >= 16, "Invalid version auxiliary link");
        auxiliary += BigInt(next);
      }
      const next = u32(offset + 12);
      assert(index + 1 === count ? next === 0 : next >= 16, "Invalid version dependency link");
      address += BigInt(next);
    }
  }
  const versym = tags.has(0x6ffffff0n) ? fileOffset(required(0x6ffffff0n), symbolCount * 2) : undefined;
  const symbols: ElfSymbol[] = [];
  for (let index = 0; index < symbolCount; index++) {
    const offset = symoff + index * 24;
    const symbol: ElfSymbol = {
      name: string(u32(offset)), type: bytes[offset + 4]! & 15, binding: bytes[offset + 4]! >> 4,
      visibility: bytes[offset + 5]! & 3,
      section: u16(offset + 6), address: u64(offset + 8), size: u64(offset + 16),
    };
    assert(symbol.type !== 6 && symbol.section !== 0xfff2, "TLS and common symbols are unsupported");
    assert((bytes[offset + 5]! & ~3) === 0, "Unsupported ELF symbol calling convention");
    if (versym !== undefined) {
      const version = u16(versym + index * 2) & 0x7fff;
      if (version >= 2) {
        const requirement = versions.get(version);
        assert(requirement, "Unknown symbol version requirement");
        symbol.version = requirement;
      }
    }
    symbols.push(symbol);
  }
  const relocations: Relocation[] = [], destinations = new Set<bigint>();
  const addRelocations = (address: bigint, sizeValue: bigint): void => {
    const size = safeNumber(sizeValue, "Relocation table size");
    assert(size % 24 === 0 && size / 24 + relocations.length <= MAX_RELOCATIONS, "Invalid or excessive RELA table");
    const start = fileOffset(address, size);
    for (let index = 0; index < size / 24; index++) {
      const offset = start + index * 24, info = u64(offset + 8);
      const relocation: Relocation = {
        address: u64(offset), type: Number(info & 0xffffffffn), symbolIndex: Number(info >> 32n), addend: i64(offset + 16),
      };
      if (relocation.type === 0) continue;
      assert([257, 1025, 1026, 1027].includes(relocation.type), `Unsupported AArch64 relocation ${relocation.type}`);
      assert(relocation.symbolIndex < symbols.length, "Relocation symbol index is out of bounds");
      assert(relocation.type !== 1027 || relocation.symbolIndex === 0, "RELATIVE relocation must use symbol zero");
      assert(relocation.address % 8n === 0n && memoryContains(relocation.address, 8n), "Relocation destination is outside guest segments or unaligned");
      assert(!destinations.has(relocation.address), "Duplicate relocation destination");
      destinations.add(relocation.address); relocations.push(relocation);
    }
  };
  if (tags.has(7n)) {
    assert(required(9n) === 24n, "Unsupported RELA entry size");
    addRelocations(required(7n), required(8n));
  } else assert(!tags.has(8n), "RELA size has no table");
  if (tags.has(23n)) {
    assert(required(20n) === 7n, "PLT relocations must use RELA");
    addRelocations(required(23n), required(2n));
  }
  const array = (addressTag: bigint, sizeTag: bigint): { address: bigint; count: number } | undefined => {
    if (!tags.has(addressTag)) { assert(!tags.has(sizeTag), "Initialization array size has no address"); return undefined; }
    const address = required(addressTag), size = required(sizeTag);
    assert(size % 8n === 0n && size <= 8192n && memoryContains(address, size), "Invalid initialization array");
    return { address, count: Number(size / 8n) };
  };
  const init = tags.get(12n), fini = tags.get(13n);
  if (init !== undefined && init !== 0n) assert(executable(init), "DT_INIT is outside executable memory");
  if (fini !== undefined && fini !== 0n) assert(executable(fini), "DT_FINI is outside executable memory");
  return { bytes, segments, symbols, relocations, needed, init, fini,
           initArray: array(25n, 27n), finiArray: array(26n, 28n) };
}

function permissions(flags: number): number { return ((flags & 4) >> 2) | (flags & 2) | ((flags & 1) << 2); }

export function loadElf(cpu: RuntimeAdapter, image: ElfImage, base: bigint, resolve: SymbolResolver): LoadedElf {
  assert(base >= 0n && base % PAGE_SIZE === 0n, "ELF load base must be page aligned");
  const resolved = new Map<number, bigint>();
  const symbolAddress = (index: number): bigint => {
    const existing = resolved.get(index);
    if (existing !== undefined) return existing;
    const symbol = image.symbols[index]; assert(symbol, "Symbol index is out of bounds");
    let address: bigint;
    if (index === 0 && !symbol.name) address = 0n;
    else if (symbol.section === 0) address = resolve(symbol);
    else if (symbol.section === 0xfff1) address = symbol.address;
    else address = base + symbol.address;
    assert(address >= 0n && address < U64_LIMIT, `Resolved symbol ${symbol.name} is outside the address space`);
    resolved.set(index, address); return address;
  };
  // Resolve before modifying the engine address space. Unknown essential imports
  // fail here unless the caller explicitly supplies diagnostic trap addresses.
  for (const relocation of image.relocations) if (relocation.type !== 1027) symbolAddress(relocation.symbolIndex);
  const owned: Region[] = [];
  const dispose = (): void => {
    for (const region of owned.splice(0).reverse()) cpu.unmap(region.address, region.size);
  };
  const pointer = new Uint8Array(8), pointerView = new DataView(pointer.buffer);
  const zero = new Uint8Array(64 * 1024);
  try {
    for (const segment of image.segments) {
      if (segment.type !== 1 || segment.memorySize === 0n) continue;
      const start = segment.address / PAGE_SIZE * PAGE_SIZE;
      const end = (segment.address + segment.memorySize + PAGE_SIZE - 1n) / PAGE_SIZE * PAGE_SIZE;
      validateRange(base + start, end - start);
      const region = { address: base + start, size: end - start, permissions: permissions(segment.flags) };
      cpu.map(region.address, region.size, region.permissions); owned.push(region);
      for (let copied = 0; copied < segment.fileSize; copied += MAX_TRANSFER_BYTES) {
        const size = Math.min(MAX_TRANSFER_BYTES, segment.fileSize - copied);
        cpu.copyIn(base + segment.address + BigInt(copied), image.bytes.subarray(segment.offset + copied, segment.offset + copied + size));
      }
      let address = base + segment.address + BigInt(segment.fileSize);
      let remaining = segment.memorySize - BigInt(segment.fileSize);
      while (remaining > 0n) {
        const size = Number(remaining < BigInt(zero.byteLength) ? remaining : BigInt(zero.byteLength));
        cpu.copyIn(address, zero.subarray(0, size)); address += BigInt(size); remaining -= BigInt(size);
      }
    }
    for (const relocation of image.relocations) {
      const value = (relocation.type === 1027 ? base : symbolAddress(relocation.symbolIndex)) + relocation.addend;
      pointerView.setBigUint64(0, BigInt.asUintN(64, value), true);
      cpu.copyIn(base + relocation.address, pointer);
    }
    for (const segment of image.segments.filter(s => s.type === 0x6474e552 && s.memorySize > 0n)) {
      const start = base + segment.address / PAGE_SIZE * PAGE_SIZE;
      const end = base + (segment.address + segment.memorySize + PAGE_SIZE - 1n) / PAGE_SIZE * PAGE_SIZE;
      const region = owned.find(r => r.address === start && r.size === end - start);
      assert(region, "Partial-mapping GNU_RELRO layouts are unsupported");
      cpu.protect(region.address, region.size, region.permissions & ~2);
      region.permissions &= ~2;
    }
    const isExecutable = (address: bigint): boolean => owned.some(r => !!(r.permissions & 4) && address >= r.address && address < r.address + r.size);
    const initializers: bigint[] = [];
    if (image.init && image.init !== 0n) initializers.push(base + image.init);
    if (image.initArray) {
      for (let index = 0; index < image.initArray.count; index++) {
        const bytes = cpu.copyOut(base + image.initArray.address + BigInt(index * 8), 8);
        const address = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, true);
        if (address !== 0n && address !== U64_LIMIT - 1n) {
          assert(isExecutable(address), "Relocated initializer is outside executable memory");
          initializers.push(address);
        }
      }
    }
    const exports = new Map<string, ElfSymbol>();
    for (const symbol of image.symbols) {
      if (!symbol.name || symbol.section === 0 || ![1, 2].includes(symbol.binding) || ![0, 3].includes(symbol.visibility)) continue;
      assert(!exports.has(symbol.name), `Duplicate unversioned ELF export ${symbol.name}`);
      exports.set(symbol.name, symbol);
    }
    return { image, base, initializers, dispose,
      lookupExport(name: string): bigint {
        const symbol = exports.get(name); assert(symbol, `ELF export ${name} is missing`);
        return symbol.section === 0xfff1 ? symbol.address : base + symbol.address;
      },
    };
  } catch (error) { dispose(); throw error; }
}
