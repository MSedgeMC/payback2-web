import type { RuntimeAdapter } from "./adapter.ts";
import { readGuestBytes } from "./guest-memory.ts";

// shortcut: up to eight 64-bit general arguments; add FP/aggregate layouts when required.
export function readVariadicWords(cpu: RuntimeAdapter, pointer: bigint, count: number): bigint[] {
  if (!Number.isInteger(count) || count < 0 || count > 8) throw new RangeError("AArch64 variadic argument count exceeds its limit");
  if (pointer % 8n) throw new RangeError("AArch64 va_list is not aligned");
  const bytes = readGuestBytes(cpu, pointer, 32), view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = view.getInt32(24, true), stack = view.getBigUint64(0, true);
  const top = view.getBigUint64(8, true);
  if (offset < 0) {
    if (offset < -64 || offset % 8 || top % 16n) throw new RangeError("Invalid AArch64 general register save area");
  }
  const values: bigint[] = [];
  for (let index = 0; index < count; index++) {
    const address = offset < 0 ? top + BigInt(offset) : stack;
    if (offset < 0) offset += 8; else stack += 8n;
    if (address % 8n) throw new RangeError("AArch64 variadic argument is not aligned");
    const argument = readGuestBytes(cpu, address, 8);
    values.push(new DataView(argument.buffer, argument.byteOffset, argument.byteLength).getBigUint64(0, true));
  }
  return values;
}

export function readVariadicLong(cpu: RuntimeAdapter, pointer: bigint): bigint {
  return BigInt.asIntN(64, readVariadicWords(cpu, pointer, 1)[0]!);
}
