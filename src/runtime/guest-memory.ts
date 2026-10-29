import { MAX_TRANSFER_BYTES, validateRange } from "./adapter.ts";
import type { RuntimeAdapter } from "./adapter.ts";

export function readCString(cpu: RuntimeAdapter, address: bigint, maxBytes: number): Uint8Array {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_TRANSFER_BYTES) {
    throw new RangeError("Invalid guest string byte limit");
  }
  validateRange(address, BigInt(maxBytes));
  const output = new Uint8Array(maxBytes);
  let read = 0;
  while (read < maxBytes) {
    const cursor = address + BigInt(read);
    const region = cpu.regions.find(r => cursor >= r.address && cursor < r.address + r.size);
    if (!region || !(region.permissions & 1)) throw new RangeError("Guest string points outside readable memory");
    const count = Number(BigInt(maxBytes - read) < region.address + region.size - cursor
      ? BigInt(maxBytes - read) : region.address + region.size - cursor);
    const chunk = cpu.copyOut(cursor, count), end = chunk.indexOf(0);
    output.set(end < 0 ? chunk : chunk.subarray(0, end), read);
    if (end >= 0) return output.subarray(0, read + end);
    read += count;
  }
  throw new RangeError("Guest string is unterminated within its byte limit");
}

export function writeGuestBytes(cpu: RuntimeAdapter, address: bigint, bytes: Uint8Array): void {
  if (bytes.byteLength > MAX_TRANSFER_BYTES) throw new RangeError("Guest write exceeds its byte limit");
  validateRange(address, BigInt(bytes.byteLength));
  if (!bytes.byteLength) return;
  const region = cpu.regions.find(r => address >= r.address && address + BigInt(bytes.byteLength) <= r.address + r.size);
  if (!region || !(region.permissions & 2)) throw new RangeError("Guest write is outside a writable mapping");
  cpu.copyIn(address, bytes);
}
