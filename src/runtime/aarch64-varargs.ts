import type { RuntimeAdapter } from "./adapter.ts";
import { readGuestBytes } from "./guest-memory.ts";

// shortcut: first little-endian 64-bit integer only; extend with the next observed variadic type.
export function readVariadicLong(cpu: RuntimeAdapter, pointer: bigint): bigint {
  if (pointer % 8n) throw new RangeError("AArch64 va_list is not aligned");
  const bytes = readGuestBytes(cpu, pointer, 32), view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const offset = view.getInt32(24, true);
  let address: bigint;
  if (offset < 0) {
    const top = view.getBigUint64(8, true);
    if (offset < -64 || offset % 8 || top % 16n) throw new RangeError("Invalid AArch64 general register save area");
    address = top + BigInt(offset);
  } else address = view.getBigUint64(0, true);
  if (address % 8n) throw new RangeError("AArch64 variadic argument is not aligned");
  const argument = readGuestBytes(cpu, address, 8);
  return new DataView(argument.buffer, argument.byteOffset, argument.byteLength).getBigInt64(0, true);
}
