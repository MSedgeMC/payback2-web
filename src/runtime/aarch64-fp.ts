import type { RuntimeAdapter } from "./adapter.ts";

// AArch64 passes floating-point arguments and returns in the low bits of v0–v7.
// Only the narrow part is defined by the ABI, so writes preserve the untouched bytes.
export function readDouble(cpu: RuntimeAdapter, index: number): number {
  const bytes = cpu.readVector(index);
  return new DataView(bytes.buffer, bytes.byteOffset, 8).getFloat64(0, true);
}

export function writeDouble(cpu: RuntimeAdapter, index: number, value: number): void {
  const bytes = cpu.readVector(index);
  new DataView(bytes.buffer, bytes.byteOffset, 8).setFloat64(0, value, true);
  cpu.writeVector(index, bytes);
}

export function readFloat(cpu: RuntimeAdapter, index: number): number {
  const bytes = cpu.readVector(index);
  return new DataView(bytes.buffer, bytes.byteOffset, 4).getFloat32(0, true);
}

export function writeFloat(cpu: RuntimeAdapter, index: number, value: number): void {
  const bytes = cpu.readVector(index);
  new DataView(bytes.buffer, bytes.byteOffset, 4).setFloat32(0, value, true);
  cpu.writeVector(index, bytes);
}

export function readDoublePair(cpu: RuntimeAdapter): [number, number] {
  return [readDouble(cpu, 0), readDouble(cpu, 1)];
}
