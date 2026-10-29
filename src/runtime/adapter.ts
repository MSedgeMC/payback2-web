export const PAGE_SIZE = 4096n;
export const MAX_GUEST_BYTES = 512 * 1024 * 1024;
export const MAX_SLICE_INSTRUCTIONS = 100_000;
export const MAX_TRANSFER_BYTES = 1024 * 1024;
export const U64_LIMIT = 1n << 64n;

export const Permission = { read: 1, write: 2, execute: 4 } as const;
export type Register = `x${number}` | "sp" | "pc" | "nzcv" | "fpcr" | "fpsr" | "tpidr_el0";
export type Region = { address: bigint; size: bigint; permissions: number };
export type ExecutionResult = {
  reason: "end" | "budget" | "interrupt" | "fault";
  pc: bigint;
  elapsedMs: number;
  interrupt?: number;
  diagnostic?: string;
};

export interface RuntimeAdapter {
  readonly name: string;
  readonly regions: readonly Region[];
  readonly wasmMemoryBytes: number;
  map(address: bigint, size: bigint, permissions: number): void;
  unmap(address: bigint, size: bigint): void;
  protect(address: bigint, size: bigint, permissions: number): void;
  copyIn(address: bigint, bytes: Uint8Array): void;
  copyOut(address: bigint, size: number): Uint8Array;
  readRegister(register: Register): bigint;
  writeRegister(register: Register, value: bigint): void;
  readVector(index: number): Uint8Array;
  writeVector(index: number, bytes: Uint8Array): void;
  run(begin: bigint, end: bigint, instructionLimit: number): ExecutionResult;
  close(): void;
}

export function validateRange(address: bigint, size: bigint): void {
  if (address < 0n || size < 0n || address >= U64_LIMIT || size > U64_LIMIT - address) {
    throw new RangeError("Guest address range exceeds the unsigned 64-bit address space");
  }
}

export function validatePageRange(address: bigint, size: bigint): void {
  validateRange(address, size);
  if (size === 0n || address % PAGE_SIZE !== 0n || size % PAGE_SIZE !== 0n) {
    throw new RangeError("Guest mappings must be nonempty and aligned to 4096 bytes");
  }
}

export function validatePermissions(permissions: number): void {
  if (!Number.isInteger(permissions) || permissions < 0 || permissions > 7) {
    throw new RangeError("Invalid guest permissions");
  }
}
