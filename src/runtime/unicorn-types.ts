export interface UnicornEngine {
  handle_ptr: number;
  mem_map(address: bigint, size: bigint, permissions: number): void;
  mem_unmap(address: bigint, size: bigint): void;
  mem_protect(address: bigint, size: bigint, permissions: number): void;
  mem_write(address: bigint, bytes: Uint8Array): void;
  mem_read(address: bigint, size: number): Uint8Array;
  reg_write_i64(register: number, value: bigint): void;
  reg_read_i64(register: number): bigint;
  reg_read(register: number, size: number): Uint8Array;
  reg_write(register: number, bytes: Uint8Array): void;
  hook_add(type: number, callback: (...args: unknown[]) => unknown): { handle: number; callback: number };
  hook_del(hook: { handle: number; callback: number }): void;
  emu_start(begin: bigint, end: bigint, timeout: number, count: number): void;
  emu_stop(): void;
  close(): void;
}

export interface UnicornModule {
  [key: string]: unknown;
  ARCH_ARM64: number;
  MODE_ARM: number;
  HOOK_INTR: number;
  HOOK_MEM_INVALID: number;
  HEAPU8: Uint8Array;
  _free(address: number): void;
  Unicorn: new (architecture: number, mode: number) => UnicornEngine;
}
