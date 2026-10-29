import createUnicorn from "../../.cache/runtime/unicorn-aarch64.cjs";
import {
  MAX_GUEST_BYTES, MAX_SLICE_INSTRUCTIONS, MAX_TRANSFER_BYTES, validatePageRange,
  validatePermissions, validateRange,
} from "./adapter.ts";
import type { ExecutionResult, Register, Region, RuntimeAdapter } from "./adapter.ts";
import type { UnicornEngine, UnicornModule } from "./unicorn-types.ts";

let modulePromise: Promise<UnicornModule> | undefined;
const runtimeDiagnostics: string[] = [];

export async function createRuntime(): Promise<RuntimeAdapter> {
  modulePromise ??= createUnicorn({ print: () => {}, printErr: (message: unknown) => {
    runtimeDiagnostics.push(String(message).slice(0, 500));
    if (runtimeDiagnostics.length > 4) runtimeDiagnostics.shift();
  } });
  return new UnicornRuntime(await modulePromise);
}

class UnicornRuntime implements RuntimeAdapter {
  readonly name = "Unicorn.js 2.1.4 / AArch64 / WASM TCI";
  readonly regions: Region[] = [];
  private readonly module: UnicornModule;
  private readonly engine: UnicornEngine;
  private readonly hooks: ReturnType<UnicornEngine["hook_add"]>[] = [];
  private closed = false;
  private interrupt: number | undefined;
  private memoryFault: string | undefined;
  private running = false;
  private hasExecuted = false;

  constructor(module: UnicornModule) {
    this.module = module;
    this.engine = new module.Unicorn(module.ARCH_ARM64, module.MODE_ARM);
    this.hooks.push(this.engine.hook_add(module.HOOK_INTR, (_engine, number) => {
      this.interrupt = Number(number);
      this.engine.emu_stop();
    }));
    this.hooks.push(this.engine.hook_add(module.HOOK_MEM_INVALID, (_engine, kind, address, size) => {
      this.memoryFault = `Guest memory fault type ${String(kind)} at 0x${BigInt(address as bigint).toString(16)} (${String(size)} bytes)`;
      return false;
    }));
  }

  get wasmMemoryBytes(): number { return this.module.HEAPU8.byteLength; }

  private assertOpen(): void {
    if (this.closed) throw new Error("Runtime is closed");
  }

  private registerId(register: Register): number {
    const name = register.toUpperCase();
    if (name.startsWith("X") && !/^X([0-9]|[12][0-9]|30)$/.test(name)) {
      throw new RangeError("AArch64 integer register must be x0 through x30");
    }
    const code = this.module[`ARM64_REG_${name}`];
    if (typeof code !== "number") throw new Error(`Unsupported AArch64 register ${register}`);
    return code;
  }

  map(address: bigint, size: bigint, permissions: number): void {
    this.assertOpen();
    validatePageRange(address, size);
    validatePermissions(permissions);
    if (this.regions.some(r => address < r.address + r.size && r.address < address + size)) {
      throw new RangeError("Guest mapping overlaps an existing region");
    }
    if (this.regions.reduce((total, r) => total + r.size, size) > BigInt(MAX_GUEST_BYTES)) {
      throw new RangeError("Guest memory budget exceeded");
    }
    this.engine.mem_map(address, size, permissions);
    this.regions.push({ address, size, permissions });
    this.regions.sort((a, b) => a.address < b.address ? -1 : 1);
  }

  unmap(address: bigint, size: bigint): void {
    this.assertOpen();
    validatePageRange(address, size);
    const index = this.regions.findIndex(r => r.address === address && r.size === size);
    if (index < 0) throw new RangeError("Unmap requires an exact owned mapping");
    this.engine.mem_unmap(address, size);
    this.regions.splice(index, 1);
  }

  protect(address: bigint, size: bigint, permissions: number): void {
    this.assertOpen();
    validatePageRange(address, size);
    validatePermissions(permissions);
    const region = this.regions.find(r => r.address === address && r.size === size);
    if (!region) throw new RangeError("Protect requires an exact owned mapping");
    this.engine.mem_protect(address, size, permissions);
    region.permissions = permissions;
  }

  private checkCopy(address: bigint, size: number): void {
    this.assertOpen();
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_TRANSFER_BYTES) {
      throw new RangeError("Host transfers must be bounded to 1 MiB");
    }
    validateRange(address, BigInt(size));
    if (size && !this.regions.some(r => address >= r.address && address + BigInt(size) <= r.address + r.size)) {
      throw new RangeError("Host copy is outside an owned guest mapping");
    }
  }

  copyIn(address: bigint, bytes: Uint8Array): void {
    this.checkCopy(address, bytes.byteLength);
    if (this.running) throw new Error("Guest memory cannot be replaced during execution");
    if (bytes.byteLength) {
      this.engine.mem_write(address, bytes);
      if (this.hasExecuted) {
        const region = this.regions.find(r => !!(r.permissions & 4) && address >= r.address && address < r.address + r.size);
        if (region) {
          // This immutable npm build lacks uc_ctl. Remapping only the affected
          // pages invalidates translations while retaining their bytes/rights.
          // The loading path runs before any translations exist and skips it.
          const last = address + BigInt(bytes.byteLength);
          for (let page = address / 4096n * 4096n; page < last; page += 4096n) {
            const contents = this.engine.mem_read(page, 4096);
            this.engine.mem_unmap(page, 4096n);
            this.engine.mem_map(page, 4096n, region.permissions);
            this.engine.mem_write(page, contents);
          }
        }
      }
    }
  }

  copyOut(address: bigint, size: number): Uint8Array {
    this.checkCopy(address, size);
    return size ? this.engine.mem_read(address, size) : new Uint8Array();
  }

  readRegister(register: Register): bigint {
    this.assertOpen();
    return BigInt.asUintN(64, this.engine.reg_read_i64(this.registerId(register)));
  }

  writeRegister(register: Register, value: bigint): void {
    this.assertOpen();
    this.engine.reg_write_i64(this.registerId(register), BigInt.asIntN(64, value));
  }

  private vectorId(index: number): number {
    if (!Number.isInteger(index) || index < 0 || index > 31) throw new RangeError("Vector register must be v0 through v31");
    const code = this.module[`ARM64_REG_Q${index}`];
    if (typeof code !== "number") throw new Error("Runtime lacks 128-bit vector registers");
    return code;
  }

  readVector(index: number): Uint8Array {
    this.assertOpen();
    return this.engine.reg_read(this.vectorId(index), 16);
  }

  writeVector(index: number, bytes: Uint8Array): void {
    this.assertOpen();
    if (bytes.byteLength !== 16) throw new RangeError("AArch64 vector values must be 16 bytes");
    this.engine.reg_write(this.vectorId(index), bytes);
  }

  run(begin: bigint, end: bigint, instructionLimit: number): ExecutionResult {
    this.assertOpen();
    validateRange(begin, 1n);
    validateRange(end, 1n);
    if (!Number.isInteger(instructionLimit) || instructionLimit < 1 || instructionLimit > MAX_SLICE_INSTRUCTIONS) {
      throw new RangeError(`Execution slice must contain 1–${MAX_SLICE_INSTRUCTIONS} instructions`);
    }
    if (this.running) throw new Error("Nested guest execution is unsupported");
    this.running = true;
    this.hasExecuted = true;
    this.interrupt = undefined;
    this.memoryFault = undefined;
    runtimeDiagnostics.length = 0;
    const started = performance.now();
    let diagnostic: string | undefined;
    try {
      // Unicorn's time-based API uses native threads; only count-bounded execution
      // is used here. The owning worker also has a termination deadline.
      this.engine.emu_start(begin, end, 0, instructionLimit);
    } catch (error) {
      diagnostic = this.memoryFault ?? [...runtimeDiagnostics, String(error)].join("\n").slice(0, 500);
    } finally {
      this.running = false;
    }
    const pc = this.readRegister("pc");
    return {
      reason: diagnostic ? "fault" : this.interrupt !== undefined ? "interrupt" : pc === end ? "end" : "budget",
      pc, elapsedMs: performance.now() - started,
      ...(this.interrupt !== undefined ? { interrupt: this.interrupt } : {}),
      ...(diagnostic ? { diagnostic } : {}),
    };
  }

  close(): void {
    if (this.closed) return;
    for (const hook of this.hooks) this.engine.hook_del(hook);
    this.engine.close();
    this.module._free(this.engine.handle_ptr);
    this.regions.length = 0;
    this.closed = true;
  }
}
