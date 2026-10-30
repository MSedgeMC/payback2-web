import type { RuntimeAdapter } from "./adapter.ts";
import { MAX_TRANSFER_BYTES } from "./adapter.ts";
import type { ElfSymbol } from "./elf.ts";
import { readCString, readGuestBytes, writeGuestBytes } from "./guest-memory.ts";
import { GuestHeap } from "./heap.ts";
import { GuestSyscalls } from "./syscalls.ts";
import { GuestThreads } from "./threads.ts";
import { libmHandler } from "./libm.ts";

export type NativeImport = { symbol: ElfSymbol; address: bigint; kind: "function" | "data" };
export type NativeSettlement = { ok: true; value: unknown } | { ok: false; error: unknown };
export type NativeWait = {
  kind: "wait";
  ready: Promise<unknown>;
  onReady: (value: unknown) => NativeDispatch;
  onError?: (error: unknown) => NativeDispatch;
};
export type NativeDispatch = void | boolean | NativeWait | {
  kind: "call";
  address: bigint;
  args: readonly bigint[];
  onReturn?: (value: bigint) => NativeDispatch;
};

// Unknown function imports stop at SVC; unknown data remains inaccessible.
// shortcut: native coverage is incremental; essential missing APIs block initialization.
export class NativeImports {
  readonly entries: NativeImport[] = [];
  readonly destructors: { callback: bigint; argument: bigint; dso: bigint }[] = [];
  readonly threadKeys = new Map<number, { destructor: bigint; value: bigint }>();
  private readonly cpu: RuntimeAdapter;
  private readonly codeBase: bigint;
  private readonly dataBase: bigint;
  private readonly mappings: { address: bigint; size: bigint }[] = [];
  private readonly byName = new Map<string, NativeImport>();
  private codeCount = 0;
  private dataCount = 0;
  private callbackReturnAddress: bigint | undefined;
  private readonly callbackFrames: { returnAddress: bigint; stackPointer: bigint; threadPointer: bigint;
    onReturn?: (value: bigint) => NativeDispatch }[] = [];
  private readonly errnoAddress: bigint;
  private heap: GuestHeap | undefined;
  private readonly syscalls: GuestSyscalls;
  readonly threads: GuestThreads;
  private readonly handlers = new Map<bigint, () => NativeDispatch>();
  private detail: string | undefined;
  private disposed = false;

  constructor(cpu: RuntimeAdapter, codeBase = 0x70000000n, dataBase = 0x71000000n) {
    this.cpu = cpu; this.codeBase = codeBase; this.dataBase = dataBase; this.syscalls = new GuestSyscalls(cpu); this.threads = new GuestThreads(cpu);
    this.errnoAddress = dataBase + 32n * 4096n;
    try {
      cpu.map(codeBase, 4096n, 5); this.mappings.push({ address: codeBase, size: 4096n });
      cpu.map(this.errnoAddress, 4096n, 3); this.mappings.push({ address: this.errnoAddress, size: 4096n });
      cpu.copyIn(this.errnoAddress, new Uint8Array(4));
    } catch (error) { this.dispose(); throw error; }
  }

  resolve = (symbol: ElfSymbol): bigint => {
    const key = `${symbol.name}\0${symbol.version?.name ?? ""}\0${symbol.version?.library ?? ""}`;
    const existing = this.byName.get(key);
    if (existing) {
      if (existing.symbol.type !== symbol.type) throw new Error("Conflicting import symbol types");
      return existing.address;
    }
    let entry: NativeImport;
    if (symbol.type === 2) {
      if (this.codeCount >= 512) throw new RangeError("Diagnostic function import budget exceeded");
      if (this.codeCount === 256) {
        const address = this.codeBase + 4096n;
        this.cpu.map(address, 4096n, 5); this.mappings.push({ address, size: 4096n });
      }
      const address = this.codeBase + BigInt(this.codeCount * 16);
      // svc #1; ret. The owning probe dispatches supported APIs after stopping.
      this.cpu.copyIn(address, new Uint8Array([0x21, 0, 0, 0xd4, 0xc0, 3, 0x5f, 0xd6]));
      this.codeCount++;
      entry = { symbol, address, kind: "function" };
    } else if (symbol.type === 1) {
      if (this.dataCount >= 32 || symbol.size > 4096n) throw new RangeError("Diagnostic data import budget exceeded");
      const address = this.dataBase + BigInt(this.dataCount++ * 4096);
      this.cpu.map(address, 4096n, 0); this.mappings.push({ address, size: 4096n });
      entry = { symbol, address, kind: "data" };
    } else throw new Error(`Unsupported diagnostic import type ${symbol.type} for ${symbol.name}`);
    this.entries.push(entry); this.byName.set(key, entry);
    return entry.address;
  };

  bind(symbol: ElfSymbol, handler: () => NativeDispatch): bigint {
    if (symbol.type !== 2) throw new TypeError("Only native functions can have handlers");
    const address = this.resolve(symbol);
    if (this.handlers.has(address)) throw new Error("Native function already has a handler");
    this.handlers.set(address, handler); return address;
  }

  /** Name of the last raw guest syscall without an implementation, if any. */
  get unsupportedSyscall(): string | undefined { return this.syscalls.unsupportedSyscall; }

  /** Refusals the guest received as normal error codes, for bounded diagnostics. */
  get notices(): readonly string[] { return this.syscalls.notices; }

  /** Why the last dispatched import was refused, for bounded diagnostics. */
  get unsupportedDetail(): string | undefined { return this.detail ?? this.syscalls.unsupportedSyscall; }

  /** Records the concrete input that a handler could not serve. */
  explain(detail: string): void { this.detail = detail.slice(0, 200); }

  atInterrupt(pc: bigint): NativeImport | undefined {
    return this.entries.find(entry => entry.kind === "function" && entry.address + 4n === pc);
  }

  handleInterrupt(pc: bigint): boolean | NativeWait {
    const entry = this.atInterrupt(pc), symbol = entry?.symbol;
    this.detail = undefined;
    const handler = entry && this.handlers.get(entry.address);
    if (handler) return this.dispatch(handler());
    if (entry && entry.address === this.callbackReturnAddress) {
      const frame = this.callbackFrames.at(-1);
      if (!frame || this.cpu.readRegister("sp") !== frame.stackPointer) throw new Error("Invalid native callback stack");
      if (this.cpu.readRegister("tpidr_el0") !== frame.threadPointer) throw new Error("Invalid native callback thread");
      this.callbackFrames.pop();
      this.cpu.writeRegister("x30", frame.returnAddress);
      return this.dispatch(frame.onReturn?.(this.cpu.readRegister("x0")));
    }
    if (!entry) return this.dispatch(this.syscalls.handle(pc));
    if (!symbol) return false;
    if (symbol.version?.library === "libm.so") {
      const math = libmHandler(symbol.name);
      if (!math) { this.explain(`libm ${symbol.name}`); return false; }
      math(this.cpu);
      this.cpu.writeRegister("pc", this.cpu.readRegister("x30"));
      return true;
    }
    if (symbol.version?.library !== "libc.so" || symbol.version.name !== "LIBC") {
      this.explain(`${symbol.version?.library ?? "unknown"}:${symbol.version?.name ?? "unversioned"} ${symbol.name}`);
      return false;
    }
    if (symbol.name === "syscall") {
      if (!this.syscalls.redirect(Number(BigInt.asUintN(32, this.cpu.readRegister("x0"))))) {
        this.explain(`syscall ${this.syscalls.unsupportedSyscall ?? "unknown"}`);
        return false;
      }
    } else if (symbol.name === "__errno") this.cpu.writeRegister("x0", this.errnoAddress);
    else if (symbol.name === "malloc" || symbol.name === "calloc") {
      this.heap ??= new GuestHeap(this.cpu);
      const size = this.cpu.readRegister("x0") * (symbol.name === "calloc" ? this.cpu.readRegister("x1") : 1n);
      const address = this.heap.allocate(size, symbol.name === "calloc");
      this.cpu.writeRegister("x0", address);
      if (address === 0n) {
        const bytes = new Uint8Array(4); new DataView(bytes.buffer).setInt32(0, 12, true); // ENOMEM
        writeGuestBytes(this.cpu, this.errnoAddress, bytes);
      }
    } else if (symbol.name === "free") {
      const address = this.cpu.readRegister("x0");
      if (address !== 0n) {
        if (!this.heap) throw new RangeError("Free requires an active guest allocation");
        this.heap.free(address);
      }
    } else if (symbol.name === "getpid") {
      // Each isolated worker hosts one guest process in its own PID namespace.
      this.cpu.writeRegister("x0", 1n);
    } else if (symbol.name === "getauxval") {
      const query = this.cpu.readRegister("x0");
      if (query !== 16n && query !== 26n) return false;
      // AT_HWCAP advertises verified FP/NEON; AT_HWCAP2 advertises no extra features.
      this.cpu.writeRegister("x0", query === 16n ? 3n : 0n);
    } else if (symbol.name === "__system_property_get") {
      readCString(this.cpu, this.cpu.readRegister("x0"), 128);
      // The browser guest has an empty Android property area: missing keys return zero and an empty string.
      writeGuestBytes(this.cpu, this.cpu.readRegister("x1"), new Uint8Array([0]));
      this.cpu.writeRegister("x0", 0n);
    } else if (symbol.name === "strlen") {
      const bytes = readCString(this.cpu, this.cpu.readRegister("x0"), MAX_TRANSFER_BYTES);
      this.cpu.writeRegister("x0", BigInt(bytes.length));
    } else if (symbol.name === "memset") {
      const size = Number(this.cpu.readRegister("x2"));
      if (!Number.isSafeInteger(size) || size < 0 || size > MAX_TRANSFER_BYTES) throw new RangeError("Native fill exceeds its byte limit");
      const value = Number(this.cpu.readRegister("x1") & 255n);
      writeGuestBytes(this.cpu, this.cpu.readRegister("x0"), new Uint8Array(size).fill(value));
    } else if (symbol.name === "memcpy" || symbol.name === "memmove") {
      const destination = this.cpu.readRegister("x0");
      const bytes = readGuestBytes(this.cpu, this.cpu.readRegister("x1"), Number(this.cpu.readRegister("x2")));
      writeGuestBytes(this.cpu, destination, bytes);
    } else if (symbol.name === "pthread_mutex_lock" || symbol.name === "pthread_mutex_unlock") {
      const address = this.cpu.readRegister("x0");
      if (address % 4n) throw new RangeError("Native mutex is not aligned");
      const bytes = readGuestBytes(this.cpu, address, 40), view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const state = view.getUint16(0, true), locking = symbol.name === "pthread_mutex_lock";
      // shortcut: uncontended normal mutexes on one guest thread; add waiting when scheduling is implemented.
      if (state !== (locking ? 0 : 1)) return false;
      view.setUint16(0, locking ? 1 : 0, true);
      writeGuestBytes(this.cpu, address, bytes.subarray(0, 2));
      this.cpu.writeRegister("x0", 0n);
    } else if (symbol.name === "pthread_create") {
      const entry = this.cpu.readRegister("x2"), argument = this.cpu.readRegister("x3"), target = this.cpu.readRegister("x0");
      // The parent must observe success when it resumes, so record it before the context snapshot.
      this.cpu.writeRegister("x0", 0n);
      this.threads.create(entry, argument, target);
      // The child's context (including its own pc) is installed; skip the libc return path.
      return true;
    } else if (symbol.name === "pthread_cond_wait") {
      const condition = this.cpu.readRegister("x0"), mutex = this.cpu.readRegister("x1");
      // The ABI releases the mutex while waiting and reacquires it on resume. The resumed
      // call must observe success, so x0 is set before the context is captured.
      this.setMutex(mutex, 0);
      this.cpu.writeRegister("x0", 0n);
      this.threads.suspend(condition, mutex);
      // The parent runs now; its registers were restored by the scheduler.
      return true;
    } else if (symbol.name === "pthread_cond_signal" || symbol.name === "pthread_cond_broadcast") {
      const condition = this.cpu.readRegister("x0"), broadcast = symbol.name === "pthread_cond_broadcast";
      this.cpu.writeRegister("x0", 0n);
      const woken = this.threads.resume(condition, broadcast);
      if (woken !== undefined) {
        this.setMutex(woken, 1);
        if (broadcast && this.threads.waitingCount(condition) > 0) {
          this.explain(`${this.threads.waitingCount(condition)} waiter(s) still waiting after broadcast`);
        }
        return true;
      }
    } else if (symbol.name === "pthread_detach") {
      const handle = this.cpu.readRegister("x0");
      // A detached thread is not joined; scheduling already does not require it.
      this.cpu.writeRegister("x0", this.threads.has(handle) ? 0n : 3n); // ESRCH
    } else if (symbol.name === "pthread_join") {
      const handle = this.cpu.readRegister("x0"), result = this.threads.resultOf(handle);
      if (!this.threads.has(handle)) { this.cpu.writeRegister("x0", 3n); return true; } // ESRCH
      // shortcut: cooperative scheduling means a joiner only observes finished threads.
      if (result === undefined) return false;
      const retval = this.cpu.readRegister("x1");
      if (retval !== 0n) writeGuestBytes(this.cpu, retval, new Uint8Array(new BigUint64Array([result]).buffer));
      this.cpu.writeRegister("x0", 0n);
    } else if (symbol.name === "pthread_once") {
      const control = this.cpu.readRegister("x0");
      if (control % 4n) throw new RangeError("Native once control is not aligned");
      const bytes = readGuestBytes(this.cpu, control, 4), view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const state = view.getUint32(0, true);
      if (state === 2) this.cpu.writeRegister("x0", 0n);
      else if (state === 0) {
        const callback = this.cpu.readRegister("x1");
        this.validateCallback(callback, []);
        view.setUint32(0, 1, true); writeGuestBytes(this.cpu, control, bytes);
        return this.dispatch({ kind: "call", address: callback, args: [], onReturn: () => {
          const current = readGuestBytes(this.cpu, control, 4), currentView = new DataView(current.buffer, current.byteOffset, current.byteLength);
          if (currentView.getUint32(0, true) !== 1) throw new Error("Invalid pthread_once callback state");
          currentView.setUint32(0, 2, true); writeGuestBytes(this.cpu, control, current);
          this.cpu.writeRegister("x0", 0n);
        } });
      } else return false; // shortcut: an in-progress once call blocks; add wakeups with guest scheduling.
    } else if (symbol.name === "pthread_key_create") {
      const destination = this.cpu.readRegister("x0"), destructor = this.cpu.readRegister("x1");
      if (destructor !== 0n && (destructor % 4n || !this.cpu.regions.some(r => (r.permissions & 4) &&
          destructor >= r.address && destructor + 4n <= r.address + r.size))) throw new RangeError("Thread destructor is outside executable guest memory");
      // shortcut: one guest thread with 128 keys; move values per thread when scheduling is added.
      let key = 0;
      while (key < 128 && this.threadKeys.has(key)) key++;
      if (key === 128) this.cpu.writeRegister("x0", 11n); // EAGAIN
      else {
        const bytes = new Uint8Array(4); new DataView(bytes.buffer).setUint32(0, key, true);
        writeGuestBytes(this.cpu, destination, bytes);
        this.threadKeys.set(key, { destructor, value: 0n }); this.cpu.writeRegister("x0", 0n);
      }
    } else if (["pthread_getspecific", "pthread_setspecific", "pthread_key_delete"].includes(symbol.name)) {
      const key = Number(BigInt.asUintN(32, this.cpu.readRegister("x0"))), entry = this.threadKeys.get(key);
      if (symbol.name === "pthread_getspecific") this.cpu.writeRegister("x0", entry?.value ?? 0n);
      else {
        if (entry) {
          if (symbol.name === "pthread_setspecific") entry.value = this.cpu.readRegister("x1");
          else this.threadKeys.delete(key);
        }
        this.cpu.writeRegister("x0", entry ? 0n : 22n); // EINVAL
      }
    } else if (symbol.name === "__cxa_atexit") {
      if (this.destructors.length >= 256) this.cpu.writeRegister("x0", -1n);
      else {
        const callback = this.cpu.readRegister("x0");
        if (!this.cpu.regions.some(r => (r.permissions & 4) && callback >= r.address && callback < r.address + r.size)) {
          throw new RangeError("Destructor callback is outside executable guest memory");
        }
        this.destructors.push({ callback, argument: this.cpu.readRegister("x1"), dso: this.cpu.readRegister("x2") });
        this.cpu.writeRegister("x0", 0n);
      }
    } else return false;
    this.cpu.writeRegister("pc", this.cpu.readRegister("x30"));
    return true;
  }

  /** Sets the observed byte of an uncontended guest mutex. */
  private setMutex(address: bigint, value: number): void {
    if (address === 0n) return;
    try {
      const bytes = readGuestBytes(this.cpu, address, 4);
      new DataView(bytes.buffer, bytes.byteOffset, 4).setUint16(0, value, true);
      writeGuestBytes(this.cpu, address, bytes.subarray(0, 2));
    } catch { /* an unmapped mutex is reported by the lock path instead */ }
  }

  private validateCallback(address: bigint, args: readonly bigint[]): void {
    if (address % 4n || !this.cpu.regions.some(r => (r.permissions & 4) && address >= r.address && address + 4n <= r.address + r.size)) {
      throw new RangeError("Native callback is outside executable guest memory");
    }
    if (args.length > 8 || args.some(value => typeof value !== "bigint")) throw new RangeError("Native callback exceeds integer argument registers");
    if (this.cpu.readRegister("sp") % 16n) throw new RangeError("Native callback stack is not aligned");
    if (this.callbackFrames.length >= 32) throw new RangeError("Native callback nesting limit exceeded");
  }

  resumeWait(wait: NativeWait, settled: NativeSettlement): boolean | NativeWait {
    if (this.disposed) throw new Error("Native imports are disposed");
    if (settled.ok) return this.dispatch(wait.onReady(settled.value));
    if (!wait.onError) throw settled.error;
    return this.dispatch(wait.onError(settled.error));
  }

  private dispatch(result: NativeDispatch): boolean | NativeWait {
    if (result === false) return false;
    if (result !== undefined && result !== true) {
      if (result.kind === "wait") {
        if (!(result.ready instanceof Promise) || typeof result.onReady !== "function") throw new TypeError("Invalid native wait");
        return result;
      }
      if (result.kind !== "call") throw new TypeError("Invalid native handler result");
      this.validateCallback(result.address, result.args);
      this.callbackReturnAddress ??= this.resolve({ name: "native:return", type: 2, binding: 1, visibility: 0,
        section: 0, address: 0n, size: 0n });
      this.callbackFrames.push({ returnAddress: this.cpu.readRegister("x30"), stackPointer: this.cpu.readRegister("sp"),
        threadPointer: this.cpu.readRegister("tpidr_el0"), onReturn: result.onReturn });
      for (let index = 0; index < result.args.length; index++) this.cpu.writeRegister(`x${index}`, result.args[index]!);
      this.cpu.writeRegister("x30", this.callbackReturnAddress); this.cpu.writeRegister("pc", result.address);
    } else this.cpu.writeRegister("pc", this.cpu.readRegister("x30"));
    return true;
  }

  dispose(): void {
    this.disposed = true;
    this.destructors.length = 0;
    this.callbackFrames.length = 0;
    this.threadKeys.clear();
    this.heap?.dispose();
    this.syscalls.dispose();
    this.threads.dispose();
    this.handlers.clear();
    for (const mapping of this.mappings.splice(0).reverse()) this.cpu.unmap(mapping.address, mapping.size);
  }
}
