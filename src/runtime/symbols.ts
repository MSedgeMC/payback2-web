import type { RuntimeAdapter } from "./adapter.ts";
import { MAX_TRANSFER_BYTES } from "./adapter.ts";
import type { ElfSymbol } from "./elf.ts";
import { readCString, readGuestBytes, writeGuestBytes } from "./guest-memory.ts";
import { GuestHeap } from "./heap.ts";

export type NativeImport = { symbol: ElfSymbol; address: bigint; kind: "function" | "data" };

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
  private onceReturnAddress: bigint | undefined;
  private readonly onceFrames: { control: bigint; returnAddress: bigint; stackPointer: bigint }[] = [];
  private readonly errnoAddress: bigint;
  private heap: GuestHeap | undefined;
  private readonly handlers = new Map<bigint, () => void | boolean>();

  constructor(cpu: RuntimeAdapter, codeBase = 0x70000000n, dataBase = 0x71000000n) {
    this.cpu = cpu; this.codeBase = codeBase; this.dataBase = dataBase;
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

  bind(symbol: ElfSymbol, handler: () => void | boolean): bigint {
    if (symbol.type !== 2) throw new TypeError("Only native functions can have handlers");
    const address = this.resolve(symbol);
    if (this.handlers.has(address)) throw new Error("Native function already has a handler");
    this.handlers.set(address, handler); return address;
  }

  atInterrupt(pc: bigint): NativeImport | undefined {
    return this.entries.find(entry => entry.kind === "function" && entry.address + 4n === pc);
  }

  handleInterrupt(pc: bigint): boolean {
    const entry = this.atInterrupt(pc), symbol = entry?.symbol;
    const handler = entry && this.handlers.get(entry.address);
    if (handler) {
      if (handler() === false) return false;
      this.cpu.writeRegister("pc", this.cpu.readRegister("x30"));
      return true;
    }
    if (entry && entry.address === this.onceReturnAddress) {
      const frame = this.onceFrames.at(-1);
      if (!frame || this.cpu.readRegister("sp") !== frame.stackPointer) throw new Error("Invalid pthread_once callback stack");
      const bytes = readGuestBytes(this.cpu, frame.control, 4), view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      if (view.getUint32(0, true) !== 1) throw new Error("Invalid pthread_once callback state");
      view.setUint32(0, 2, true); writeGuestBytes(this.cpu, frame.control, bytes);
      this.onceFrames.pop();
      this.cpu.writeRegister("x0", 0n); this.cpu.writeRegister("x30", frame.returnAddress);
      this.cpu.writeRegister("pc", frame.returnAddress);
      return true;
    }
    if (symbol?.version?.library !== "libc.so" || symbol.version.name !== "LIBC") return false;
    if (symbol.name === "__errno") this.cpu.writeRegister("x0", this.errnoAddress);
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
    } else if (symbol.name === "memset") {
      const size = Number(this.cpu.readRegister("x2"));
      if (!Number.isSafeInteger(size) || size < 0 || size > MAX_TRANSFER_BYTES) throw new RangeError("Native fill exceeds its byte limit");
      const value = Number(this.cpu.readRegister("x1") & 255n);
      writeGuestBytes(this.cpu, this.cpu.readRegister("x0"), new Uint8Array(size).fill(value));
    } else if (symbol.name === "memcpy") {
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
    } else if (symbol.name === "pthread_once") {
      const control = this.cpu.readRegister("x0");
      if (control % 4n) throw new RangeError("Native once control is not aligned");
      const bytes = readGuestBytes(this.cpu, control, 4), view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const state = view.getUint32(0, true);
      if (state === 2) this.cpu.writeRegister("x0", 0n);
      else if (state === 0) {
        const callback = this.cpu.readRegister("x1");
        if (callback % 4n || !this.cpu.regions.some(r => (r.permissions & 4) && callback >= r.address && callback + 4n <= r.address + r.size)) {
          throw new RangeError("Once callback is outside executable guest memory");
        }
        if (this.onceFrames.length >= 32) throw new RangeError("Native once callback nesting limit exceeded");
        this.onceReturnAddress ??= this.resolve({ name: "pthread_once:return", type: 2, binding: 1, visibility: 0,
          section: 0, address: 0n, size: 0n });
        view.setUint32(0, 1, true); writeGuestBytes(this.cpu, control, bytes);
        this.onceFrames.push({ control, returnAddress: this.cpu.readRegister("x30"), stackPointer: this.cpu.readRegister("sp") });
        this.cpu.writeRegister("x30", this.onceReturnAddress); this.cpu.writeRegister("pc", callback);
        return true;
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

  dispose(): void {
    this.destructors.length = 0;
    this.onceFrames.length = 0;
    this.threadKeys.clear();
    this.heap?.dispose();
    this.handlers.clear();
    for (const mapping of this.mappings.splice(0).reverse()) this.cpu.unmap(mapping.address, mapping.size);
  }
}
