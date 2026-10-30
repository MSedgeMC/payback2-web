import { MAX_SLICE_INSTRUCTIONS } from "./adapter.ts";
import type { ExecutionResult, RuntimeAdapter } from "./adapter.ts";
import { loadElf } from "./elf.ts";
import type { ElfImage, LoadedElf } from "./elf.ts";
import { NativeImports } from "./symbols.ts";
import type { NativeSettlement, NativeWait } from "./symbols.ts";

export type NativeCallProbe = {
  status: "blocked-import" | "blocked-interrupt" | "fault" | "budget" | "returned";
  sliceCount: number;
  instructionBudget: number;
  elapsedMs: number;
  wasmMemoryBytes: number;
  last: ExecutionResult;
  blockedSymbol?: string;
  blockedDetail?: string;
  blockedLibrary?: string;
  registers: { x0: bigint; x1: bigint; x2: bigint; x8: bigint; x30: bigint; sp: bigint };
};

export type InitializationProbe = Omit<NativeCallProbe, "status"> & {
  status: Exclude<NativeCallProbe["status"], "returned"> | "initializers-returned";
  completedInitializers: number;
  registeredDestructors: number;
  initializerCount: number;
};

const stack = 0x60000000n, stackSize = 1024n * 1024n, sentinel = 0x7fff0000n;
const ownedStackSize = stackSize + 4096n, threadPointer = stack + stackSize + 16n;
const maximumSlices = 400, instructionsPerSlice = 500;
/** Bounded execution budget. Diagnostics raise it explicitly so the defaults stay safe in a worker. */
export type ExecutionLimits = { slices: number; milliseconds: number; instructionsPerSlice?: number };
/** Receives every completed execution slice; used by diagnostics to attribute stalls. */
export type SliceObserver = (result: ExecutionResult) => void;
const defaultLimits: ExecutionLimits = { slices: maximumSlices, milliseconds: 3000 };
function checkLimits(limits: ExecutionLimits): Required<ExecutionLimits> {
  const perSlice = limits.instructionsPerSlice ?? instructionsPerSlice;
  if (!Number.isInteger(limits.slices) || limits.slices < 1 || limits.slices > 1_000_000 ||
      !Number.isFinite(limits.milliseconds) || limits.milliseconds <= 0 || limits.milliseconds > 600_000 ||
      !Number.isInteger(perSlice) || perSlice < 1 || perSlice > MAX_SLICE_INSTRUCTIONS) {
    throw new RangeError("Invalid execution limits");
  }
  return { ...limits, instructionsPerSlice: perSlice };
}
type ExecutionProbe = NativeCallProbe & { completedCalls: number };
type ResumeValue = NativeSettlement | "timeout" | undefined;

async function waitForNative(wait: NativeWait, milliseconds: number): Promise<ResumeValue> {
  if (milliseconds <= 0) { void wait.ready.catch(() => {}); return "timeout"; }
  return new Promise(resolve => {
    const timer = setTimeout(() => resolve("timeout"), milliseconds);
    wait.ready.then(value => { clearTimeout(timer); resolve({ ok: true, value }); },
      error => { clearTimeout(timer); resolve({ ok: false, error }); });
  });
}

export class NativeSession {
  readonly imports: NativeImports;
  private readonly cpu: RuntimeAdapter;
  private readonly previousThreadPointer: bigint;
  private readonly previousStackPointer: bigint;
  private readonly libraries = new Map<string, LoadedElf>();
  private readonly initialized = new Set<LoadedElf>();
  private stackMapped = false;
  private disposed = false;
  private stopped = false;

  constructor(cpu: RuntimeAdapter) {
    this.cpu = cpu;
    this.previousThreadPointer = cpu.readRegister("tpidr_el0");
    this.previousStackPointer = cpu.readRegister("sp");
    this.imports = new NativeImports(cpu);
    try {
      cpu.map(stack, ownedStackSize, 3); this.stackMapped = true;
      cpu.writeRegister("sp", stack + stackSize - 16n);
      // Bionic reserves two slots before ARM64 TP; slot 5 holds the stack guard.
      // shortcut: one native thread; extend its TLS when guest APIs require more state.
      cpu.copyIn(threadPointer + 40n, crypto.getRandomValues(new Uint8Array(8)));
      cpu.writeRegister("tpidr_el0", threadPointer);
    } catch (error) { this.dispose(); throw error; }
  }

  private assertActive(): void {
    if (this.disposed) throw new Error("Native session is disposed");
    if (this.stopped) throw new Error("Native session stopped before its previous call returned");
  }

  load(name: string, image: ElfImage, base: bigint): LoadedElf {
    this.assertActive();
    if (!/^[a-zA-Z0-9_.-]{1,128}$/.test(name) || this.libraries.has(name) || this.libraries.size >= 16) {
      throw new Error("Invalid, duplicate, or excessive native library");
    }
    const loaded = loadElf(this.cpu, image, base, symbol => {
      // shortcut: unique unversioned dependency exports; extend symbol precedence when required.
      if (!symbol.version) {
        const matches = image.needed.flatMap(name => {
          const library = this.libraries.get(name);
          return library ? library.image.symbols.filter(candidate => candidate.name === symbol.name && candidate.section !== 0 &&
            [1, 2].includes(candidate.binding) && [0, 3].includes(candidate.visibility)).map(candidate => ({ library, candidate })) : [];
        });
        if (matches.length > 1) throw new Error(`Ambiguous dependency export ${symbol.name}`);
        const match = matches[0];
        if (match) {
          if (match.candidate.type !== symbol.type) throw new Error(`Conflicting dependency symbol type for ${symbol.name}`);
          return match.library.lookupExport(symbol.name);
        }
      }
      return this.imports.resolve(symbol);
    });
    this.libraries.set(name, loaded);
    return loaded;
  }

  isLibraryInitialized(name: string): boolean {
    const loaded = this.libraries.get(name);
    return !this.disposed && loaded !== undefined && this.initialized.has(loaded);
  }

  initialize(loaded: LoadedElf): InitializationProbe {
    this.checkInitialization(loaded);
    return this.finishInitialization(loaded, this.execute(loaded.initializers));
  }

  async initializeAsync(loaded: LoadedElf, limits: ExecutionLimits = defaultLimits,
                        observe?: SliceObserver): Promise<InitializationProbe> {
    this.checkInitialization(loaded);
    return this.finishInitialization(loaded, await this.executeAsync(loaded.initializers, checkLimits(limits), observe));
  }

  private checkInitialization(loaded: LoadedElf): void {
    this.assertActive();
    if (![...this.libraries.values()].includes(loaded) || this.initialized.has(loaded)) throw new Error("Library is foreign or already initialized");
    for (const name of loaded.image.needed) {
      const dependency = this.libraries.get(name);
      if (dependency && !this.initialized.has(dependency)) throw new Error(`Dependency ${name} is not initialized`);
    }
  }

  private finishInitialization(loaded: LoadedElf, probe: ExecutionProbe): InitializationProbe {
    const { completedCalls, ...result } = probe;
    if (result.status === "returned") this.initialized.add(loaded);
    return { ...result, status: result.status === "returned" ? "initializers-returned" : result.status,
      completedInitializers: completedCalls, initializerCount: loaded.initializers.length,
      registeredDestructors: this.imports.destructors.length };
  }

  call(address: bigint, args: readonly bigint[]): NativeCallProbe {
    this.prepareCall(args);
    const { completedCalls: _completed, ...result } = this.execute([address]);
    return result;
  }

  async callAsync(address: bigint, args: readonly bigint[]): Promise<NativeCallProbe> {
    this.prepareCall(args);
    const { completedCalls: _completed, ...result } = await this.executeAsync([address]);
    return result;
  }

  private prepareCall(args: readonly bigint[]): void {
    this.assertActive();
    if (args.length > 8) throw new RangeError("Native call exceeds integer argument registers");
    // shortcut: integer register arguments only; extend for an observed FP or aggregate caller.
    for (let index = 0; index < args.length; index++) this.cpu.writeRegister(`x${index}`, args[index]!);
  }

  private execute(addresses: readonly bigint[]): ExecutionProbe {
    const execution = this.execution(addresses, checkLimits(defaultLimits));
    let step = execution.next();
    while (!step.done) {
      if (step.value) {
        void step.value.ready.catch(() => {});
        throw new Error("Asynchronous native handler requires an asynchronous session call");
      }
      step = execution.next(undefined);
    }
    return step.value;
  }

  private async executeAsync(addresses: readonly bigint[], limits: Required<ExecutionLimits> = checkLimits(defaultLimits),
                             observe?: SliceObserver): Promise<ExecutionProbe> {
    const execution = this.execution(addresses, limits, observe), started = performance.now();
    let yielded = started, step = execution.next();
    while (!step.done) {
      const resumed = step.value ? await waitForNative(step.value, limits.milliseconds - (performance.now() - started)) : undefined;
      if (performance.now() - yielded >= 8) {
        await new Promise(resolve => setTimeout(resolve, 0)); yielded = performance.now();
      }
      step = execution.next(resumed);
    }
    return step.value;
  }

  private *execution(addresses: readonly bigint[], limits: Required<ExecutionLimits>, observe?: SliceObserver): Generator<NativeWait | undefined, ExecutionProbe, ResumeValue> {
    this.assertActive();
    const cpu = this.cpu, imports = this.imports, started = performance.now();
    for (const address of addresses) {
      if (address % 4n || !cpu.regions.some(r => (r.permissions & 4) && address >= r.address && address + 4n <= r.address + r.size)) {
        throw new RangeError("Native call is outside executable guest memory");
      }
    }
    this.stopped = true;
    let sliceCount = 0, completedCalls = 0;
    let last: ExecutionResult = { reason: "end", pc: sentinel, elapsedMs: 0 };
    let status: NativeCallProbe["status"] = "returned";
    let blockedSymbol: string | undefined, blockedLibrary: string | undefined, blockedDetail: string | undefined;
    for (const initializer of addresses) {
      if (sliceCount >= limits.slices || performance.now() - started >= limits.milliseconds) {
        status = "budget";
        last = { reason: "budget", pc: initializer, elapsedMs: 0 };
        break;
      }
      cpu.writeRegister("x30", sentinel);
      let pc = initializer;
      while (sliceCount < limits.slices && performance.now() - started < limits.milliseconds) {
        if (this.disposed) throw new Error("Native session is disposed");
        sliceCount++;
        last = cpu.run(pc, sentinel, limits.instructionsPerSlice);
        observe?.(last);
        pc = last.pc;
        if (last.reason === "interrupt") {
          let handled = imports.handleInterrupt(last.pc);
          while (typeof handled !== "boolean") {
            const waitingStack = cpu.readRegister("sp"), waitingThread = cpu.readRegister("tpidr_el0");
            const settled = yield handled;
            if (settled === "timeout") { last = { ...last, reason: "budget" }; break; }
            if (this.disposed) throw new Error("Native session is disposed");
            if (cpu.readRegister("sp") !== waitingStack || cpu.readRegister("tpidr_el0") !== waitingThread) throw new Error("Native wait state changed");
            if (!settled) throw new Error("Native wait resumed without a result");
            handled = imports.resumeWait(handled, settled);
          }
          if (last.reason === "budget") break;
          if (handled === true) {
            pc = cpu.readRegister("pc");
            last = { reason: "budget", pc, elapsedMs: last.elapsedMs };
            yield undefined; continue;
          }
        }
        if (last.reason === "budget") { yield undefined; continue; }
        break;
      }
      if (last.reason === "interrupt") {
        const entry = imports.atInterrupt(last.pc);
        status = entry ? "blocked-import" : "blocked-interrupt";
        blockedSymbol = entry?.symbol.name ?? imports.unsupportedSyscall; blockedLibrary = entry?.symbol.version?.library;
        blockedDetail = imports.unsupportedDetail;
        break;
      }
      if (last.reason === "fault") { status = "fault"; break; }
      if (last.reason === "budget") { status = "budget"; break; }
      completedCalls++;
    }
    this.stopped = status !== "returned";
    return { status, completedCalls,
      sliceCount, instructionBudget: limits.slices * limits.instructionsPerSlice, elapsedMs: performance.now() - started,
      wasmMemoryBytes: cpu.wasmMemoryBytes, last,
      ...(blockedSymbol ? { blockedSymbol } : {}), ...(blockedLibrary ? { blockedLibrary } : {}),
      ...(blockedDetail ? { blockedDetail } : {}),
      registers: { x0: cpu.readRegister("x0"), x1: cpu.readRegister("x1"), x2: cpu.readRegister("x2"),
                   x8: cpu.readRegister("x8"), x30: cpu.readRegister("x30"), sp: cpu.readRegister("sp") },
    };
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    // Diagnostic disposal releases mappings; guest finalizers remain unsupported.
    this.cpu.writeRegister("sp", this.previousStackPointer);
    this.cpu.writeRegister("tpidr_el0", this.previousThreadPointer);
    if (this.stackMapped) this.cpu.unmap(stack, ownedStackSize);
    for (const loaded of [...this.libraries.values()].reverse()) loaded.dispose();
    this.libraries.clear(); this.initialized.clear(); this.imports.dispose();
  }
}

export function probeInitialization(cpu: RuntimeAdapter, image: ElfImage): InitializationProbe {
  const started = performance.now(), session = new NativeSession(cpu);
  try {
    const result = session.initialize(session.load("probe.so", image, 0x10000000n));
    return { ...result, elapsedMs: performance.now() - started };
  } finally { session.dispose(); }
}
