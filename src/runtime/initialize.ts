import type { ExecutionResult, RuntimeAdapter } from "./adapter.ts";
import { loadElf } from "./elf.ts";
import type { ElfImage } from "./elf.ts";
import { NativeImports } from "./symbols.ts";

export type InitializationProbe = {
  status: "blocked-import" | "blocked-interrupt" | "fault" | "budget" | "initializers-returned";
  completedInitializers: number;
  initializerCount: number;
  sliceCount: number;
  instructionBudget: number;
  elapsedMs: number;
  wasmMemoryBytes: number;
  last: ExecutionResult;
  blockedSymbol?: string;
  blockedLibrary?: string;
  registers: { x0: bigint; x1: bigint; x2: bigint; x8: bigint; x30: bigint; sp: bigint };
};

export function probeInitialization(cpu: RuntimeAdapter, image: ElfImage): InitializationProbe {
  const base = 0x10000000n, stack = 0x60000000n, stackSize = 1024n * 1024n, sentinel = 0x7fff0000n;
  const imports = new NativeImports(cpu);
  let loaded: ReturnType<typeof loadElf> | undefined;
  let stackMapped = false;
  const started = performance.now();
  let sliceCount = 0, completedInitializers = 0;
  let last: ExecutionResult = { reason: "end", pc: sentinel, elapsedMs: 0 };
  let status: InitializationProbe["status"] = "initializers-returned";
  let blockedSymbol: string | undefined, blockedLibrary: string | undefined;
  try {
    loaded = loadElf(cpu, image, base, imports.resolve);
    cpu.map(stack, stackSize, 3); stackMapped = true;
    cpu.writeRegister("sp", stack + stackSize - 16n);
    for (const initializer of loaded.initializers) {
      if (sliceCount >= 20 || performance.now() - started >= 3000) {
        status = "budget";
        last = { reason: "budget", pc: initializer, elapsedMs: 0 };
        break;
      }
      cpu.writeRegister("x30", sentinel);
      let pc = initializer;
      while (sliceCount < 20 && performance.now() - started < 3000) {
        sliceCount++;
        last = cpu.run(pc, sentinel, 10_000);
        pc = last.pc;
        if (last.reason === "interrupt" && imports.handleInterrupt(last.pc)) {
          pc = cpu.readRegister("pc");
          last = { reason: "budget", pc, elapsedMs: last.elapsedMs };
          continue;
        }
        if (last.reason === "budget") continue;
        break;
      }
      if (last.reason === "interrupt") {
        const entry = imports.atInterrupt(last.pc);
        status = entry ? "blocked-import" : "blocked-interrupt";
        blockedSymbol = entry?.symbol.name; blockedLibrary = entry?.symbol.version?.library;
        break;
      }
      if (last.reason === "fault") { status = "fault"; break; }
      if (last.reason === "budget") { status = "budget"; break; }
      completedInitializers++;
    }
    return { status, completedInitializers, initializerCount: loaded.initializers.length,
      sliceCount, instructionBudget: 200_000, elapsedMs: performance.now() - started,
      wasmMemoryBytes: cpu.wasmMemoryBytes, last,
      ...(blockedSymbol ? { blockedSymbol } : {}), ...(blockedLibrary ? { blockedLibrary } : {}),
      registers: { x0: cpu.readRegister("x0"), x1: cpu.readRegister("x1"), x2: cpu.readRegister("x2"),
                   x8: cpu.readRegister("x8"), x30: cpu.readRegister("x30"), sp: cpu.readRegister("sp") },
    };
  } finally {
    if (stackMapped) cpu.unmap(stack, stackSize);
    loaded?.dispose(); imports.dispose();
  }
}
