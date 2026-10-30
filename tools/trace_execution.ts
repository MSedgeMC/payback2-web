import { openAsBlob } from "node:fs";
import { basename, isAbsolute, resolve } from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
import { SUPPORTED_GAME, verifyEngine, verifyPairip, verifyStartupBytecode } from "../src/assets/baseline.ts";
import { readPackageBase, readPackageLibraries } from "../src/assets/importer.ts";
import { createRuntime } from "../src/runtime/unicorn.ts";
import { parseElf } from "../src/runtime/elf.ts";
import { readDex } from "../src/runtime/dex.ts";
import { probeGameStartup } from "../src/runtime/startup.ts";
import type { ExecutionResult } from "../src/runtime/adapter.ts";

// Samples the guest program counter through the real startup path, so a stalled
// initialization can be attributed to one loop instead of a slice budget.
const root = process.env.PAYBACK2_DATA_ROOT;
const path = process.argv[2] ?? (root && isAbsolute(root) ? resolve(root, "game/engine/libpayback2.so") : undefined);
if (!path || !isAbsolute(path)) throw new Error("Pass an absolute local game-file path or set PAYBACK2_DATA_ROOT");
const slices = Number(process.env.TRACE_SLICES ?? 2000), milliseconds = Number(process.env.TRACE_MS ?? 120000);
const dumps = new Set((process.env.TRACE_DUMP ?? "").split(",").filter(Boolean).map(value => BigInt(value)));

const input = await openAsBlob(path);
const files = await readPackageLibraries(new File([input], basename(path)));
await verifyEngine(files.engine);
if (files.pairip) await verifyPairip(files.pairip);
let base: Awaited<ReturnType<typeof readPackageBase>>;
const cpu = await createRuntime();
try {
  base = await readPackageBase(new File([input], basename(path)));
  const bytecode = base ? await base.bytes(SUPPORTED_GAME.startupDexName, SUPPORTED_GAME.startupDexBytes) : undefined;
  if (bytecode) await verifyStartupBytecode(bytecode);
  const java = bytecode ? { dex: readDex(bytecode), base } : undefined;
  const histogram = new Map<bigint, number>(), observed: { pc: string; reason: string; registers: Record<string, string> }[] = [];
  const observe = (result: ExecutionResult): void => {
    histogram.set(result.pc, (histogram.get(result.pc) ?? 0) + 1);
    if (!dumps.has(result.pc)) return;
    const registers: Record<string, string> = {};
    for (let index = 0; index <= 30; index++) registers[`x${index}`] = `0x${cpu.readRegister(`x${index}` as `x${number}`).toString(16)}`;
    registers.sp = `0x${cpu.readRegister("sp").toString(16)}`;
    registers.x8u32 = String(BigInt.asUintN(32, cpu.readRegister("x8")));
    observed.push({ pc: `0x${result.pc.toString(16)}`, reason: result.reason, registers });
  };
  const probe = await probeGameStartup(cpu, parseElf(files.engine), files.pairip ? parseElf(files.pairip) : undefined,
    java, { slices, milliseconds }, observe);
  const top = [...histogram].sort((left, right) => right[1] - left[1]).slice(0, 15)
    .map(([address, count]) => ({ pc: `0x${address.toString(16)}`, samples: count }));
  const report = { status: probe.result.status, blockedSymbol: probe.result.blockedSymbol,
    completedInitializers: "completedInitializers" in probe.result ? probe.result.completedInitializers : undefined,
    slices: probe.result.sliceCount,
    elapsedMs: probe.result.elapsedMs, distinctSamples: histogram.size, top, dumps: observed.slice(0, 4) };
  await mkdir(".local", { recursive: true });
  await writeFile(".local/trace-execution.json", JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(report, null, 2));
} finally { cpu.close(); await base?.close(); }
