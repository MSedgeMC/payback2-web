import { openAsBlob } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { basename, isAbsolute, resolve } from "node:path";
import { SUPPORTED_GAME, verifyEngine, verifyPairip, verifyStartupBytecode } from "../src/assets/baseline.ts";
import { readPackageLibraries, readPackageBase } from "../src/assets/importer.ts";
import type { BoundedZip } from "../src/assets/importer.ts";
import { createRuntime } from "../src/runtime/unicorn.ts";
import { parseElf } from "../src/runtime/elf.ts";
import { readDex } from "../src/runtime/dex.ts";
import { probeGameStartup } from "../src/runtime/startup.ts";

const root = process.env.PAYBACK2_DATA_ROOT;
const path = process.argv[2] ?? (root && isAbsolute(root) ? resolve(root, "game/engine/libpayback2.so") : undefined);
if (!path || !isAbsolute(path)) throw new Error("Pass an absolute local game-file path or set PAYBACK2_DATA_ROOT");
// Diagnostics may extend the budget; the worker keeps the conservative defaults.
const slices = Number(process.env.PROBE_SLICES ?? 400), milliseconds = Number(process.env.PROBE_MS ?? 3000);
const instructionsPerSlice = process.env.PROBE_SLICE_INSTRUCTIONS ? Number(process.env.PROBE_SLICE_INSTRUCTIONS) : undefined;

const importStarted = performance.now();
const input = await openAsBlob(path);
const file = new File([input], basename(path)), files = await readPackageLibraries(file);
await verifyEngine(files.engine);
if (files.pairip) await verifyPairip(files.pairip);
let base: BoundedZip | undefined;
let cpu: Awaited<ReturnType<typeof createRuntime>> | undefined;
try {
  base = await readPackageBase(file);
  const bytecode = base ? await base.bytes(SUPPORTED_GAME.startupDexName, SUPPORTED_GAME.startupDexBytes) : undefined;
  if (bytecode) await verifyStartupBytecode(bytecode);
  const java = bytecode ? { dex: readDex(bytecode), base } : undefined;
  const importElapsedMs = performance.now() - importStarted;
  const image = parseElf(files.engine), pairip = files.pairip ? parseElf(files.pairip) : undefined;
  cpu = await createRuntime();
  const skipPairip = process.env.SKIP_PAIRIP === "1";
  const result = await probeGameStartup(cpu, image, skipPairip ? undefined : pairip, java, { slices, milliseconds, ...(instructionsPerSlice ? { instructionsPerSlice } : {}) });
  const serialize = (_key: string, value: unknown): unknown => typeof value === "bigint" ? `0x${value.toString(16)}` : value;
  const report = { engineSha256: SUPPORTED_GAME.engineSha256, ...(pairip ? { pairipSha256: SUPPORTED_GAME.pairipSha256 } : {}),
                   ...(bytecode ? { startupDexSha256: SUPPORTED_GAME.startupDexSha256 } : {}), inputBytes: input.size, importElapsedMs,
                   runtime: cpu.name, result };
  await mkdir(".local", { recursive: true });
  await writeFile(".local/engine-probe.json", JSON.stringify(report, serialize, 2) + "\n");
  console.log(JSON.stringify(report, serialize, 2));
} finally { cpu?.close(); await base?.close(); }
