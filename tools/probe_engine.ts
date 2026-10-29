import { readFile, stat, mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { SUPPORTED_GAME, verifyEngine } from "../src/assets/baseline.ts";
import { createRuntime } from "../src/runtime/unicorn.ts";
import { parseElf } from "../src/runtime/elf.ts";
import { probeInitialization } from "../src/runtime/initialize.ts";

const root = process.env.PAYBACK2_DATA_ROOT;
if (!root || !isAbsolute(root)) throw new Error("Set PAYBACK2_DATA_ROOT to the absolute preserved-data directory");
const path = resolve(root, "game/engine/libpayback2.so");
if ((await stat(path)).size !== SUPPORTED_GAME.engineBytes) throw new Error("Original engine size mismatch");
const bytes = await readFile(path);
await verifyEngine(bytes);
const image = parseElf(bytes);
const cpu = await createRuntime();
try {
  const result = probeInitialization(cpu, image);
  const serialize = (_key: string, value: unknown): unknown => typeof value === "bigint" ? `0x${value.toString(16)}` : value;
  const report = { engineSha256: SUPPORTED_GAME.engineSha256, runtime: cpu.name, result };
  await mkdir(".local", { recursive: true });
  await writeFile(".local/engine-probe.json", JSON.stringify(report, serialize, 2) + "\n");
  console.log(JSON.stringify(report, serialize, 2));
} finally { cpu.close(); }
