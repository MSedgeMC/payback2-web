import { openAsBlob } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { basename, isAbsolute, resolve } from "node:path";
import { SUPPORTED_GAME, verifyEngine, verifyPairip } from "../src/assets/baseline.ts";
import { readPackageLibraries } from "../src/assets/importer.ts";
import { createRuntime } from "../src/runtime/unicorn.ts";
import { parseElf } from "../src/runtime/elf.ts";
import { probeGameStartup } from "../src/runtime/startup.ts";

const root = process.env.PAYBACK2_DATA_ROOT;
const path = process.argv[2] ?? (root && isAbsolute(root) ? resolve(root, "game/engine/libpayback2.so") : undefined);
if (!path || !isAbsolute(path)) throw new Error("Pass an absolute local game-file path or set PAYBACK2_DATA_ROOT");
const importStarted = performance.now();
const input = await openAsBlob(path);
const files = await readPackageLibraries(new File([input], basename(path)));
await verifyEngine(files.engine);
if (files.pairip) await verifyPairip(files.pairip);
const importElapsedMs = performance.now() - importStarted;
const image = parseElf(files.engine), pairip = files.pairip ? parseElf(files.pairip) : undefined;
const cpu = await createRuntime();
try {
  const result = probeGameStartup(cpu, image, pairip);
  const serialize = (_key: string, value: unknown): unknown => typeof value === "bigint" ? `0x${value.toString(16)}` : value;
  const report = { engineSha256: SUPPORTED_GAME.engineSha256, ...(pairip ? { pairipSha256: SUPPORTED_GAME.pairipSha256 } : {}), inputBytes: input.size, importElapsedMs,
                   runtime: cpu.name, result };
  await mkdir(".local", { recursive: true });
  await writeFile(".local/engine-probe.json", JSON.stringify(report, serialize, 2) + "\n");
  console.log(JSON.stringify(report, serialize, 2));
} finally { cpu.close(); }
