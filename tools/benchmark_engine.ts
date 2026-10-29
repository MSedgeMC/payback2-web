import assert from "node:assert/strict";
import { readFile, stat, mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { SUPPORTED_GAME, verifyEngine } from "../src/assets/baseline.ts";
import { parseElf, loadElf } from "../src/runtime/elf.ts";
import { createRuntime } from "../src/runtime/unicorn.ts";
import { NativeImports } from "../src/runtime/symbols.ts";
import { words } from "../tests/fixtures/aarch64.ts";

const root = process.env.PAYBACK2_DATA_ROOT;
if (!root || !isAbsolute(root)) throw new Error("Set PAYBACK2_DATA_ROOT to the absolute preserved-data directory");
const path = resolve(root, "game/engine/libpayback2.so");
if ((await stat(path)).size !== SUPPORTED_GAME.engineBytes) throw new Error("Original engine size mismatch");
const bytes = await readFile(path);
await verifyEngine(bytes);
const cpu = await createRuntime(), imports = new NativeImports(cpu);
const base = 0x10000000n, code = 0x10000n, end = 0x7fff0000n;
const symbol = "_ZN9ExitGames6Common7Helpers10MathHelper7getLog2Em";
let loaded: ReturnType<typeof loadElf> | undefined;
try {
  loaded = loadElf(cpu, parseElf(bytes), base, imports.resolve);
  const routine = loaded.lookupExport(symbol);
  // Independently audited leaf routine: integer operations and a read-only lookup table, no calls or writes.
  // shortcut: only positive 32-bit inputs are audited; expand coverage before benchmarking other paths.
  for (const input of [1n, 2n, 3n, 255n, 256n, 65535n, 65536n, 16777215n, 16777216n, 4294967295n]) {
    cpu.writeRegister("x0", input); cpu.writeRegister("x30", end);
    assert.equal(cpu.run(routine, end, 100).reason, "end");
    assert.equal(cpu.readRegister("x0"), BigInt(input.toString(2).length - 1), "Original lookup routine result mismatch");
  }
  cpu.map(code, 4096n, 5);
  cpu.copyIn(code, words(
    0xaa1e03f7, // Preserve the outer return address in x23.
    0x529fffe0, 0xd63f0280, // mov w0, #65535; blr x20
    0x8b0002b5, 0xf1000673, 0x54ffff81, // Accumulate result; decrement x19; repeat.
    0xaa1703fe, 0xd65f03c0,
  ));
  const iterations = 20_000, times: number[] = [];
  for (let sample = 0; sample < 4; sample++) {
    cpu.writeRegister("x19", BigInt(iterations)); cpu.writeRegister("x20", routine);
    cpu.writeRegister("x21", 0n); cpu.writeRegister("x30", end);
    const started = performance.now();
    let result = cpu.run(code, end, 100_000);
    for (let slice = 1; result.reason === "budget" && slice < 8; slice++) result = cpu.run(result.pc, end, 100_000);
    const elapsedMs = performance.now() - started;
    assert.equal(result.reason, "end", result.diagnostic ?? "Original routine benchmark exhausted its work budget");
    assert.equal(cpu.readRegister("x21"), 15n * BigInt(iterations));
    assert.equal(cpu.readRegister("x19"), 0n);
    if (sample > 0) times.push(elapsedMs);
  }
  times.sort((a, b) => a - b);
  const elapsedMs = times[1]!;
  const guestInstructions = iterations * 17 + 3;
  const report = { engineSha256: SUPPORTED_GAME.engineSha256, symbol, input: 65535, iterations,
    runtime: cpu.name, host: { node: process.version, platform: process.platform, arch: process.arch },
    scope: "Original integer lookup routine on Node/VPS; initialization and game frames are outside this measurement",
    samples: "one warmup, median of three measured samples", guestInstructions, elapsedMs,
    millionInstructionsPerSecond: guestInstructions / elapsedMs / 1000,
    microsecondsPerCall: elapsedMs * 1000 / iterations, wasmMemoryBytes: cpu.wasmMemoryBytes };
  await mkdir(".local", { recursive: true });
  await writeFile(".local/engine-routine-benchmark.json", JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(report, null, 2));
} finally { loaded?.dispose(); imports.dispose(); cpu.close(); }
