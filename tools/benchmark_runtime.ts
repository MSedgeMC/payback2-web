import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createRuntime } from "../src/runtime/unicorn.ts";
import { hostCallLoop, integerLoop, memoryLoop, vectorLoop } from "../tests/fixtures/aarch64.ts";

const BASE = 0x10000n, END = 0x11000n, DATA = 0x20000n;
const iterations = 20_000;
const started = performance.now();
const cpu = await createRuntime();
const startupMs = performance.now() - started;
cpu.map(BASE, 4096n, 5);
cpu.map(DATA, 4096n, 3);
const results: { mix: string; guestInstructions: number; elapsedMs: number; millionInstructionsPerSecond: number }[] = [];

function runLoop(mix: string, code: Uint8Array, loopLength: number, setup: () => void, check: () => void): void {
  cpu.copyIn(BASE, code);
  const times: number[] = [];
  for (let sample = 0; sample < 4; sample++) {
    setup();
    cpu.writeRegister("x0", BigInt(iterations));
    cpu.writeRegister("x30", END);
    const before = performance.now();
    let result = cpu.run(BASE, END, 100_000);
    for (let slice = 0; result.reason === "budget" && slice < 2; slice++) result = cpu.run(result.pc, END, 100_000);
    assert.equal(result.reason, "end", `${mix} failed: ${result.diagnostic ?? result.reason}`);
    check();
    if (sample > 0) times.push(performance.now() - before);
  }
  times.sort((a, b) => a - b);
  const elapsedMs = times[1]!;
  const guestInstructions = loopLength * iterations + 1;
  results.push({ mix, guestInstructions, elapsedMs,
                 millionInstructionsPerSecond: guestInstructions / elapsedMs / 1000 });
}

try {
  runLoop("integer and branch", integerLoop, 3,
          () => cpu.writeRegister("x1", 0n), () => assert.equal(cpu.readRegister("x1"), BigInt(iterations)));
  runLoop("load, store, integer and branch", memoryLoop, 5,
          () => { cpu.writeRegister("x1", DATA); cpu.copyIn(DATA, new Uint8Array(8)); },
          () => assert.equal(new DataView(cpu.copyOut(DATA, 8).buffer).getBigUint64(0, true), BigInt(iterations)));
  runLoop("SIMD and branch", vectorLoop, 3,
          () => { cpu.writeVector(0, new Uint8Array(16)); cpu.writeVector(1, new Uint8Array(new Uint32Array([1, 2, 3, 4]).buffer)); },
          () => assert.deepEqual(new Uint32Array(cpu.readVector(0).buffer), new Uint32Array([iterations, iterations * 2, iterations * 3, iterations * 4])));
  cpu.copyIn(BASE, hostCallLoop);
  cpu.writeRegister("x0", 1000n); cpu.writeRegister("x1", 0n); cpu.writeRegister("x30", END);
  const hostStarted = performance.now();
  let next = BASE, calls = 0;
  while (calls <= 1000) {
    const result = cpu.run(next, END, 100);
    if (result.reason === "end") break;
    assert.equal(result.reason, "interrupt");
    calls++; next = result.pc;
  }
  assert.equal(calls, 1000); assert.equal(cpu.readRegister("x1"), 1000n);
  const hostElapsedMs = performance.now() - hostStarted;
  const output = { runtime: cpu.name, host: { node: process.version, platform: process.platform, arch: process.arch },
                   startupMs, wasmMemoryBytes: cpu.wasmMemoryBytes, samples: "one warmup, median of three measured samples",
                   results, hostCall: { calls, elapsedMs: hostElapsedMs, microsecondsPerCall: hostElapsedMs * 1000 / calls },
                   scope: "Synthetic Node/VPS measurements only; no game-frame or browser FPS measurement" };
  const directory = resolve(".local"); await mkdir(directory, { recursive: true });
  await writeFile(resolve(directory, "runtime-benchmark.json"), JSON.stringify(output, null, 2) + "\n");
  console.log(JSON.stringify(output, null, 2));
} finally { cpu.close(); }
