import { writeFile, mkdir } from "node:fs/promises";
import { translate, PC_OFFSET } from "../src/runtime/translate/translate.ts";
import { integerLoop, memoryLoop } from "../tests/fixtures/aarch64.ts";

// Compares the AOT-translated loop against the interpreted measurement in
// docs/PERFORMANCE.md. Synthetic guest loops; guest instructions per second.
const iterations = 50_000_000;

function measure(name: string, code: Uint8Array, loopLength: number, setup: (view: DataView) => void): { name: string; mips: number; elapsedMs: number } {
  const result = translate(code, 0, code.length);
  const instance = new WebAssembly.Instance(result.module, {});
  const view = new DataView((instance.exports.memory as WebAssembly.Memory).buffer);
  const run = (): void => { setup(view); view.setBigUint64(PC_OFFSET, 0n, true); (instance.exports.run as () => void)(); };
  run();
  const started = performance.now();
  run();
  const elapsedMs = performance.now() - started;
  const guestInstructions = loopLength * iterations + 1;
  return { name, mips: guestInstructions / elapsedMs / 1000, elapsedMs };
}

const results = [
  measure("integer and branch (translated)", integerLoop, 3, view => { view.setBigUint64(0, BigInt(iterations), true); view.setBigUint64(8, 0n, true); }),
  measure("load, store, integer and branch (translated)", memoryLoop, 5, view => { view.setBigUint64(0, BigInt(iterations), true); view.setBigUint64(8, 64n, true); }),
];
const report = { iterations, runtime: "AArch64 translated to WebAssembly", results,
  scope: "Synthetic guest loops measured in Node on the VPS; no game frame and no browser measurement" };
await mkdir(".local", { recursive: true });
await writeFile(".local/translate-benchmark.json", JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 2));
