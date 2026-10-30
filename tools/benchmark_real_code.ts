import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createRuntime } from "../src/runtime/unicorn.ts";
import { translate, PC_OFFSET } from "../src/runtime/translate/translate.ts";
import { decode } from "../src/runtime/translate/arm64.ts";

// Measures the dependency's real integrity loop under both engines, and reports how much of
// a real code region the translator covers. The library is local private data, never committed.
const LIBRARY = resolve(import.meta.dirname, "../.local/dependencies/libpairipcore.so");
const START = 0x47d20, EXIT = 0x47d4c, CODE_PAGE = 0x47000;
const TABLE = 0x60000, BUFFER = 0x61000, INDEX = 0x60200;
const FNV_OFFSET = 0xcbf29ce484222325n, FNV_PRIME = 0x100000001b3n;
const BYTES = 200_000, REPEATS = 200;
const INSTRUCTIONS_PER_BYTE = 7;

const library = new Uint8Array(await readFile(LIBRARY));
const code = new Uint8Array(EXIT); code.set(library.subarray(START, EXIT), START);
const seed = new Uint8Array(BYTES);
for (let index = 0; index < BYTES; index++) seed[index] = (index * 37 + 11) & 0xff;

async function interpreted(): Promise<{ elapsedMs: number; hash: bigint }> {
  const cpu = await createRuntime();
  try {
    cpu.map(BigInt(CODE_PAGE), 4096n, 5); cpu.copyIn(BigInt(START), library.subarray(START, EXIT));
    const dataBytes = BigInt(Math.ceil((BUFFER - TABLE + BYTES) / 4096) * 4096);
    cpu.map(BigInt(TABLE), dataBytes, 3);
    const table = new Uint8Array(8); new DataView(table.buffer).setBigUint64(0, BigInt(BUFFER), true);
    cpu.copyIn(BigInt(TABLE), table);
    const index = new Uint8Array(8); new DataView(index.buffer).setUint32(0, 0, true); cpu.copyIn(BigInt(INDEX), index);
    cpu.copyIn(BigInt(BUFFER), seed);
    cpu.writeRegister("x8", BigInt(TABLE)); cpu.writeRegister("x22", BigInt(INDEX));
    cpu.writeRegister("x9", BigInt(BYTES)); cpu.writeRegister("x13", FNV_OFFSET); cpu.writeRegister("x29", FNV_PRIME);
    const started = performance.now();
    let slices = 0;
    let result = cpu.run(BigInt(START), BigInt(EXIT), 100000);
    while (result.reason === "budget" && slices++ < 10000) result = cpu.run(result.pc, BigInt(EXIT), 100000);
    const elapsedMs = performance.now() - started;
    if (result.reason !== "end") throw new Error(`interpreter stopped: ${result.reason}`);
    return { elapsedMs, hash: cpu.readRegister("x13") };
  } finally { cpu.close(); }
}

function translated(): { elapsedMs: number; hash: bigint } {
  const pages = Math.ceil((BUFFER + BYTES) / 65536);
  const result = translate(code, START, EXIT, pages);
  if (result.unsupported.length) throw new Error("the integrity loop must be fully translatable");
  const instance = new WebAssembly.Instance(result.module, {});
  const view = new DataView((instance.exports.memory as WebAssembly.Memory).buffer);
  const table = new Uint8Array(view.buffer, TABLE, 8); new DataView(table.buffer, table.byteOffset).setBigUint64(0, BigInt(BUFFER), true);
  new Uint8Array(view.buffer, BUFFER, BYTES).set(seed);
  const run = (): void => {
    view.setBigUint64(8 * 8, BigInt(TABLE), true);
    view.setBigUint64(9 * 8, BigInt(BYTES), true);
    view.setBigUint64(13 * 8, FNV_OFFSET, true);
    view.setBigUint64(22 * 8, BigInt(INDEX), true);
    view.setBigUint64(29 * 8, FNV_PRIME, true);
    view.setBigUint64(PC_OFFSET, BigInt(START), true);
    (instance.exports.run as () => void)();
  };
  run();
  const started = performance.now();
  for (let repeat = 0; repeat < REPEATS; repeat++) run();
  const elapsedMs = (performance.now() - started) / REPEATS;
  return { elapsedMs, hash: view.getBigUint64(13 * 8, true) };
}

// Coverage over a contiguous slice of the dependency's text. `udf` and undecodable words are
// data and padding inside .text rather than code, so they are reported separately.
function coverage(start: number, length: number): { words: number; code: number; supported: number; percentOfCode: number } {
  let supported = 0, code = 0, words = 0;
  const view = new DataView(library.buffer, library.byteOffset, library.byteLength);
  for (let address = start; address + 4 <= start + length; address += 4) {
    words++;
    const word = view.getUint32(address, true);
    if (word === 0 || word === 0xd503201f) continue;
    try { decode(address, word); supported++; code++; }
    catch { if (!isUdf(word)) code++; }
  }
  return { words, code, supported, percentOfCode: Math.round(supported / code * 1000) / 10 };
}

/** `udf #imm16` (0x0000xxxx) is padding or a trap placeholder, not executable code. */
function isUdf(word: number): boolean {
  return ((word & 0xffff0000) >>> 0) === 0;
}

const slow = await interpreted(), fast = translated();
if (slow.hash !== fast.hash) throw new Error(`hash mismatch: ${slow.hash} vs ${fast.hash}`);
const guestInstructions = INSTRUCTIONS_PER_BYTE * BYTES;
const report = {
  loop: { start: `0x${START.toString(16)}`, exit: `0x${EXIT.toString(16)}`, bytesHashed: BYTES, hash: `0x${slow.hash.toString(16)}` },
  interpreted: { elapsedMs: Math.round(slow.elapsedMs * 100) / 100, mips: Math.round(guestInstructions / slow.elapsedMs / 1000) },
  translated: { elapsedMs: Math.round(fast.elapsedMs * 1000) / 1000, mips: Math.round(guestInstructions / fast.elapsedMs / 1000),
    repeats: REPEATS, note: "per-hash time, averaged" },
  speedup: Math.round(slow.elapsedMs / fast.elapsedMs),
  coverage: { text: coverage(0, 0x79000) },
  scope: "Real engine code from the local dependency; Node on the VPS; no browser and no game frame",
};
await mkdir(".local", { recursive: true });
await writeFile(".local/real-code-benchmark.json", JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 2));
