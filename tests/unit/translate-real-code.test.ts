import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { translate, PC_OFFSET } from "../../src/runtime/translate/translate.ts";
import { SUPPORTED_GAME } from "../../src/assets/baseline.ts";

// Real engine code: the dependency's FNV-1a self-integrity loop, entered at 0x47d20.
// The bytes live only in the local private data directory and are never committed.
const LIBRARY = resolve(import.meta.dirname, "../../.local/dependencies/libpairipcore.so");
const START = 0x47d20, EXIT = 0x47d4c, CODE_PAGE = 0x47000;
const TABLE = 0x60000, BUFFER = 0x61000, INDEX = 0x60200;
const FNV_OFFSET = 0xcbf29ce484222325n, FNV_PRIME = 0x100000001b3n;

function instructions(): Uint8Array {
  return new Uint8Array(0);
}
void instructions;

test("the dependency's real integrity loop translates and matches the interpreter", async (context) => {
  let library: Uint8Array;
  try { library = new Uint8Array(await readFile(LIBRARY)); }
  catch { context.skip(); return; }
  // Anchor the test to the verified baseline so a different library cannot masquerade.
  assert.equal(createHash("sha256").update(library).digest("hex"), SUPPORTED_GAME.pairipSha256);
  // The translator indexes by guest address, so the slice is padded to its real extent.
  const code = new Uint8Array(EXIT); code.set(library.subarray(START, EXIT), START);
  const length = 256, seed = new Uint8Array(length);
  for (let index = 0; index < length; index++) seed[index] = (index * 37 + 11) & 0xff;

  // Interpreter: map the real bytes at their real addresses and run to the loop exit.
  const cpu = await createRuntime();
  let interpreted: { x11: bigint; x12: bigint; x13: bigint; x14: bigint; flags: bigint };
  try {
    cpu.map(BigInt(CODE_PAGE), 4096n, 5); cpu.copyIn(BigInt(START), library.subarray(START, EXIT));
    cpu.map(BigInt(TABLE), 8192n + 4096n, 3);
    const table = new Uint8Array(8); new DataView(table.buffer).setBigUint64(0, BigInt(BUFFER), true);
    cpu.copyIn(BigInt(TABLE), table);
    const indexWord = new Uint8Array(8); new DataView(indexWord.buffer).setUint32(0, 0, true);
    cpu.copyIn(BigInt(INDEX), indexWord);
    cpu.copyIn(BigInt(BUFFER), seed);
    cpu.writeRegister("x8", BigInt(TABLE)); cpu.writeRegister("x22", BigInt(INDEX));
    cpu.writeRegister("x9", BigInt(length)); cpu.writeRegister("x13", FNV_OFFSET); cpu.writeRegister("x29", FNV_PRIME);
    const result = cpu.run(BigInt(START), BigInt(EXIT), 100000);
    assert.equal(result.reason, "end", "the interpreter must reach the loop exit");
    interpreted = { x11: cpu.readRegister("x11"), x12: cpu.readRegister("x12"), x13: cpu.readRegister("x13"),
      x14: cpu.readRegister("x14"), flags: cpu.readRegister("nzcv") };
    assert.notEqual(interpreted.x13, FNV_OFFSET, "the hash must actually advance");
  } finally { cpu.close(); }

  // Translator: the same bytes in the same linear memory layout.
  const translation = translate(code, START, EXIT, 8);
  assert.deepEqual(translation.unsupported, [], "the real loop must be fully translatable");
  const instance = new WebAssembly.Instance(translation.module, {});
  const view = new DataView((instance.exports.memory as WebAssembly.Memory).buffer);
  view.setBigUint64(8 * 8, BigInt(TABLE), true);      // x8
  view.setBigUint64(9 * 8, BigInt(length), true);     // x9
  view.setBigUint64(13 * 8, FNV_OFFSET, true);        // x13
  view.setBigUint64(22 * 8, BigInt(INDEX), true);     // x22
  view.setBigUint64(29 * 8, FNV_PRIME, true);         // x29
  new Uint8Array(view.buffer, TABLE, 8).set(new Uint8Array(new BigUint64Array([BigInt(BUFFER)]).buffer));
  new Uint8Array(view.buffer, BUFFER, length).set(seed);
  view.setBigUint64(PC_OFFSET, BigInt(START), true);
  (instance.exports.run as () => void)();

  assert.equal(view.getBigUint64(PC_OFFSET, true), BigInt(EXIT), "translated code must leave at the loop exit");
  assert.equal(view.getBigUint64(13 * 8, true), interpreted.x13, "the FNV hash must be identical");
  assert.equal(view.getBigUint64(11 * 8, true), interpreted.x11, "the index register must match");
  assert.equal(view.getBigUint64(12 * 8, true), interpreted.x12, "the counter must match");
  assert.equal(view.getBigUint64(14 * 8, true), interpreted.x14, "the last byte read must match");
  assert.equal(view.getBigUint64(32 * 8, true), interpreted.flags, "the flags must match");
});
