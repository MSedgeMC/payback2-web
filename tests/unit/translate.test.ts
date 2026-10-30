import assert from "node:assert/strict";
import { test } from "node:test";
import { translate, PC_OFFSET } from "../../src/runtime/translate/translate.ts";
import { words } from "../fixtures/aarch64.ts";

function run(code: Uint8Array, seed: Record<number, bigint>): { instance: WebAssembly.Instance; read: (register: number) => bigint } {
  const result = translate(code, 0, code.length);
  assert.deepEqual(result.unsupported, [], "the fixture must be fully translatable");
  const instance = new WebAssembly.Instance(result.module, {});
  const view = new DataView((instance.exports.memory as WebAssembly.Memory).buffer);
  for (const [register, value] of Object.entries(seed)) view.setBigUint64(Number(register) * 8, value, true);
  view.setBigUint64(PC_OFFSET, BigInt(result.entry), true);
  (instance.exports.run as () => void)();
  return { instance, read: register => view.getBigUint64(register * 8, true) };
}

test("translated countdown loop matches the interpreter's semantics", () => {
  // add x1, x1, #1 ; subs x0, x0, #1 ; b.ne -8 ; ret
  const code = words(0x91000421, 0xf1000400, 0x54ffffc1, 0xd65f03c0);
  const { read } = run(code, { 0: 1000n, 1: 0n });
  assert.equal(read(0), 0n, "the counter register reaches zero");
  assert.equal(read(1), 1000n, "the loop body ran exactly the requested number of times");
  assert.equal(read(32) & (1n << 30n), 1n << 30n, "subs left the zero flag set");
});

test("translated code handles flags, memory and conditional branches", () => {
  // movz x2, #7 ; str x2, [x0] ; ldr x3, [x0] ; cmp x3, #7 ; b.eq +8 ; movz x3, #1 ; ret
  const code = words(0xd28000e2, 0xf9000002, 0xf9400003, 0xf1001c7f, 0x54000040, 0xd2800023, 0xd65f03c0);
  const { read } = run(code, { 0: 64n });
  assert.equal(read(3), 7n, "the loaded value survives and the equal branch was taken");
});

test("translation reports instruction gaps instead of emitting wrong code", () => {
  const code = words(0xd28000e2, 0xd503201f, 0xd65f03c0);
  const result = translate(code, 0, code.length);
  assert.equal(result.unsupported.length, 0, "nop is inside the supported subset");
  const odd = words(0x9e670000, 0xd65f03c0); // an unassigned encoding
  const reported = translate(odd, 0, odd.length);
  assert.equal(reported.unsupported.length, 1);
  assert.equal(reported.unsupported[0]!.address, 0);
});
