import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { readVariadicWords } from "../../src/runtime/aarch64-varargs.ts";

test("AArch64 variadic long reads signed register-save and stack values without changing the passed va_list", async () => {
  const cpu = await createRuntime(), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    const bytes = new Uint8Array(32), view = new DataView(bytes.buffer), argument = new Uint8Array(8);
    view.setBigUint64(0, data + 256n, true); view.setBigUint64(8, data + 128n, true);
    for (const [offset, value] of [[-64, -0x8000000000000000n], [-40, -0x123456789abcdefn], [-8, 0x7fffffffffffffffn]] as const) {
      view.setInt32(24, offset, true); new DataView(argument.buffer).setBigInt64(0, value, true);
      cpu.copyIn(data, bytes); cpu.copyIn(data + 128n + BigInt(offset), argument); cpu.protect(data, 4096n, 1);
      assert.equal(BigInt.asIntN(64, readVariadicWords(cpu, data, 1)[0]!), value); assert.deepEqual(cpu.copyOut(data, 32), bytes);
      cpu.protect(data, 4096n, 3);
    }
    for (const offset of [0, 8]) {
      view.setInt32(24, offset, true); view.setBigUint64(8, 0n, true); cpu.copyIn(data, bytes);
      new DataView(argument.buffer).setBigInt64(0, 42n, true); cpu.copyIn(data + 256n, argument);
      assert.equal(BigInt.asIntN(64, readVariadicWords(cpu, data, 1)[0]!), 42n); assert.deepEqual(cpu.copyOut(data, 32), bytes);
    }
  } finally { cpu.unmap(data, 4096n); cpu.close(); }
});

test("AArch64 variadic words cross from the last GP slot to the stack and preserve unsigned handles", async () => {
  const cpu = await createRuntime(), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    const bytes = new Uint8Array(32), view = new DataView(bytes.buffer), arguments_ = new Uint8Array(16);
    view.setBigUint64(0, data + 256n, true); view.setBigUint64(8, data + 128n, true); view.setInt32(24, -8, true);
    const values = [0xffffffffffffffffn, 0x8000000000000000n, 0x123456789abcdef0n];
    new DataView(arguments_.buffer).setBigUint64(0, values[0]!, true); cpu.copyIn(data + 120n, arguments_.subarray(0, 8));
    const stackView = new DataView(arguments_.buffer);
    stackView.setBigUint64(0, values[1]!, true); stackView.setBigUint64(8, values[2]!, true);
    cpu.copyIn(data + 256n, arguments_); cpu.copyIn(data, bytes); cpu.protect(data, 4096n, 1);
    assert.deepEqual(readVariadicWords(cpu, data, 3), values);
    assert.deepEqual(cpu.copyOut(data, 32), bytes);
    for (const count of [-1, 1.5, 9, NaN]) assert.throws(() => readVariadicWords(cpu, data, count), /count/);
    assert.deepEqual(readVariadicWords(cpu, data, 0), []);
    cpu.protect(data, 4096n, 3);
    view.setBigUint64(0, data + 4096n, true); cpu.copyIn(data, bytes);
    assert.throws(() => readVariadicWords(cpu, data, 2), /readable/);
    view.setBigUint64(0, data + 257n, true); cpu.copyIn(data, bytes);
    assert.throws(() => readVariadicWords(cpu, data, 2), /argument is not aligned/);
  } finally { cpu.unmap(data, 4096n); cpu.close(); }
});

test("AArch64 variadic long rejects invalid offsets, alignment, and inaccessible argument storage", async () => {
  const cpu = await createRuntime(), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    const bytes = new Uint8Array(32), view = new DataView(bytes.buffer);
    view.setBigUint64(8, data + 128n, true);
    for (const offset of [-72, -7]) { view.setInt32(24, offset, true); cpu.copyIn(data, bytes); assert.throws(() => readVariadicWords(cpu, data, 1), /save area/); }
    view.setInt32(24, -8, true); view.setBigUint64(8, data + 129n, true); cpu.copyIn(data, bytes);
    assert.throws(() => readVariadicWords(cpu, data, 1), /save area/);
    view.setBigUint64(8, data + 8192n, true); cpu.copyIn(data, bytes); assert.throws(() => readVariadicWords(cpu, data, 1), /readable/);
    view.setInt32(24, 0, true); view.setBigUint64(0, data + 1n, true); cpu.copyIn(data, bytes);
    assert.throws(() => readVariadicWords(cpu, data, 1), /argument is not aligned/);
    assert.throws(() => readVariadicWords(cpu, data + 1n, 1), /va_list is not aligned/);
    assert.throws(() => readVariadicWords(cpu, data + 4088n, 1), /readable/);
  } finally { cpu.unmap(data, 4096n); cpu.close(); }
});
