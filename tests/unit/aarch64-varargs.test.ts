import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { readVariadicLong } from "../../src/runtime/aarch64-varargs.ts";

test("AArch64 variadic long reads signed register-save and stack values without changing the passed va_list", async () => {
  const cpu = await createRuntime(), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    const bytes = new Uint8Array(32), view = new DataView(bytes.buffer), argument = new Uint8Array(8);
    view.setBigUint64(0, data + 256n, true); view.setBigUint64(8, data + 128n, true);
    for (const [offset, value] of [[-64, -0x8000000000000000n], [-40, -0x123456789abcdefn], [-8, 0x7fffffffffffffffn]] as const) {
      view.setInt32(24, offset, true); new DataView(argument.buffer).setBigInt64(0, value, true);
      cpu.copyIn(data, bytes); cpu.copyIn(data + 128n + BigInt(offset), argument); cpu.protect(data, 4096n, 1);
      assert.equal(readVariadicLong(cpu, data), value); assert.deepEqual(cpu.copyOut(data, 32), bytes);
      cpu.protect(data, 4096n, 3);
    }
    for (const offset of [0, 8]) {
      view.setInt32(24, offset, true); view.setBigUint64(8, 0n, true); cpu.copyIn(data, bytes);
      new DataView(argument.buffer).setBigInt64(0, 42n, true); cpu.copyIn(data + 256n, argument);
      assert.equal(readVariadicLong(cpu, data), 42n); assert.deepEqual(cpu.copyOut(data, 32), bytes);
    }
  } finally { cpu.unmap(data, 4096n); cpu.close(); }
});

test("AArch64 variadic long rejects invalid offsets, alignment, and inaccessible argument storage", async () => {
  const cpu = await createRuntime(), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    const bytes = new Uint8Array(32), view = new DataView(bytes.buffer);
    view.setBigUint64(8, data + 128n, true);
    for (const offset of [-72, -7]) { view.setInt32(24, offset, true); cpu.copyIn(data, bytes); assert.throws(() => readVariadicLong(cpu, data), /save area/); }
    view.setInt32(24, -8, true); view.setBigUint64(8, data + 129n, true); cpu.copyIn(data, bytes);
    assert.throws(() => readVariadicLong(cpu, data), /save area/);
    view.setBigUint64(8, data + 8192n, true); cpu.copyIn(data, bytes); assert.throws(() => readVariadicLong(cpu, data), /readable/);
    view.setInt32(24, 0, true); view.setBigUint64(0, data + 1n, true); cpu.copyIn(data, bytes);
    assert.throws(() => readVariadicLong(cpu, data), /argument is not aligned/);
    assert.throws(() => readVariadicLong(cpu, data + 1n), /va_list is not aligned/);
    assert.throws(() => readVariadicLong(cpu, data + 4088n), /readable/);
  } finally { cpu.unmap(data, 4096n); cpu.close(); }
});
