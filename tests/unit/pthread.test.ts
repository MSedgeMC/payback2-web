import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeImports } from "../../src/runtime/symbols.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";

test("normal native mutexes preserve their object and block repeated or unsupported locks", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu), data = 0x20000n, end = 0x7fff0000n;
  try {
    const symbol = { ...parseElf(syntheticElf()).symbols[1]!, version: { name: "LIBC", library: "libc.so" } };
    const lock = imports.resolve({ ...symbol, name: "pthread_mutex_lock" });
    const unlock = imports.resolve({ ...symbol, name: "pthread_mutex_unlock" });
    cpu.map(data, 4096n, 3);
    const object = new Uint8Array(40).fill(0x99); object[0] = object[1] = 0;
    cpu.copyIn(data, object); cpu.writeRegister("x19", 123n);
    const call = (address: bigint, mutex = data): boolean => {
      cpu.writeRegister("x0", mutex); cpu.writeRegister("x30", end);
      return imports.handleInterrupt(cpu.run(address, end, 20).pc);
    };
    assert.equal(call(lock), true); assert.equal(cpu.readRegister("x0"), 0n);
    const locked = object.slice(); locked[0] = 1;
    assert.deepEqual(cpu.copyOut(data, 40), locked);
    assert.equal(call(lock), false); assert.deepEqual(cpu.copyOut(data, 40), locked);
    assert.equal(call(unlock), true); assert.deepEqual(cpu.copyOut(data, 40), object);
    assert.equal(cpu.readRegister("pc"), end); assert.equal(cpu.readRegister("x19"), 123n);
    for (const state of [2, 0x2000, 0x4000, 0x8000, 0xffff]) {
      const bytes = object.slice(); new DataView(bytes.buffer).setUint16(0, state, true); cpu.copyIn(data, bytes);
      assert.equal(call(lock), false); assert.deepEqual(cpu.copyOut(data, 40), bytes);
    }
    assert.throws(() => call(lock, data + 1n), /aligned/);
    assert.throws(() => call(lock, data + 4096n), /readable/);
    cpu.copyIn(data, object); cpu.protect(data, 4096n, 1);
    assert.throws(() => call(lock), /writable/); assert.deepEqual(cpu.copyOut(data, 40), object);
  } finally { imports.dispose(); cpu.close(); }
});
