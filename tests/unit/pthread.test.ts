import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeImports } from "../../src/runtime/symbols.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";

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

test("pthread_once runs the actual guest callback once and completes only after it returns", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu), data = 0x20000n, callback = 0x30000n, end = 0x7fff0000n;
  try {
    const address = imports.resolve({ ...parseElf(syntheticElf()).symbols[1]!, name: "pthread_once",
      version: { name: "LIBC", library: "libc.so" } });
    cpu.map(data, 4096n, 3); cpu.map(callback, 4096n, 5);
    cpu.copyIn(data, new Uint8Array(4));
    cpu.copyIn(callback, words(0x91000442, 0xd65f03c0)); // add x2,x2,#1; ret
    cpu.writeRegister("x2", 0n); cpu.writeRegister("x19", 123n);
    const begin = (control = data, fn = callback) => {
      cpu.writeRegister("x0", control); cpu.writeRegister("x1", fn); cpu.writeRegister("x30", end);
      return cpu.run(address, end, 20);
    };
    const first = begin(); assert.equal(imports.handleInterrupt(first.pc), true);
    assert.equal(cpu.copyOut(data, 4)[0], 1); assert.equal(cpu.readRegister("pc"), callback);
    assert.equal(cpu.readRegister("x2"), 0n);
    const returned = cpu.run(cpu.readRegister("pc"), end, 20);
    assert.equal(returned.reason, "interrupt"); assert.equal(cpu.readRegister("x2"), 1n);
    assert.equal(imports.handleInterrupt(returned.pc), true);
    assert.deepEqual(cpu.copyOut(data, 4), new Uint8Array([2, 0, 0, 0]));
    assert.equal(cpu.readRegister("x0"), 0n); assert.equal(cpu.readRegister("x30"), end);
    assert.equal(cpu.readRegister("pc"), end); assert.equal(cpu.readRegister("x19"), 123n);
    assert.equal(imports.handleInterrupt(begin().pc), true); assert.equal(cpu.readRegister("x2"), 1n);
    cpu.copyIn(data, new Uint8Array([1, 0, 0, 0]));
    assert.equal(imports.handleInterrupt(begin().pc), false); assert.equal(cpu.readRegister("x2"), 1n);
    cpu.copyIn(data, new Uint8Array(4));
    assert.throws(() => imports.handleInterrupt(begin(data, 0n).pc), /executable/);
    assert.deepEqual(cpu.copyOut(data, 4), new Uint8Array(4));
    assert.throws(() => imports.handleInterrupt(begin(data + 1n).pc), /aligned/);
  } finally { imports.dispose(); cpu.close(); }
});

test("blocked callbacks and invalid callback stacks leave once initialization incomplete", async () => {
  for (const brokenStack of [false, true]) {
    const cpu = await createRuntime(), imports = new NativeImports(cpu), data = 0x20000n, callback = 0x30000n, end = 0x7fff0000n;
    try {
      const symbol = { ...parseElf(syntheticElf()).symbols[1]!, version: { name: "LIBC", library: "libc.so" } };
      const address = imports.resolve({ ...symbol, name: "pthread_once" });
      const blocked = imports.resolve({ ...symbol, name: "unsupported_callback" });
      cpu.map(data, 4096n, 3); cpu.map(callback, 4096n, 5);
      cpu.copyIn(data, new Uint8Array(4));
      cpu.copyIn(callback, brokenStack ? words(0xd10043ff, 0xd65f03c0) : words(0xd61f0200));
      cpu.writeRegister("x0", data); cpu.writeRegister("x1", callback); cpu.writeRegister("x16", blocked); cpu.writeRegister("x30", end);
      assert.equal(imports.handleInterrupt(cpu.run(address, end, 20).pc), true);
      const result = cpu.run(cpu.readRegister("pc"), end, 20);
      assert.equal(result.reason, "interrupt");
      if (brokenStack) assert.throws(() => imports.handleInterrupt(result.pc), /callback stack/);
      else assert.equal(imports.handleInterrupt(result.pc), false);
      assert.deepEqual(cpu.copyOut(data, 4), new Uint8Array([1, 0, 0, 0]));
    } finally { imports.dispose(); cpu.close(); }
  }
});

test("native thread keys retain destructors and full-width values and bound allocation", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu), data = 0x20000n, callback = 0x30000n, end = 0x7fff0000n;
  try {
    const symbol = { ...parseElf(syntheticElf()).symbols[1]!, version: { name: "LIBC", library: "libc.so" } };
    const create = imports.resolve({ ...symbol, name: "pthread_key_create" });
    const get = imports.resolve({ ...symbol, name: "pthread_getspecific" });
    const set = imports.resolve({ ...symbol, name: "pthread_setspecific" });
    const remove = imports.resolve({ ...symbol, name: "pthread_key_delete" });
    cpu.map(data, 4096n, 3); cpu.map(callback, 4096n, 5); cpu.copyIn(callback, words(0xd65f03c0));
    const call = (address: bigint, first: bigint, second = 0n): bigint => {
      cpu.writeRegister("x0", first); cpu.writeRegister("x1", second); cpu.writeRegister("x30", end);
      assert.equal(imports.handleInterrupt(cpu.run(address, end, 20).pc), true);
      return cpu.readRegister("x0");
    };
    assert.throws(() => call(create, data, data), /executable/); assert.equal(imports.threadKeys.size, 0);
    assert.equal(call(create, data, callback), 0n);
    const key = new DataView(cpu.copyOut(data, 4).buffer).getUint32(0, true);
    assert.equal(call(get, BigInt(key)), 0n);
    assert.deepEqual(imports.threadKeys.get(key), { destructor: callback, value: 0n });
    const value = 0xfedcba9876543210n;
    assert.equal(call(set, BigInt(key), value), 0n); assert.equal(call(get, BigInt(key)), value);
    assert.equal(call(remove, BigInt(key)), 0n); assert.equal(call(get, BigInt(key)), 0n);
    assert.equal(call(set, BigInt(key), value), 22n); assert.equal(call(remove, BigInt(key)), 22n);
    for (let index = 0; index < 128; index++) assert.equal(call(create, data), 0n);
    assert.equal(imports.threadKeys.size, 128); assert.equal(call(create, data), 11n);
  } finally { imports.dispose(); assert.equal(imports.threadKeys.size, 0); cpu.close(); }
});
