import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { JniEnvironment } from "../../src/runtime/jni.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { readDexClass } from "../../src/runtime/dex.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { syntheticDex } from "../fixtures/dex.ts";
import { words } from "../fixtures/aarch64.ts";

const tableCall = (index: number) => words(0xf9400008, 0xf9400108 | (index << 10), 0xd61f0100);
const descriptor = "([B)Ljava/lang/Object;";

test("JNI native registration retains declared static and instance bindings through reference release and replacement", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    jni.defineClass(readDexClass(syntheticDex(), "example/Runner")); cpu.map(data, 4096n, 3);
    for (const [offset, value] of [[0, "example/Runner"], [64, "execute"], [128, descriptor], [256, "instance"]] as const) {
      cpu.copyIn(data + BigInt(offset), new TextEncoder().encode(value + "\0"));
    }
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    const call = (index: number, args: bigint[]) => { cpu.copyIn(entry, tableCall(index)); return session.call(entry, [jni.environmentAddress, ...args]); };
    const reference = call(6, [data]).registers.x0, native = entry + 64n, replacement = entry + 80n;
    cpu.copyIn(native, words(0xd2800540, 0xd65f03c0)); cpu.copyIn(replacement, words(0xd2800300, 0xd65f03c0));
    const bytes = new Uint8Array(48), view = new DataView(bytes.buffer);
    [data + 64n, data + 128n, native, data + 256n, data + 128n, replacement].forEach((value, index) => view.setBigUint64(index * 8, value, true));
    cpu.copyIn(data + 512n, bytes); cpu.protect(data, 4096n, 1); cpu.writeRegister("x19", 123n);
    const registered = call(215, [reference, data + 512n, 0x100000002n]);
    assert.equal(registered.status, "returned"); assert.equal(registered.registers.x0, 0n); assert.equal(cpu.readRegister("x19"), 123n);
    assert.equal(jni.lookupNative("example/Runner", "execute", descriptor), native);
    assert.equal(jni.lookupNative("example/Runner", "instance", descriptor), replacement);
    assert.deepEqual(cpu.copyOut(data + 512n, bytes.length), bytes);
    assert.equal(session.call(jni.lookupNative("example/Runner", "execute", descriptor)!, []).registers.x0, 42n);
    assert.equal(call(215, [reference, 0n, 0n]).registers.x0, 0n);
    cpu.protect(data, 4096n, 3); view.setBigUint64(16, replacement, true); cpu.copyIn(data + 512n, bytes);
    assert.equal(call(215, [reference, data + 512n, 1n]).status, "returned");
    call(23, [reference]);
    assert.equal(jni.lookupNative("example/Runner", "execute", descriptor), replacement);
    assert.equal(session.call(replacement, []).registers.x0, 24n);
    jni.dispose(); assert.equal(jni.lookupNative("example/Runner", "execute", descriptor), undefined);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("JNI native registration rejects invalid tables and targets and installs no partial or undeclared bindings", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    const definition = readDexClass(syntheticDex(), "example/Runner");
    definition.methods.push({ name: "managed", descriptor, isStatic: true, isNative: false }); jni.defineClass(definition);
    cpu.map(data, 4096n, 3);
    for (const [offset, value] of [[0, "example/Runner"], [64, "execute"], [128, descriptor], [256, "missing"], [320, "managed"]] as const) {
      cpu.copyIn(data + BigInt(offset), new TextEncoder().encode(value + "\0"));
    }
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    cpu.copyIn(entry, tableCall(6)); const reference = session.call(entry, [jni.environmentAddress, data]).registers.x0;
    const bytes = new Uint8Array(48), view = new DataView(bytes.buffer);
    [data + 64n, data + 128n, entry, data + 256n, data + 128n, entry].forEach((value, index) => view.setBigUint64(index * 8, value, true));
    cpu.copyIn(data + 512n, bytes);
    const pointer = cpu.copyOut(jni.vmAddress + 512n + 215n * 8n, 8), address = new DataView(pointer.buffer).getBigUint64(0, true);
    const register = (table = data + 512n, count = 1n, clazz = reference, environment = jni.environmentAddress) => {
      [environment, clazz, table, count].forEach((value, index) => cpu.writeRegister(`x${index}`, value)); cpu.writeRegister("x30", 0x7fff0000n);
      const result = cpu.run(address, 0x7fff0000n, 20); assert.equal(result.reason, "interrupt");
      return session.imports.handleInterrupt(result.pc);
    };
    for (const [table, count, message] of [[data + 512n, -1n, /count/], [data + 512n, 257n, /count/],
      [data + 513n, 1n, /aligned/], [data + 4088n, 1n, /readable/]] as const) assert.throws(() => register(table, count), message);
    for (const target of [0n, entry + 1n, data]) {
      view.setBigUint64(16, target, true); cpu.copyIn(data + 512n, bytes);
      assert.throws(() => register(), /executable/);
    }
    view.setBigUint64(16, entry, true); view.setBigUint64(0, 0n, true); cpu.copyIn(data + 512n, bytes);
    assert.throws(() => register(), /readable/);
    view.setBigUint64(0, data + 64n, true); cpu.copyIn(data + 512n, bytes);
    assert.throws(() => register(data + 512n, 1n, 0n), /class reference/);
    assert.throws(() => register(data + 512n, 1n, reference, jni.vmAddress), /JNIEnv/);
    assert.equal(register(data + 512n, 2n), false);
    assert.equal(jni.lookupNative("example/Runner", "execute", descriptor), undefined);
    assert.equal(cpu.readRegister("x0"), jni.environmentAddress);
    view.setBigUint64(0, data + 320n, true); cpu.copyIn(data + 512n, bytes);
    assert.equal(register(), false); assert.equal(jni.lookupNative("example/Runner", "managed", descriptor), undefined);
    assert.equal(session.imports.atInterrupt(cpu.readRegister("pc"))?.symbol.name, "JNI.RegisterNatives");
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});
