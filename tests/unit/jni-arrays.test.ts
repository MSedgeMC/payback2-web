import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { JniEnvironment } from "../../src/runtime/jni.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";

const tableCall = (index: number) => words(0xf9400008, 0xf9400108 | (index << 10), 0xd61f0100);

test("JNI Object arrays preserve null initialization and retain initial values after local reference release", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3); cpu.copyIn(data, new TextEncoder().encode("java/lang/Object\0initial\0"));
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    const call = (index: number, args: bigint[]) => {
      cpu.copyIn(entry, tableCall(index)); const result = session.call(entry, [jni.environmentAddress, ...args]);
      assert.equal(result.status, "returned"); return result.registers.x0;
    };
    const clazz = call(6, [data]), initial = call(167, [data + 17n]);
    const empty = call(172, [0n, clazz, 0n]), array = call(172, [2n, clazz, 0n]), filled = call(172, [0x100000002n, clazz, initial]);
    const references = (jni as unknown as { references: Map<bigint, { elements: ({ value?: string } | null)[] }> }).references;
    assert.deepEqual(references.get(empty)!.elements, []); assert.deepEqual(references.get(array)!.elements, [null, null]);
    const values = references.get(filled)!.elements;
    assert.equal(values.length, 2); assert.equal(values[0]?.value, "initial"); assert.equal(values[1], values[0]);
    call(174, [array, 0x100000001n, initial]);
    assert.equal(references.get(array)!.elements[1], values[0]);
    const retained = call(21, [filled]); call(23, [initial]); call(23, [filled]);
    assert.equal(references.get(retained)!.elements, values); assert.equal(values[0]?.value, "initial");
    assert.equal(references.get(array)!.elements[1]?.value, "initial");
    call(174, [retained, 1n, 0n]); assert.equal(values[1], null);
    cpu.copyIn(entry, tableCall(33));
    assert.throws(() => session.call(entry, [jni.environmentAddress, array, data, data]), /class reference/);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("JNI Object array writes validate array types, signed indexes, and element handles before mutation", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3); cpu.copyIn(data, new TextEncoder().encode("java/lang/Object\0"));
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    cpu.copyIn(entry, tableCall(6)); const clazz = session.call(entry, [jni.environmentAddress, data]).registers.x0;
    cpu.copyIn(entry, tableCall(172)); const array = session.call(entry, [jni.environmentAddress, 1n, clazz, 0n]).registers.x0;
    const pointer = cpu.copyOut(jni.vmAddress + 512n + 174n * 8n, 8), address = new DataView(pointer.buffer).getBigUint64(0, true);
    const set = (object: bigint, index: bigint, value: bigint) => {
      [jni.environmentAddress, object, index, value].forEach((argument, number) => cpu.writeRegister(`x${number}`, argument)); cpu.writeRegister("x30", 0x7fff0000n);
      return session.imports.handleInterrupt(cpu.run(address, 0x7fff0000n, 20).pc);
    };
    assert.throws(() => set(clazz, 0n, 0n), /array reference/);
    assert.throws(() => set(array, -1n, 0n), /index/); assert.throws(() => set(array, 1n, 0n), /index/);
    assert.throws(() => set(array, 0n, 42n), /element reference/);
    const references = (jni as unknown as { references: Map<bigint, { elements: unknown[] }> }).references;
    assert.deepEqual(references.get(array)!.elements, [null]);
    assert.equal(session.imports.atInterrupt(cpu.readRegister("pc"))?.symbol.name, "JNI.SetObjectArrayElement");
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});

test("JNI Object arrays validate lengths, class and initial references, and cumulative retained allocation", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3); cpu.copyIn(data, new TextEncoder().encode("java/lang/Object\0"));
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    cpu.copyIn(entry, tableCall(6)); const clazz = session.call(entry, [jni.environmentAddress, data]).registers.x0;
    const pointer = cpu.copyOut(jni.vmAddress + 512n + 172n * 8n, 8), address = new DataView(pointer.buffer).getBigUint64(0, true);
    const create = (length = 1n, type = clazz, initial = 0n) => {
      [jni.environmentAddress, length, type, initial].forEach((value, index) => cpu.writeRegister(`x${index}`, value)); cpu.writeRegister("x30", 0x7fff0000n);
      const result = cpu.run(address, 0x7fff0000n, 20); assert.equal(result.reason, "interrupt");
      return session.imports.handleInterrupt(result.pc);
    };
    assert.throws(() => create(-1n), /length/); assert.throws(() => create(16385n), /length/);
    assert.throws(() => create(1n, 0n), /class reference/); assert.throws(() => create(1n, clazz, 42n), /initial element/);
    for (let index = 0; index < 127; index++) assert.equal(create(16384n), true);
    assert.throws(() => create(16384n), /allocation budget/);
    assert.equal(session.imports.atInterrupt(cpu.readRegister("pc"))?.symbol.name, "JNI.NewObjectArray");
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});
