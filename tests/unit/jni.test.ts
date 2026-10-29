import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { JniEnvironment } from "../../src/runtime/jni.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";

const tableCall = (index: number) => words(0xf9400008, 0xf9400108 | (index << 10), 0xd61f0100);

test("guest JavaVM calls return an attached JNI environment and reject unsupported versions and threads", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), output = 0x40000n;
  try {
    cpu.map(output, 4096n, 3);
    const image = parseElf(syntheticElf()); image.bytes.set(tableCall(6), 0x300);
    const loaded = session.load("jni_fixture.so", image, 0x10000000n), entry = loaded.lookupExport("local");
    const thread = cpu.readRegister("tpidr_el0");
    for (const [requested, expected] of [[0x10006, 0], [0x10004, 0], [0x10008, -3]] as const) {
      const result = session.call(entry, [jni.vmAddress, output, BigInt(requested)]);
      assert.equal(result.status, "returned"); assert.equal(BigInt.asIntN(32, result.registers.x0), BigInt(expected));
      const pointer = new DataView(cpu.copyOut(output, 8).buffer).getBigUint64(0, true);
      assert.equal(pointer, expected === 0 ? jni.environmentAddress : 0n);
    }
    cpu.writeRegister("tpidr_el0", thread + 4096n);
    const detached = session.call(entry, [jni.vmAddress, output, 0x10006n]);
    assert.equal(BigInt.asIntN(32, detached.registers.x0), -2n);
    assert.deepEqual(cpu.copyOut(output, 8), new Uint8Array(8));
    cpu.writeRegister("tpidr_el0", thread);
    cpu.copyIn(entry, tableCall(4));
    assert.equal(session.call(entry, [jni.environmentAddress]).registers.x0, 0x10006n);
    cpu.copyIn(entry, tableCall(17)); cpu.writeRegister("x19", 42n);
    assert.equal(session.call(entry, [jni.environmentAddress]).status, "returned");
    assert.equal(cpu.readRegister("x19"), 42n);
    cpu.copyIn(entry, tableCall(6));
    assert.throws(() => session.call(entry, [jni.vmAddress, output + 4096n, 0x10006n]), /writable/);
    assert.throws(() => session.call(entry, [jni.vmAddress, output, 0x10006n]), /previous call/);
  } finally { jni.dispose(); jni.dispose(); session.dispose(); cpu.unmap(output, 4096n); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("essential JNI methods remain visible failures rather than fabricated Java objects", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports);
  const data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3); cpu.copyIn(data, new TextEncoder().encode("synthetic/Unsupported\0"));
    const image = parseElf(syntheticElf()); image.bytes.set(tableCall(6), 0x300);
    const loaded = session.load("jni_fixture.so", image, 0x10000000n);
    const result = session.call(loaded.lookupExport("local"), [jni.environmentAddress, data]);
    assert.equal(result.status, "blocked-import"); assert.equal(result.blockedSymbol, "JNI.FindClass");
    assert.equal(result.blockedLibrary, "JNIEnv");
    assert.ok(cpu.regions.find(region => region.address === jni.vmAddress)?.permissions === 1);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});

test("JNI standard class lookup creates bounded local handles and validates guest strings", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3); cpu.copyIn(data, new TextEncoder().encode("java/lang/Float\0"));
    const image = parseElf(syntheticElf()); image.bytes.set(tableCall(6), 0x300);
    const entry = session.load("jni_fixture.so", image, 0x10000000n).lookupExport("local"), references = new Set<bigint>();
    for (let index = 0; index < 256; index++) {
      cpu.copyIn(data, new TextEncoder().encode((index % 2 ? "java/lang/Double" : "java/lang/Float") + "\0"));
      const result = session.call(entry, [jni.environmentAddress, data]);
      assert.equal(result.status, "returned"); assert.notEqual(result.registers.x0, 0n);
      references.add(result.registers.x0);
    }
    assert.equal(references.size, 256);
    assert.throws(() => session.call(entry, [jni.environmentAddress, data]), /reference limit/);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
  const invalidCpu = await createRuntime(), invalidSession = new NativeSession(invalidCpu), invalidJni = new JniEnvironment(invalidCpu, invalidSession.imports);
  try {
    const image = parseElf(syntheticElf()); image.bytes.set(tableCall(6), 0x300);
    const entry = invalidSession.load("jni_fixture.so", image, 0x10000000n).lookupExport("local");
    assert.throws(() => invalidSession.call(entry, [invalidJni.environmentAddress, 0n]), /readable/);
  } finally { invalidJni.dispose(); invalidSession.dispose(); invalidCpu.close(); }
});

test("JNI global class references retain identity after local release and reject stale or wrong-lifetime handles", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3); cpu.copyIn(data, new TextEncoder().encode("java/lang/Float\0"));
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    const call = (index: number, argument: bigint): bigint => {
      cpu.copyIn(entry, tableCall(index));
      const result = session.call(entry, [jni.environmentAddress, argument]);
      assert.equal(result.status, "returned"); return result.registers.x0;
    };
    const local = call(6, data), global = call(21, local);
    assert.notEqual(global, local); assert.notEqual(global, 0n);
    call(23, local);
    const retained = call(21, global); assert.notEqual(retained, 0n);
    call(22, global); call(22, retained);
    assert.equal(call(21, 0n), 0n); call(22, 0n); call(23, 0n);
    const wrongLifetime = call(6, data);
    assert.throws(() => call(22, wrongLifetime), /lifetime/);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
  const staleCpu = await createRuntime(), staleSession = new NativeSession(staleCpu), staleJni = new JniEnvironment(staleCpu, staleSession.imports);
  try {
    const image = parseElf(syntheticElf()); image.bytes.set(tableCall(21), 0x300);
    const entry = staleSession.load("jni_fixture.so", image, 0x10000000n).lookupExport("local");
    assert.throws(() => staleSession.call(entry, [staleJni.environmentAddress, 0x73000000n]), /Invalid JNI class reference/);
  } finally { staleJni.dispose(); staleSession.dispose(); staleCpu.close(); }
});

test("JNI method lookup returns stable Float constructor identifiers and blocks unknown descriptors", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    for (const [offset, value] of [[0, "java/lang/Float"], [64, "<init>"], [128, "(F)V"]] as const) {
      cpu.copyIn(data + BigInt(offset), new TextEncoder().encode(value + "\0"));
    }
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    cpu.copyIn(entry, tableCall(6)); const local = session.call(entry, [jni.environmentAddress, data]).registers.x0;
    cpu.copyIn(entry, tableCall(21)); const global = session.call(entry, [jni.environmentAddress, local]).registers.x0;
    cpu.copyIn(entry, tableCall(33));
    const method = session.call(entry, [jni.environmentAddress, local, data + 64n, data + 128n]);
    assert.equal(method.status, "returned"); assert.notEqual(method.registers.x0, 0n);
    assert.equal(session.call(entry, [jni.environmentAddress, global, data + 64n, data + 128n]).registers.x0, method.registers.x0);
    cpu.copyIn(data + 64n, new TextEncoder().encode("floatValue\0"));
    cpu.copyIn(data + 128n, new TextEncoder().encode("()F\0"));
    const accessor = session.call(entry, [jni.environmentAddress, global, data + 64n, data + 128n]);
    assert.equal(accessor.status, "returned"); assert.notEqual(accessor.registers.x0, method.registers.x0);
    cpu.copyIn(data + 64n, new TextEncoder().encode("<init>\0"));
    cpu.copyIn(data + 128n, new TextEncoder().encode("(I)V\0"));
    const unknown = session.call(entry, [jni.environmentAddress, global, data + 64n, data + 128n]);
    assert.equal(unknown.status, "blocked-import"); assert.equal(unknown.blockedSymbol, "JNI.GetMethodID");
    assert.equal(unknown.registers.x0, jni.environmentAddress);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});
