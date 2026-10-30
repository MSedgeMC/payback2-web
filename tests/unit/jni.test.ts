import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { JniEnvironment } from "../../src/runtime/jni.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";
import { readDexClass } from "../../src/runtime/dex.ts";
import { syntheticDex } from "../fixtures/dex.ts";

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
    assert.throws(() => call(21, global), /Invalid JNI reference/);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
  const staleCpu = await createRuntime(), staleSession = new NativeSession(staleCpu), staleJni = new JniEnvironment(staleCpu, staleSession.imports);
  try {
    staleCpu.map(data, 4096n, 3); staleCpu.copyIn(data, new TextEncoder().encode("java/lang/Float\0"));
    const image = parseElf(syntheticElf()); image.bytes.set(tableCall(6), 0x300);
    const entry = staleSession.load("jni_fixture.so", image, 0x10000000n).lookupExport("local");
    const local = staleSession.call(entry, [staleJni.environmentAddress, data]).registers.x0;
    staleCpu.copyIn(entry, tableCall(22));
    assert.throws(() => staleSession.call(entry, [staleJni.environmentAddress, local]), /lifetime/);
  } finally { staleJni.dispose(); staleSession.dispose(); staleCpu.unmap(data, 4096n); staleCpu.close(); }
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
    cpu.copyIn(data + 64n, new TextEncoder().encode("<init>(F\0"));
    cpu.copyIn(data + 128n, new TextEncoder().encode(")V\0"));
    const table = cpu.copyOut(jni.vmAddress + 512n + 33n * 8n, 8), address = new DataView(table.buffer).getBigUint64(0, true);
    cpu.writeRegister("x0", jni.environmentAddress); cpu.writeRegister("x1", global);
    cpu.writeRegister("x2", data + 64n); cpu.writeRegister("x3", data + 128n); cpu.writeRegister("x30", 0x7fff0000n);
    const malformed = cpu.run(address, 0x7fff0000n, 20);
    assert.equal(session.imports.handleInterrupt(malformed.pc), false);
    assert.equal(cpu.readRegister("pc"), malformed.pc); assert.equal(cpu.readRegister("x0"), jni.environmentAddress);
    cpu.copyIn(data + 64n, new TextEncoder().encode("<init>\0"));
    cpu.copyIn(data + 128n, new TextEncoder().encode("(I)V\0"));
    const unknown = session.call(entry, [jni.environmentAddress, global, data + 64n, data + 128n]);
    assert.equal(unknown.status, "blocked-import"); assert.equal(unknown.blockedSymbol, "JNI.GetMethodID");
    assert.equal(unknown.registers.x0, jni.environmentAddress);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});

test("JNI static method lookup resolves Uri parsing and rejects instance lookup of the same method", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    for (const [offset, value] of [[0, "android/net/Uri"], [64, "parse"], [128, "(Ljava/lang/String;)Landroid/net/Uri;"]] as const) {
      cpu.copyIn(data + BigInt(offset), new TextEncoder().encode(value + "\0"));
    }
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    cpu.copyIn(entry, tableCall(6)); const reference = session.call(entry, [jni.environmentAddress, data]).registers.x0;
    const args = [jni.environmentAddress, reference, data + 64n, data + 128n];
    cpu.copyIn(entry, tableCall(113)); const method = session.call(entry, args);
    assert.equal(method.status, "returned"); assert.notEqual(method.registers.x0, 0n);
    assert.equal(session.call(entry, args).registers.x0, method.registers.x0);
    cpu.copyIn(entry, tableCall(33)); const wrongKind = session.call(entry, args);
    assert.equal(wrongKind.status, "blocked-import"); assert.equal(wrongKind.blockedSymbol, "JNI.GetMethodID");
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});

test("JNI static fields have stable typed identifiers and reject the wrong descriptor", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    for (const [offset, value] of [[0, "android/content/Intent"], [64, "FLAG_ACTIVITY_NEW_TASK"], [128, "I"]] as const) {
      cpu.copyIn(data + BigInt(offset), new TextEncoder().encode(value + "\0"));
    }
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    cpu.copyIn(entry, tableCall(6)); const reference = session.call(entry, [jni.environmentAddress, data]).registers.x0;
    const args = [jni.environmentAddress, reference, data + 64n, data + 128n];
    cpu.copyIn(entry, tableCall(144)); const field = session.call(entry, args);
    assert.equal(field.status, "returned"); assert.notEqual(field.registers.x0, 0n);
    assert.equal(session.call(entry, args).registers.x0, field.registers.x0);
    cpu.copyIn(data + 64n, new TextEncoder().encode("ACTION_VIEW\0"));
    cpu.copyIn(data + 128n, new TextEncoder().encode("Ljava/lang/String;\0"));
    const stringField = session.call(entry, args);
    assert.equal(stringField.status, "returned"); assert.notEqual(stringField.registers.x0, field.registers.x0);
    cpu.copyIn(data + 64n, new TextEncoder().encode("FLAG_ACTIVITY_NEW_TASK\0"));
    cpu.copyIn(data + 128n, new TextEncoder().encode("J\0")); const wrongType = session.call(entry, args);
    assert.equal(wrongType.status, "blocked-import"); assert.equal(wrongType.blockedSymbol, "JNI.GetStaticFieldID");
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});

test("JNI class and method lookup use isolated DEX declarations with their actual access flags", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    const definition = readDexClass(syntheticDex(), "example/Runner"); jni.defineClass(definition);
    assert.throws(() => jni.defineClass(definition), /duplicate/);
    assert.throws(() => jni.defineClass({ name: "java/lang/Float", methods: [] }), /duplicate/);
    cpu.map(data, 4096n, 3);
    for (const [offset, value] of [[0, "example/Runner"], [64, "execute"], [128, "([B)Ljava/lang/Object;"]] as const) {
      cpu.copyIn(data + BigInt(offset), new TextEncoder().encode(value + "\0"));
    }
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    cpu.copyIn(entry, tableCall(6)); const reference = session.call(entry, [jni.environmentAddress, data]).registers.x0;
    cpu.copyIn(entry, tableCall(113));
    const args = [jni.environmentAddress, reference, data + 64n, data + 128n];
    assert.equal(session.call(entry, args).status, "returned");
    definition.methods[0]!.isStatic = false;
    assert.equal(session.call(entry, args).status, "returned");
    cpu.copyIn(entry, tableCall(33)); const wrongKind = session.call(entry, args);
    assert.equal(wrongKind.status, "blocked-import");
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});

test("the JVM accepts a created guest thread and still rejects a foreign thread pointer", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu);
  try {
    const jni = new JniEnvironment(cpu, session.imports), original = cpu.readRegister("tpidr_el0");
    try {
      const call = (register: bigint) => {
        cpu.writeRegister("x0", jni.environmentAddress); cpu.writeRegister("tpidr_el0", register); cpu.writeRegister("x30", 0x7fff0000n);
        const pointer = cpu.copyOut(jni.vmAddress + 512n + 4n * 8n, 8), address = new DataView(pointer.buffer).getBigUint64(0, true);
        return cpu.run(address, 0x7fff0000n, 4);
      };
      // The creating thread is accepted.
      assert.equal(session.imports.handleInterrupt(call(original).pc), true);
      // A thread pointer nobody owns is rejected instead of silently accepted.
      assert.throws(() => session.imports.handleInterrupt(call(0x1234567n).pc), /Foreign or detached JNIEnv/);
    } finally { cpu.writeRegister("tpidr_el0", original); jni.dispose(); }
  } finally { session.dispose(); cpu.close(); }
});
