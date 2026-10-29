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
    cpu.copyIn(entry, tableCall(6));
    assert.throws(() => session.call(entry, [jni.vmAddress, output + 4096n, 0x10006n]), /writable/);
    assert.throws(() => session.call(entry, [jni.vmAddress, output, 0x10006n]), /previous call/);
  } finally { jni.dispose(); jni.dispose(); session.dispose(); cpu.unmap(output, 4096n); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("essential JNI methods remain visible failures rather than fabricated Java objects", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports);
  try {
    const image = parseElf(syntheticElf()); image.bytes.set(tableCall(6), 0x300);
    const loaded = session.load("jni_fixture.so", image, 0x10000000n);
    const result = session.call(loaded.lookupExport("local"), [jni.environmentAddress, 0n]);
    assert.equal(result.status, "blocked-import"); assert.equal(result.blockedSymbol, "JNI.FindClass");
    assert.equal(result.blockedLibrary, "JNIEnv");
    assert.ok(cpu.regions.find(region => region.address === jni.vmAddress)?.permissions === 1);
  } finally { jni.dispose(); session.dispose(); cpu.close(); }
});
