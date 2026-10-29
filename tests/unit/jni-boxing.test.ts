import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { JniEnvironment } from "../../src/runtime/jni.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";

const tableCall = (index: number) => words(0xf9400008, 0xf9400108 | (index << 10), 0xd61f0100);

test("JNI NewObjectV boxes exact signed Java Long values from the AArch64 argument save area", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    for (const [offset, value] of [[0, "java/lang/Long"], [64, "<init>"], [128, "(J)V"]] as const) cpu.copyIn(data + BigInt(offset), new TextEncoder().encode(value + "\0"));
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    const call = (index: number, args: bigint[]) => {
      cpu.copyIn(entry, tableCall(index)); const result = session.call(entry, [jni.environmentAddress, ...args]);
      assert.equal(result.status, "returned"); return result.registers.x0;
    };
    const clazz = call(6, [data]), method = call(33, [clazz, data + 64n, data + 128n]);
    const va = new Uint8Array(32), view = new DataView(va.buffer), argument = new Uint8Array(8);
    view.setBigUint64(0, data + 896n, true); view.setBigUint64(8, data + 768n, true); view.setInt32(24, -40, true); cpu.copyIn(data + 512n, va);
    for (const value of [-0x8000000000000000n, -0x123456789abcdefn, 0x7fffffffffffffffn]) {
      new DataView(argument.buffer).setBigInt64(0, value, true); cpu.copyIn(data + 728n, argument);
      const local = call(29, [clazz, method, data + 512n]);
      assert.deepEqual(jni.referenceValue(local), { kind: "boxed-long", value });
      const object = jni.referenceValue(local);
      assert.deepEqual(cpu.copyOut(data + 512n, 32), va);
      const global = call(21, [local]); call(23, [local]); assert.equal(jni.referenceValue(global), object); call(22, [global]);
    }
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("JNI NewObjectV rejects mismatched constructors and leaves unsupported argument types blocked", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    for (const [offset, value] of [[0, "java/lang/Float"], [64, "<init>"], [128, "(F)V"], [256, "java/lang/Long"]] as const) cpu.copyIn(data + BigInt(offset), new TextEncoder().encode(value + "\0"));
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    cpu.copyIn(entry, tableCall(6)); const clazz = session.call(entry, [jni.environmentAddress, data]).registers.x0;
    cpu.copyIn(entry, tableCall(33)); const method = session.call(entry, [jni.environmentAddress, clazz, data + 64n, data + 128n]).registers.x0;
    cpu.copyIn(entry, tableCall(6)); const longClass = session.call(entry, [jni.environmentAddress, data + 256n]).registers.x0;
    const pointer = cpu.copyOut(jni.vmAddress + 512n + 29n * 8n, 8), address = new DataView(pointer.buffer).getBigUint64(0, true);
    const construct = (type: bigint, constructor: bigint) => {
      [jni.environmentAddress, type, constructor, 0n].forEach((value, index) => cpu.writeRegister(`x${index}`, value)); cpu.writeRegister("x30", 0x7fff0000n);
      return session.imports.handleInterrupt(cpu.run(address, 0x7fff0000n, 20).pc);
    };
    assert.throws(() => construct(0n, method), /class reference/); assert.throws(() => construct(clazz, 0n), /constructor identifier/);
    assert.throws(() => construct(longClass, method), /constructor identifier/);
    assert.equal(construct(clazz, method), false); assert.equal(cpu.readRegister("x0"), jni.environmentAddress);
    assert.equal(session.imports.atInterrupt(cpu.readRegister("pc"))?.symbol.name, "JNI.NewObjectV");
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});
