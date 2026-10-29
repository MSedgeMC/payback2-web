import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { JniEnvironment } from "../../src/runtime/jni.ts";
import { readDex } from "../../src/runtime/dex.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { syntheticManagedDex } from "../fixtures/dex.ts";
import { words } from "../fixtures/aarch64.ts";

const tableCall = (index: number) => words(0xf9400008, 0xf9400108 | (index << 10), 0xd61f0100);

test("JNI static managed calls allocate source arrays, enter registered guest code, and release native frame locals", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n, callback = 0x50000n;
  try {
    const dex = syntheticManagedDex([0x3012, 0x0023, 1, 0x1071, 1, 0, 0x000c, 0x0011]); dex[218] = 2; dex[219] = 0; dex[225] = 0x89;
    jni.attachBytecode(readDex(dex), undefined, name => session.isLibraryInitialized(name));
    assert.throws(() => jni.attachBytecode(readDex(dex), undefined, () => false), /already attached/);
    cpu.map(data, 4096n, 3); cpu.map(callback, 4096n, 5);
    for (const [offset, value] of [[0, "example/Runner"], [32, "execute"], [64, "instance"], [96, "([B)Ljava/lang/Object;"], [256, "native temporary"]] as const) cpu.copyIn(data + BigInt(offset), new TextEncoder().encode(value + "\0"));
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    const call = (index: number, args: bigint[]) => {
      cpu.copyIn(entry, tableCall(index)); const result = session.call(entry, [jni.environmentAddress, ...args]);
      assert.equal(result.status, "returned"); return result.registers.x0;
    };
    const clazz = call(6, [data]), method = call(113, [clazz, data + 32n, data + 96n]);
    const table = new Uint8Array(24), tableView = new DataView(table.buffer);
    tableView.setBigUint64(0, data + 64n, true); tableView.setBigUint64(8, data + 96n, true); tableView.setBigUint64(16, callback, true); cpu.copyIn(data + 128n, table);
    assert.equal(call(215, [clazz, data + 128n, 1n]), 0n);
    cpu.copyIn(callback, words(0xa9bf7bf3, 0xaa0203f3, 0x580001c1, 0xf9400008, 0xf9400108 | (167 << 10),
      0xd63f0100, 0xaa0003e9, 0xaa1303e0, 0xa8c17bf3, 0xd65f03c0));
    const pointer = new Uint8Array(8); new DataView(pointer.buffer).setBigUint64(0, data + 256n, true); cpu.copyIn(callback + 64n, pointer);
    const va = new Uint8Array(32), view = new DataView(va.buffer);
    view.setBigUint64(0, data + 640n, true); view.setBigUint64(8, data + 512n, true); view.setInt32(24, -8, true); cpu.copyIn(data + 384n, va);
    cpu.writeRegister("x19", 123n);
    const value = call(115, [clazz, method, data + 384n]);
    assert.deepEqual(jni.referenceValue(value), { kind: "byte-array", bytes: new Uint8Array(3) });
    assert.equal(cpu.readRegister("x19"), 123n); assert.deepEqual(cpu.copyOut(data + 384n, 32), va);
    const temporary = cpu.readRegister("x9"); assert.notEqual(temporary, 0n);
    assert.throws(() => jni.referenceValue(temporary), /reference/);
    call(23, [value]); assert.throws(() => jni.referenceValue(value), /reference/);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); cpu.unmap(callback, 4096n); cpu.close(); }
});
