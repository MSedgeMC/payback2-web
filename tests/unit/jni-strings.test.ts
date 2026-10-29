import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { JniEnvironment } from "../../src/runtime/jni.ts";
import { MAX_MODIFIED_UTF8_BYTES } from "../../src/runtime/modified-utf8.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";

const tableCall = (index: number) => words(0xf9400008, 0xf9400108 | (index << 10), 0xd61f0100);

test("JNI string creation returns independent local values, accepts null, and retains strings through global references", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3); cpu.copyIn(data, new Uint8Array([65, 0xc0, 0x80, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80, 0]));
    const entry = session.load("jni_fixture.so", parseElf(syntheticElf()), 0x10000000n).lookupExport("local");
    const call = (index: number, argument: bigint) => {
      cpu.copyIn(entry, tableCall(index)); const result = session.call(entry, [jni.environmentAddress, argument]);
      assert.equal(result.status, "returned"); return result.registers.x0;
    };
    assert.equal(call(167, 0n), 0n);
    const local = call(167, data), second = call(167, data), global = call(21, local);
    assert.notEqual(local, 0n); assert.notEqual(second, local); assert.notEqual(global, local);
    call(23, local); cpu.copyIn(data, new Uint8Array([0]));
    const empty = call(167, data); assert.notEqual(empty, 0n); assert.notEqual(empty, second);
    const retained = call(21, global); call(22, global); call(22, retained); call(23, second);
    cpu.copyIn(entry, tableCall(33));
    assert.throws(() => session.call(entry, [jni.environmentAddress, empty, data, data]), /class reference/);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, 4096n); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("JNI string creation rejects malformed encoding, unreadable pointers, and unterminated oversized input", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), jni = new JniEnvironment(cpu, session.imports), data = 0x40000n, size = BigInt(MAX_MODIFIED_UTF8_BYTES + 4096);
  try {
    cpu.map(data, size, 3);
    const pointer = cpu.copyOut(jni.vmAddress + 512n + 167n * 8n, 8), address = new DataView(pointer.buffer).getBigUint64(0, true);
    const create = (value: bigint) => {
      cpu.writeRegister("x0", jni.environmentAddress); cpu.writeRegister("x1", value); cpu.writeRegister("x30", 0x7fff0000n);
      const result = cpu.run(address, 0x7fff0000n, 20); assert.equal(result.reason, "interrupt");
      return session.imports.handleInterrupt(result.pc);
    };
    cpu.copyIn(data, new Uint8Array([0xc0, 0x81, 0])); assert.throws(() => create(data), /modified UTF-8/);
    assert.throws(() => create(data + size), /readable/);
    cpu.copyIn(data, new Uint8Array(MAX_MODIFIED_UTF8_BYTES).fill(65));
    assert.throws(() => create(data), /unterminated/);
    assert.equal(session.imports.atInterrupt(cpu.readRegister("pc"))?.symbol.name, "JNI.NewStringUTF");
    assert.equal(cpu.readRegister("x0"), jni.environmentAddress);
  } finally { jni.dispose(); session.dispose(); cpu.unmap(data, size); cpu.close(); }
});
