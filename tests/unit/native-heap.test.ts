import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeImports } from "../../src/runtime/symbols.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";

test("native allocation calls reuse memory, zero calloc data, and report ENOMEM through guest errno", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu), end = 0x7fff0000n;
  try {
    const symbol = { ...parseElf(syntheticElf()).symbols[1]!, version: { name: "LIBC", library: "libc.so" } };
    const malloc = imports.resolve({ ...symbol, name: "malloc" }), calloc = imports.resolve({ ...symbol, name: "calloc" });
    const free = imports.resolve({ ...symbol, name: "free" }), errno = imports.resolve({ ...symbol, name: "__errno" });
    const call = (address: bigint, first = 0n, second = 0n): bigint => {
      cpu.writeRegister("x0", first); cpu.writeRegister("x1", second); cpu.writeRegister("x30", end);
      assert.equal(imports.handleInterrupt(cpu.run(address, end, 20).pc), true);
      assert.equal(cpu.readRegister("pc"), end);
      return cpu.readRegister("x0");
    };
    const errnoAddress = call(errno);
    assert.deepEqual(cpu.copyOut(errnoAddress, 4), new Uint8Array(4));
    call(free);
    const address = call(malloc, 32n); assert.notEqual(address, 0n); assert.equal(address % 16n, 0n);
    cpu.copyIn(address, new Uint8Array(32).fill(0x99)); call(free, address);
    assert.throws(() => call(free, address), /active/);
    assert.equal(call(calloc, 4n, 8n), address);
    assert.deepEqual(cpu.copyOut(address, 32), new Uint8Array(32));
    assert.notEqual(call(malloc, 0n), 0n);
    for (const [functionAddress, first, second] of [[malloc, 65n * 1024n * 1024n, 0n],
                                                   [calloc, 1n << 63n, 2n]] as const) {
      assert.equal(call(functionAddress, first, second), 0n);
      assert.equal(new DataView(cpu.copyOut(errnoAddress, 4).buffer).getInt32(0, true), 12);
    }
    assert.equal(call(errno), errnoAddress);
  } finally { imports.dispose(); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("native memset uses the low byte, preserves surrounding memory, and validates its destination", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu), data = 0x20000n, end = 0x7fff0000n;
  try {
    const address = imports.resolve({ ...parseElf(syntheticElf()).symbols[1]!, name: "memset",
      version: { name: "LIBC", library: "libc.so" } });
    cpu.map(data, 4096n, 3); cpu.copyIn(data, new Uint8Array(5).fill(9));
    const fill = (destination: bigint, value: bigint, count: bigint) => {
      cpu.writeRegister("x0", destination); cpu.writeRegister("x1", value); cpu.writeRegister("x2", count); cpu.writeRegister("x30", end);
      return imports.handleInterrupt(cpu.run(address, end, 20).pc);
    };
    assert.equal(fill(data + 1n, 0x1ffn, 3n), true);
    assert.equal(cpu.readRegister("x0"), data + 1n);
    assert.deepEqual(cpu.copyOut(data, 5), new Uint8Array([9, 255, 255, 255, 9]));
    assert.equal(fill(0n, 0n, 0n), true); assert.equal(cpu.readRegister("x0"), 0n);
    assert.throws(() => fill(data, 0n, 1024n * 1024n + 1n), /byte limit/);
    cpu.protect(data, 4096n, 1);
    assert.throws(() => fill(data, 0n, 3n), /writable/);
    assert.deepEqual(cpu.copyOut(data, 5), new Uint8Array([9, 255, 255, 255, 9]));
  } finally { imports.dispose(); cpu.close(); }
});
