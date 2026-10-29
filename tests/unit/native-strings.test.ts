import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeImports } from "../../src/runtime/symbols.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";

test("native strlen counts bytes to NUL and validates readable guest memory", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu), data = 0x40000n, end = 0x7fff0000n;
  try {
    cpu.map(data, 4096n, 3); cpu.copyIn(data, new Uint8Array([0xff, 0xc3, 0xa9, 0, 9]));
    const address = imports.resolve({ ...parseElf(syntheticElf()).symbols[1]!, name: "strlen", version: { name: "LIBC", library: "libc.so" } });
    const length = (pointer: bigint): bigint => {
      cpu.writeRegister("x0", pointer); cpu.writeRegister("x30", end);
      assert.equal(imports.handleInterrupt(cpu.run(address, end, 20).pc), true);
      assert.equal(cpu.readRegister("pc"), end); return cpu.readRegister("x0");
    };
    cpu.writeRegister("x19", 123n);
    assert.equal(length(data), 3n); assert.equal(length(data + 3n), 0n);
    assert.equal(cpu.readRegister("x19"), 123n);
    assert.equal(length(data + 4095n), 0n);
    assert.throws(() => length(data + 4096n), /readable/);
    cpu.protect(data, 4096n, 0); assert.throws(() => length(data), /readable/);
  } finally { imports.dispose(); cpu.unmap(data, 4096n); cpu.close(); }
});
