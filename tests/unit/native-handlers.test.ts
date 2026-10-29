import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeImports } from "../../src/runtime/symbols.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";

test("registered native handlers execute at traps, preserve the caller, and expose errors", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu), end = 0x7fff0000n;
  try {
    const symbol = parseElf(syntheticElf()).symbols[1]!;
    const address = imports.bind(symbol, () => cpu.writeRegister("x0", 42n));
    assert.throws(() => imports.bind(symbol, () => {}), /already/);
    assert.throws(() => imports.bind({ ...symbol, type: 1 }, () => {}), /functions/);
    cpu.writeRegister("x19", 123n); cpu.writeRegister("x30", end);
    assert.equal(imports.handleInterrupt(cpu.run(address, end, 20).pc), true);
    assert.equal(cpu.readRegister("x0"), 42n); assert.equal(cpu.readRegister("x19"), 123n);
    assert.equal(cpu.readRegister("pc"), end);
    const failing = imports.bind({ ...symbol, name: "failing_handler" }, () => { throw new Error("handler failed"); });
    const result = cpu.run(failing, end, 20);
    assert.throws(() => imports.handleInterrupt(result.pc), /handler failed/);
    assert.equal(cpu.readRegister("pc"), result.pc);
    const declined = imports.bind({ ...symbol, name: "unsupported_argument" }, () => false);
    cpu.writeRegister("x0", 456n);
    const blocked = cpu.run(declined, end, 20);
    assert.equal(imports.handleInterrupt(blocked.pc), false);
    assert.equal(cpu.readRegister("pc"), blocked.pc); assert.equal(cpu.readRegister("x0"), 456n);
  } finally { imports.dispose(); cpu.close(); }
});

test("native interface traps span two pages while their function budget stays bounded", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu);
  try {
    const symbol = parseElf(syntheticElf()).symbols[1]!;
    for (let index = 0; index < 512; index++) imports.resolve({ ...symbol, name: `host_${index}` });
    assert.throws(() => imports.resolve({ ...symbol, name: "excess" }), /budget/);
    const entry = imports.entries[511]!;
    assert.ok(entry.address >= 0x70001000n);
    const result = cpu.run(entry.address, 0x7fff0000n, 20);
    assert.equal(result.reason, "interrupt"); assert.equal(imports.atInterrupt(result.pc)?.symbol.name, "host_511");
    assert.equal(imports.handleInterrupt(result.pc), false);
  } finally { imports.dispose(); assert.equal(cpu.regions.length, 0); cpu.close(); }
});
