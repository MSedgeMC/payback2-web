import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeImports } from "../../src/runtime/symbols.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { words } from "../fixtures/aarch64.ts";

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

test("native handler reentry runs nested guest code and continuations in the owning session", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), code = 0x30000n;
  try {
    cpu.map(code, 4096n, 5);
    const symbol = parseElf(syntheticElf()).symbols[1]!, target = code + 256n;
    cpu.copyIn(target, words(0x91001c00, 0xd65f03c0)); // add x0,x0,#7; ret
    let returns = 0;
    const nested = session.imports.bind({ ...symbol, name: "nested" }, () => ({ kind: "call", address: target,
      args: [cpu.readRegister("x0")], onReturn: value => {
        returns++;
        return { kind: "call", address: target, args: [value], onReturn: () => { returns++; } };
      } }));
    cpu.copyIn(code, words(0xa9bf7bfd, 0x580000f0, 0xd63f0200, 0xa8c17bfd, 0xd65f03c0));
    const pointer = new Uint8Array(8); new DataView(pointer.buffer).setBigUint64(0, nested, true); cpu.copyIn(code + 32n, pointer);
    const entry = session.imports.bind({ ...symbol, name: "forward" }, () => ({ kind: "call", address: code,
      args: [35n], onReturn: value => cpu.writeRegister("x0", value * 2n) }));
    const stack = cpu.readRegister("sp"), thread = cpu.readRegister("tpidr_el0"); cpu.writeRegister("x19", 123n);
    const result = session.call(entry, []);
    assert.equal(result.status, "returned"); assert.equal(result.registers.x0, 98n); assert.equal(returns, 2);
    assert.equal(result.registers.x30, 0x7fff0000n); assert.equal(result.registers.sp, stack);
    assert.equal(cpu.readRegister("tpidr_el0"), thread); assert.equal(cpu.readRegister("x19"), 123n);
  } finally { session.dispose(); cpu.unmap(code, 4096n); cpu.close(); }
});

test("native reentry rejects invalid targets and detects corrupted return stack and thread state", async () => {
  for (const corruption of ["target", "args", "stack", "thread"] as const) {
    const cpu = await createRuntime(), session = new NativeSession(cpu), code = 0x30000n;
    try {
      cpu.map(code, 4096n, 5);
      cpu.copyIn(code, corruption === "stack" ? words(0xd10043ff, 0xd65f03c0)
        : corruption === "thread" ? words(0xd51bd05f, 0xd65f03c0) : words(0xd65f03c0)); // msr tpidr_el0,xzr
      const entry = session.imports.bind(parseElf(syntheticElf()).symbols[1]!, () => ({ kind: "call",
        address: corruption === "target" ? code + 1n : code, args: corruption === "args" ? new Array(9).fill(0n) : [] }));
      assert.throws(() => session.call(entry, []), corruption === "target" ? /executable/ : corruption === "args" ? /argument/ : new RegExp(`callback ${corruption}`));
    } finally { session.dispose(); cpu.unmap(code, 4096n); cpu.close(); }
  }
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
