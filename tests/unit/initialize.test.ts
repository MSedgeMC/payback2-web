import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { probeInitialization } from "../../src/runtime/initialize.ts";
import { DiagnosticImports } from "../../src/runtime/symbols.ts";
import { syntheticElf } from "../fixtures/elf.ts";

test("initializer probe runs genuine fixture code and releases its mappings", async () => {
  const cpu = await createRuntime();
  try {
    const result = probeInitialization(cpu, parseElf(syntheticElf()));
    assert.equal(result.status, "initializers-returned");
    assert.equal(result.completedInitializers, 2);
    assert.equal(cpu.regions.length, 0);
  } finally { cpu.close(); }
});

test("initializer budget exhaustion cannot be reported as successful execution", async () => {
  const cpu = await createRuntime();
  try {
    const image = parseElf(syntheticElf());
    image.initArray!.count = 25;
    image.relocations = Array.from({ length: 25 }, (_, index) =>
      ({ type: 1027, symbolIndex: 0, address: 0x22a0n + BigInt(index * 8), addend: 0x300n }));
    const result = probeInitialization(cpu, image);
    assert.equal(result.status, "budget");
    assert.equal(result.completedInitializers, 20);
    assert.equal(result.sliceCount, 20);
  } finally { cpu.close(); }
});

test("diagnostic function imports trap instead of pretending to implement an API", async () => {
  const cpu = await createRuntime();
  const imports = new DiagnosticImports(cpu);
  try {
    const symbol = parseElf(syntheticElf()).symbols[1]!;
    const address = imports.resolve(symbol);
    const result = cpu.run(address, 0x7fff0000n, 20);
    assert.equal(result.reason, "interrupt");
    assert.equal(imports.atInterrupt(result.pc)?.symbol.name, "host_sample");
    cpu.writeRegister("x1", imports.resolve({ ...symbol, name: "unknown_data", type: 1 }));
    cpu.map(0x10000n, 4096n, 5);
    cpu.copyIn(0x10000n, new Uint8Array([0x20, 0, 0x40, 0xf9])); // ldr x0, [x1]
    assert.equal(cpu.run(0x10000n, 0x11000n, 20).reason, "fault");
  } finally { imports.dispose(); cpu.close(); }
});

test("native imports with different version requirements cannot silently alias", async () => {
  const cpu = await createRuntime(), imports = new DiagnosticImports(cpu);
  try {
    const symbol = { ...parseElf(syntheticElf()).symbols[1]!, version: { name: "LIBC", library: "libc.so" } };
    const first = imports.resolve(symbol);
    assert.equal(imports.resolve(symbol), first);
    const second = imports.resolve({ ...symbol, version: { name: "LIBC_NEXT", library: "libc.so" } });
    assert.notEqual(first, second);
    assert.throws(() => imports.resolve({ ...symbol, type: 1 }), /Conflicting/);
    assert.equal(cpu.run(second, 0x7fff0000n, 20).reason, "interrupt");
  } finally { imports.dispose(); cpu.close(); }
});
