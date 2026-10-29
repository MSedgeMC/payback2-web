import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { probeInitialization } from "../../src/runtime/initialize.ts";
import { NativeImports } from "../../src/runtime/symbols.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";

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
  const imports = new NativeImports(cpu);
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
  const cpu = await createRuntime(), imports = new NativeImports(cpu);
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

test("getauxval returns verified ARM64 features while unsupported queries remain blocked", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu);
  try {
    const symbol = { ...parseElf(syntheticElf()).symbols[1]!, name: "getauxval",
                     version: { name: "LIBC", library: "libc.so" } };
    const address = imports.resolve(symbol), end = 0x7fff0000n;
    cpu.writeRegister("x0", 16n); cpu.writeRegister("x30", end); cpu.writeRegister("x19", 123n);
    const result = cpu.run(address, end, 20);
    assert.equal(result.reason, "interrupt");
    assert.equal(imports.handleInterrupt(result.pc), true);
    assert.equal(cpu.readRegister("x0"), 3n);
    assert.equal(cpu.readRegister("pc"), end);
    assert.equal(cpu.readRegister("x19"), 123n);
    cpu.writeRegister("x0", 26n);
    assert.equal(imports.handleInterrupt(cpu.run(address, end, 20).pc), true);
    assert.equal(cpu.readRegister("x0"), 0n);
    cpu.writeRegister("x0", 6n);
    assert.equal(imports.handleInterrupt(result.pc), false);
    assert.equal(cpu.readRegister("x0"), 6n);
    const other = imports.resolve({ ...symbol, version: { name: "LIBC", library: "other.so" } });
    cpu.writeRegister("x0", 16n);
    assert.equal(imports.handleInterrupt(cpu.run(other, end, 20).pc), false);
  } finally { imports.dispose(); cpu.close(); }
});

test("initializer native calls resume correctly and repeated calls stay bounded", async () => {
  for (const loop of [false, true]) {
    const image = parseElf(syntheticElf());
    image.symbols[1]!.name = "getauxval";
    image.symbols[1]!.version = { name: "LIBC", library: "libc.so" };
    image.relocations[0]!.addend = 0n;
    const offset = 0x22b0 - 0x308;
    const loadAddress = 0x10000010 | ((offset & 3) << 29) | ((offset >>> 2) << 5);
    image.bytes.set(words(0xa9bf7bfd, 0x52800200, loadAddress, 0xf9400210,
                          0xd63f0200, loop ? 0x17fffffc : 0xa8c17bfd, 0xd65f03c0), 0x300);
    const cpu = await createRuntime();
    try {
      const result = probeInitialization(cpu, image);
      assert.equal(result.status, loop ? "budget" : "initializers-returned");
      assert.equal(result.completedInitializers, loop ? 0 : 2);
      assert.equal(result.blockedSymbol, undefined);
      assert.equal(cpu.regions.length, 0);
    } finally { cpu.close(); }
  }
});
