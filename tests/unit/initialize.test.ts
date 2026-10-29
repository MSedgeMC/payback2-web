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

test("initializer code reads the ARM64 TLS stack guard and restores its caller's thread pointer", async () => {
  const cpu = await createRuntime(), image = parseElf(syntheticElf());
  image.bytes.set(words(0xd53bd040, 0xf9401401, 0xd65f03c0), 0x300); // mrs x0,tpidr_el0; ldr x1,[x0,#40]; ret
  const previous = 0x55000000n, copies = new Map<bigint, Uint8Array>();
  const copyIn = cpu.copyIn.bind(cpu);
  cpu.copyIn = (address, bytes) => { if (bytes.length === 8) copies.set(address, bytes.slice()); copyIn(address, bytes); };
  cpu.writeRegister("tpidr_el0", previous); cpu.writeRegister("sp", previous + 4096n);
  try {
    const result = probeInitialization(cpu, image);
    assert.equal(result.status, "initializers-returned");
    const guard = copies.get(result.registers.x0 + 40n);
    assert.ok(guard);
    assert.equal(result.registers.x1, new DataView(guard.buffer).getBigUint64(0, true));
    assert.equal(cpu.readRegister("tpidr_el0"), previous);
    assert.equal(cpu.readRegister("sp"), previous + 4096n);
    assert.equal(cpu.regions.length, 0);
  } finally { cpu.close(); }
});

test("initializer budget exhaustion cannot be reported as successful execution", async () => {
  const cpu = await createRuntime();
  const previous = 0x55000000n;
  cpu.writeRegister("sp", previous);
  try {
    const image = parseElf(syntheticElf());
    image.initArray!.count = 405;
    image.relocations = Array.from({ length: 405 }, (_, index) =>
      ({ type: 1027, symbolIndex: 0, address: 0x22a0n + BigInt(index * 8), addend: 0x300n }));
    const result = probeInitialization(cpu, image);
    assert.equal(result.status, "budget");
    assert.equal(result.completedInitializers, 400);
    assert.equal(result.sliceCount, 400);
    assert.equal(result.instructionBudget, 200_000);
    assert.equal(cpu.readRegister("sp"), previous);
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

test("getpid returns the stable identifier of the isolated guest process", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu), end = 0x7fff0000n;
  try {
    const address = imports.resolve({ ...parseElf(syntheticElf()).symbols[1]!, name: "getpid",
      version: { name: "LIBC", library: "libc.so" } });
    cpu.writeRegister("x19", 123n);
    for (let count = 0; count < 3; count++) {
      cpu.writeRegister("x0", 999n); cpu.writeRegister("x30", end);
      assert.equal(imports.handleInterrupt(cpu.run(address, end, 20).pc), true);
      assert.equal(cpu.readRegister("x0"), 1n); assert.equal(cpu.readRegister("pc"), end);
      assert.equal(cpu.readRegister("x19"), 123n);
    }
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

test("absent Android properties return an empty value and invalid guest pointers fail", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu);
  try {
    const symbol = { ...parseElf(syntheticElf()).symbols[1]!, name: "__system_property_get",
                     version: { name: "LIBC", library: "libc.so" } };
    const address = imports.resolve(symbol), data = 0x20000n, end = 0x7fff0000n;
    cpu.map(data, 4096n, 3);
    cpu.copyIn(data, new TextEncoder().encode("synthetic.missing\0"));
    cpu.copyIn(data + 128n, new Uint8Array([42, 43]));
    cpu.writeRegister("x0", data); cpu.writeRegister("x1", data + 128n); cpu.writeRegister("x30", end);
    assert.equal(imports.handleInterrupt(cpu.run(address, end, 20).pc), true);
    assert.equal(cpu.readRegister("x0"), 0n);
    assert.deepEqual(cpu.copyOut(data + 128n, 2), new Uint8Array([0, 43]));
    cpu.writeRegister("x0", data + 4096n);
    assert.throws(() => imports.handleInterrupt(cpu.run(address, end, 20).pc), /readable/);
    cpu.writeRegister("x0", data); cpu.writeRegister("x1", data + 4096n);
    assert.throws(() => imports.handleInterrupt(cpu.run(address, end, 20).pc), /writable/);
  } finally { imports.dispose(); cpu.close(); }
});

test("memcpy copies only the requested bytes, returns its destination, and rejects invalid transfers", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu);
  try {
    const symbol = { ...parseElf(syntheticElf()).symbols[1]!, name: "memcpy",
                     version: { name: "LIBC", library: "libc.so" } };
    const address = imports.resolve(symbol), source = 0x20000n, destination = 0x30000n, end = 0x7fff0000n;
    cpu.map(source, 4096n, 3); cpu.map(destination, 4096n, 3);
    cpu.copyIn(source, new Uint8Array([1, 2, 3, 4]));
    cpu.copyIn(destination, new Uint8Array([9, 9, 9, 9, 9]));
    const copy = (to: bigint, from: bigint, size: bigint): boolean => {
      cpu.writeRegister("x0", to); cpu.writeRegister("x1", from); cpu.writeRegister("x2", size); cpu.writeRegister("x30", end);
      const handled = imports.handleInterrupt(cpu.run(address, end, 20).pc);
      assert.equal(typeof handled, "boolean");
      return handled === true;
    };
    cpu.writeRegister("x19", 77n);
    assert.equal(copy(destination + 1n, source, 3n), true);
    assert.deepEqual(cpu.copyOut(destination, 5), new Uint8Array([9, 1, 2, 3, 9]));
    assert.equal(cpu.readRegister("x0"), destination + 1n);
    assert.equal(cpu.readRegister("pc"), end);
    assert.equal(cpu.readRegister("x19"), 77n);
    assert.equal(copy(0n, 0n, 0n), true);
    assert.equal(cpu.readRegister("x0"), 0n);
    assert.throws(() => copy(destination, source + 4096n, 1n), /readable/);
    assert.throws(() => copy(destination, source, 1024n * 1024n + 1n), /byte limit/);
    cpu.protect(destination, 4096n, 1);
    assert.throws(() => copy(destination, source, 1n), /writable/);
    assert.deepEqual(cpu.copyOut(destination, 5), new Uint8Array([9, 1, 2, 3, 9]));
  } finally { imports.dispose(); cpu.close(); }
});

test("C++ exit registration retains callbacks, rejects invalid code, and reports a full table", async () => {
  const cpu = await createRuntime(), imports = new NativeImports(cpu);
  try {
    const symbol = { ...parseElf(syntheticElf()).symbols[1]!, name: "__cxa_atexit",
                     version: { name: "LIBC", library: "libc.so" } };
    const address = imports.resolve(symbol), callback = 0x20000n, end = 0x7fff0000n;
    cpu.map(callback, 4096n, 5); cpu.copyIn(callback, words(0xd65f03c0));
    const register = (fn: bigint, argument: bigint): void => {
      cpu.writeRegister("x0", fn); cpu.writeRegister("x1", argument); cpu.writeRegister("x2", 0xfedcba9876543210n);
      cpu.writeRegister("x30", end);
      assert.equal(imports.handleInterrupt(cpu.run(address, end, 20).pc), true);
    };
    assert.throws(() => register(0n, 0n), /executable/);
    assert.equal(imports.destructors.length, 0);
    for (let index = 0; index < 256; index++) {
      register(callback, BigInt(index));
      assert.equal(cpu.readRegister("x0"), 0n);
    }
    assert.deepEqual(imports.destructors[255], { callback, argument: 255n, dso: 0xfedcba9876543210n });
    register(callback, 256n);
    assert.equal(BigInt.asIntN(32, cpu.readRegister("x0")), -1n);
    assert.equal(imports.destructors.length, 256);
    const finalize = imports.resolve({ ...symbol, name: "__cxa_finalize" });
    assert.equal(imports.handleInterrupt(cpu.run(finalize, end, 20).pc), false);
  } finally { imports.dispose(); assert.equal(imports.destructors.length, 0); cpu.close(); }
});
