import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../src/runtime/elf.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";

function dependency() {
  const image = parseElf(syntheticElf());
  image.needed = []; image.symbols[2]!.name = "host_sample";
  image.bytes.set(words(0x91001c00, 0xd65f03c0), 0x300); // add x0,x0,#7; ret
  return image;
}

function caller() {
  const image = parseElf(syntheticElf()); image.relocations[0]!.addend = 0n;
  const offset = 0x22b0 - 0x304;
  const loadAddress = 0x10000010 | ((offset & 3) << 29) | ((offset >>> 2) << 5);
  image.bytes.set(words(0xa9bf7bfd, loadAddress, 0xf9400210, 0xd63f0200, 0xa8c17bfd, 0xd65f03c0), 0x300);
  return image;
}

test("native dependencies, imports, and TLS remain resident across linked calls", async () => {
  const cpu = await createRuntime(), previous = 0x55000000n;
  cpu.writeRegister("sp", previous); cpu.writeRegister("tpidr_el0", previous + 4096n);
  const session = new NativeSession(cpu);
  try {
    const core = session.load("libsample.so", dependency(), 0x20000000n);
    const main = session.load("main.so", caller(), 0x10000000n);
    assert.throws(() => session.initialize(main), /not initialized/);
    assert.equal(session.initialize(core).status, "initializers-returned");
    const thread = cpu.readRegister("tpidr_el0"), guard = cpu.copyOut(thread + 40n, 8);
    const pointer = cpu.copyOut(main.base + 0x22b0n, 8);
    assert.equal(new DataView(pointer.buffer).getBigUint64(0, true), core.lookupExport("host_sample"));
    assert.equal(session.initialize(main).status, "initializers-returned");
    const result = session.call(main.lookupExport("local"), [35n]);
    assert.equal(result.status, "returned"); assert.equal(result.registers.x0, 42n);
    assert.equal(cpu.readRegister("tpidr_el0"), thread); assert.deepEqual(cpu.copyOut(thread + 40n, 8), guard);
    assert.throws(() => session.initialize(core), /already initialized/);
    assert.throws(() => session.load("libsample.so", dependency(), 0x30000000n), /duplicate/);
    assert.throws(() => session.call(0n, []), /executable/);
    assert.throws(() => session.call(main.lookupExport("local"), new Array(9).fill(0n)), /argument/);
  } finally { session.dispose(); session.dispose(); }
  assert.equal(cpu.regions.length, 0);
  assert.equal(cpu.readRegister("sp"), previous); assert.equal(cpu.readRegister("tpidr_el0"), previous + 4096n);
  assert.throws(() => session.load("closed.so", dependency(), 0x10000000n), /disposed/);
  cpu.close();
});

test("versioned imports remain explicit traps instead of aliasing an unversioned dependency", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu);
  try {
    const core = session.load("libsample.so", dependency(), 0x20000000n);
    session.initialize(core);
    const image = caller(); image.symbols[1]!.version = { name: "SAMPLE_NEXT", library: "libsample.so" };
    const main = session.load("main.so", image, 0x10000000n);
    const result = session.initialize(main);
    assert.equal(result.status, "blocked-import"); assert.equal(result.blockedSymbol, "host_sample");
    assert.equal(result.blockedLibrary, "libsample.so");
    assert.throws(() => session.call(core.lookupExport("host_sample"), []), /previous call/);
  } finally { session.dispose(); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("ambiguous and incompatible dependency exports fail before mapping the caller", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu);
  try {
    const first = dependency(); first.symbols[2]!.type = 1;
    session.load("libsample.so", first, 0x20000000n);
    const count = cpu.regions.length;
    assert.throws(() => session.load("main.so", caller(), 0x10000000n), /Conflicting/);
    assert.equal(cpu.regions.length, count);
    first.symbols[2]!.type = 2;
    session.load("second.so", dependency(), 0x30000000n);
    const ambiguous = caller(); ambiguous.needed.push("second.so");
    const afterSecond = cpu.regions.length;
    assert.throws(() => session.load("main.so", ambiguous, 0x10000000n), /Ambiguous/);
    assert.equal(cpu.regions.length, afterSecond);
  } finally { session.dispose(); cpu.close(); }
});

test("native thread allocation failure rolls back only session-owned mappings", async () => {
  const cpu = await createRuntime(), address = 0x60000000n;
  try {
    cpu.map(address, 4096n, 3); cpu.writeRegister("sp", 123n); cpu.writeRegister("tpidr_el0", 456n);
    assert.throws(() => new NativeSession(cpu), /overlaps/);
    assert.deepEqual(cpu.regions, [{ address, size: 4096n, permissions: 3 }]);
    assert.equal(cpu.readRegister("sp"), 123n); assert.equal(cpu.readRegister("tpidr_el0"), 456n);
  } finally { cpu.close(); }
});

test("asynchronous native waits yield, reenter guest code, and preserve the owning session", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), code = 0x30000n;
  try {
    cpu.map(code, 4096n, 5); cpu.copyIn(code, words(0x91001c00, 0xd65f03c0));
    let timerRan = false;
    const ready = new Promise<bigint>(resolve => setTimeout(() => { timerRan = true; resolve(35n); }, 10));
    const address = session.imports.bind(parseElf(syntheticElf()).symbols[1]!, () => ({ kind: "wait", ready,
      onReady: value => {
        assert.equal(typeof value, "bigint");
        return { kind: "call", address: code, args: [value as bigint], onReturn: result => ({ kind: "wait",
          ready: Promise.resolve(result * 2n), onReady: doubled => { cpu.writeRegister("x0", doubled as bigint); } }) };
      } }));
    const stack = cpu.readRegister("sp"), thread = cpu.readRegister("tpidr_el0");
    const pending = session.callAsync(address, []);
    assert.throws(() => session.call(code, []), /previous call/);
    const result = await pending;
    assert.equal(timerRan, true); assert.equal(result.status, "returned"); assert.equal(result.registers.x0, 84n);
    assert.equal(result.registers.sp, stack); assert.equal(cpu.readRegister("tpidr_el0"), thread);
    const core = session.load("libsample.so", dependency(), 0x20000000n);
    assert.equal((await session.initializeAsync(core)).status, "initializers-returned");
  } finally { session.dispose(); cpu.unmap(code, 4096n); cpu.close(); }
});

test("native waits expose rejected reads and synchronous callers never resume pending work", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu);
  try {
    const symbol = parseElf(syntheticElf()).symbols[1]!, failure = new Error("asset read failed");
    const recovered = session.imports.bind({ ...symbol, name: "recover" }, () => ({ kind: "wait", ready: Promise.reject(failure),
      onReady: () => assert.fail("Rejected reads cannot succeed"), onError: error => { assert.equal(error, failure); cpu.writeRegister("x0", 123n); } }));
    assert.equal((await session.callAsync(recovered, [])).registers.x0, 123n);
    const rejected = session.imports.bind({ ...symbol, name: "reject" }, () => ({ kind: "wait", ready: Promise.reject(failure), onReady: () => {} }));
    await assert.rejects(session.callAsync(rejected, []), /asset read failed/);
  } finally { session.dispose(); cpu.close(); }
  const syncCpu = await createRuntime(), sync = new NativeSession(syncCpu);
  try {
    let resumed = false;
    const address = sync.imports.bind(parseElf(syntheticElf()).symbols[1]!, () => ({ kind: "wait", ready: Promise.resolve(), onReady: () => { resumed = true; } }));
    assert.throws(() => sync.call(address, []), /asynchronous session call/);
    await Promise.resolve(); assert.equal(resumed, false);
  } finally { sync.dispose(); syncCpu.close(); }
});

test("disposing a suspended native session prevents its continuation from touching released memory", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu);
  let release!: (value: unknown) => void, resumed = false;
  const ready = new Promise(resolve => { release = resolve; });
  const address = session.imports.bind(parseElf(syntheticElf()).symbols[1]!, () => ({ kind: "wait", ready, onReady: () => { resumed = true; } }));
  const pending = session.callAsync(address, []);
  session.dispose(); cpu.close(); release(42n);
  await assert.rejects(pending, /disposed/); assert.equal(resumed, false);
});

test("a stalled native read exhausts the same call deadline and cannot resume afterward", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu);
  let release!: (value: unknown) => void, resumed = false;
  try {
    const ready = new Promise(resolve => { release = resolve; });
    const address = session.imports.bind(parseElf(syntheticElf()).symbols[1]!, () => ({ kind: "wait", ready, onReady: () => { resumed = true; } }));
    const result = await session.callAsync(address, []);
    assert.equal(result.status, "budget"); assert.equal(result.sliceCount, 1);
    assert.equal(result.last.reason, "budget"); assert.throws(() => session.call(address, []), /previous call/);
    release(42n); await Promise.resolve(); assert.equal(resumed, false);
  } finally { session.dispose(); cpu.close(); }
});
