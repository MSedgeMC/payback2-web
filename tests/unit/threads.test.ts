import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { NativeSession } from "../../src/runtime/initialize.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";

const PTHREAD_CREATE = words(0xd28000e0, 0xd65f03c0); // `mov x0, #7` then `ret`

test("a created guest thread runs on its own stack and resumes its parent", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), data = 0x40000n, child = 0x50000n;
  try {
    cpu.map(data, 4096n, 3); cpu.map(child, 4096n, 5);
    cpu.copyIn(child, PTHREAD_CREATE);
    session.load("thread_fixture.so", parseElf(syntheticElf()), 0x10000000n);
    const traps = session.imports.resolve({ name: "pthread_create", type: 2, binding: 1, visibility: 0,
      section: 0, address: 0n, size: 0n, version: { name: "LIBC", library: "libc.so" } });
    const parentStack = cpu.readRegister("sp"), parentMarker = 0x55n;
    cpu.writeRegister("x0", data); cpu.writeRegister("x1", 0n); cpu.writeRegister("x2", child); cpu.writeRegister("x3", 123n);
    cpu.writeRegister("x5", parentMarker); cpu.writeRegister("x30", 0x7fff0000n);
    const trapped = cpu.run(traps, 0x7fff0000n, 4);
    assert.equal(trapped.reason, "interrupt");
    assert.equal(session.imports.handleInterrupt(trapped.pc), true);
    // The parent is suspended inside pthread_create and the child context is installed.
    const childStack = cpu.readRegister("sp");
    assert.equal(cpu.readRegister("pc"), child, "the child starts at its entry point");
    assert.equal(cpu.readRegister("x0"), 123n, "the thread argument arrives in x0");
    assert.notEqual(childStack, parentStack, "the child has its own stack");
    assert.notEqual(cpu.readRegister("tpidr_el0"), 0n, "the child has its own thread pointer");
    const sentinel = session.imports.threads.activeSentinel;
    assert.ok(sentinel !== undefined, "a running guest thread has an exit sentinel");
    const ran = cpu.run(child, sentinel!, 100);
    assert.equal(ran.reason, "end");
    assert.equal(cpu.readRegister("x0"), 7n, "the child returned its value");
    const handle = new DataView(cpu.copyOut(data, 8).buffer).getBigUint64(0, true);
    assert.ok(session.imports.threads.has(handle), "the caller received the thread handle");
    assert.equal(session.imports.threads.resultOf(handle), undefined, "the result is unavailable before the thread exits");
    session.imports.threads.finish(cpu.readRegister("x0"));
    assert.equal(session.imports.threads.resultOf(handle), 7n, "the exit value is retained for pthread_join");
    assert.equal(cpu.readRegister("x5"), parentMarker, "the parent context is restored");
    assert.equal(cpu.readRegister("sp"), parentStack, "the parent keeps its own stack");
    assert.equal(session.imports.threads.activeSentinel, undefined, "the parent is not a guest thread");
  } finally { session.dispose(); cpu.close(); }
});

test("thread creation rejects a non-executable entry point and ignores unknown handles", async () => {
  const cpu = await createRuntime(), session = new NativeSession(cpu), data = 0x40000n;
  try {
    cpu.map(data, 4096n, 3);
    session.load("thread_fixture.so", parseElf(syntheticElf()), 0x10000000n);
    const traps = session.imports.resolve({ name: "pthread_create", type: 2, binding: 1, visibility: 0,
      section: 0, address: 0n, size: 0n, version: { name: "LIBC", library: "libc.so" } });
    cpu.writeRegister("x0", data); cpu.writeRegister("x2", data); cpu.writeRegister("x30", 0x7fff0000n);
    const trapped = cpu.run(traps, 0x7fff0000n, 4);
    assert.throws(() => session.imports.handleInterrupt(trapped.pc), /entry point is outside executable guest memory/);
    assert.equal(session.imports.threads.count(), 0, "a refused thread allocates nothing");
  } finally { session.dispose(); cpu.close(); }
});
