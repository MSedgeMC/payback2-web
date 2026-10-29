import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { integerArithmetic, vectorAdd, words } from "../fixtures/aarch64.ts";

const BASE = 0x10000n;
const END = 0x11000n;

test("AArch64 executes integer arithmetic and preserves 64-bit register values", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 5);
    cpu.copyIn(BASE, integerArithmetic);
    cpu.writeRegister("x30", END);
    cpu.writeRegister("x15", 0xfedcba9876543210n);
    assert.equal(cpu.run(BASE, END, 20).reason, "end");
    assert.equal(cpu.readRegister("x2"), 0x59n);
    assert.equal(cpu.readRegister("x15"), 0xfedcba9876543210n);
  } finally { cpu.close(); }
});

test("AArch64 SIMD adds four independent 32-bit lanes", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 5);
    cpu.copyIn(BASE, vectorAdd);
    cpu.writeVector(0, new Uint8Array(new Uint32Array([1, 2, 3, 4]).buffer));
    cpu.writeVector(1, new Uint8Array(new Uint32Array([5, 6, 7, 8]).buffer));
    cpu.writeRegister("x30", END);
    assert.equal(cpu.run(BASE, END, 20).reason, "end");
    assert.deepEqual(new Uint32Array(cpu.readVector(2).buffer), new Uint32Array([6, 8, 10, 12]));
  } finally { cpu.close(); }
});

test("AArch64 SIMD shifts use signed low-byte counts and unsigned 64-bit lanes", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 5);
    cpu.copyIn(BASE, words(0x6ee14402, 0xd65f03c0)); // ushl v2.2d,v0.2d,v1.2d; ret
    const input = new BigUint64Array([0x8000000000000003n, 0x8000000000000001n]);
    for (const { shifts, expected } of [
      { shifts: [1n, -1n], expected: [6n, 0x4000000000000000n] },
      { shifts: [-64n, 64n], expected: [0n, 0n] },
      { shifts: [256n, 255n], expected: [input[0]!, 0x4000000000000000n] },
    ]) {
      cpu.writeVector(0, new Uint8Array(input.buffer));
      cpu.writeVector(1, new Uint8Array(new BigUint64Array(shifts).buffer));
      cpu.writeRegister("x30", END);
      assert.equal(cpu.run(BASE, END, 20).reason, "end");
      assert.deepEqual(new BigUint64Array(cpu.readVector(2).buffer), new BigUint64Array(expected));
    }
  } finally { cpu.close(); }
});

test("AArch64 floating point arithmetic and conversion preserve register lanes", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 5);
    cpu.copyIn(BASE, words(0x1e612802, 0x9e780040, 0xd65f03c0)); // fadd d2,d0,d1; fcvtzs x0,d2; ret
    const value = (number: number): Uint8Array => {
      const bytes = new Uint8Array(16); new DataView(bytes.buffer).setFloat64(0, number, true); return bytes;
    };
    cpu.writeVector(0, value(1.5)); cpu.writeVector(1, value(2.25)); cpu.writeRegister("x30", END);
    assert.equal(cpu.run(BASE, END, 20).reason, "end");
    assert.equal(new DataView(cpu.readVector(2).buffer).getFloat64(0, true), 3.75);
    assert.equal(cpu.readRegister("x0"), 3n);
  } finally { cpu.close(); }
});

test("indirect AArch64 calls return to their caller and preserve saved registers", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 5);
    cpu.copyIn(BASE, words(
      0xaa1e03f3, 0xd63f0280, 0x91000400, 0xaa1303fe, 0xd65f03c0,
      0xd503201f, 0xd2800520, 0xd65f03c0,
    )); // Save LR; call x20; increment result; restore LR; return. Callee returns 41.
    cpu.writeRegister("x20", BASE + 24n); cpu.writeRegister("x30", END);
    assert.equal(cpu.run(BASE, END, 20).reason, "end");
    assert.equal(cpu.readRegister("x0"), 42n);
    assert.equal(cpu.readRegister("x19"), END);
    assert.equal(cpu.readRegister("x20"), BASE + 24n);
  } finally { cpu.close(); }
});

test("an infinite guest branch stops at the instruction budget", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 5);
    cpu.copyIn(BASE, words(0x14000000)); // b .
    assert.equal(cpu.run(BASE, END, 1000).reason, "budget");
    assert.equal(cpu.readRegister("pc"), BASE);
    assert.throws(() => cpu.run(BASE, END, 0), /slice/);
  } finally { cpu.close(); }
});

test("rewriting executable memory invalidates translated instructions", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 5);
    cpu.writeRegister("x30", END);
    cpu.copyIn(BASE, words(0xd2800020, 0xd65f03c0)); // mov x0, #1; ret
    assert.equal(cpu.run(BASE, END, 10).reason, "end");
    assert.equal(cpu.readRegister("x0"), 1n);
    cpu.copyIn(BASE, words(0xd2800040, 0xd65f03c0)); // mov x0, #2; ret
    assert.equal(cpu.run(BASE, END, 10).reason, "end");
    assert.equal(cpu.readRegister("x0"), 2n);
    assert.ok(cpu.wasmMemoryBytes > 0);
  } finally { cpu.close(); }
});

test("code loaded after execution and reused mapping addresses contain fresh instructions", async () => {
  const cpu = await createRuntime(), end = 0x7fff0000n;
  try {
    for (const [address, value] of [[0x10000n, 1], [0x20000n, 2], [0x20000n, 3]] as const) {
      cpu.map(address, 4096n, 5);
      cpu.copyIn(address, words(0xd2800000 | (value << 5), 0xd65f03c0));
      cpu.writeRegister("x30", end);
      assert.equal(cpu.run(address, end, 20).reason, "end");
      assert.equal(cpu.readRegister("x0"), BigInt(value));
      cpu.unmap(address, 4096n);
    }
  } finally { cpu.close(); }
});

test("SVC stops before a host implementation runs and records the next PC", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 5);
    cpu.copyIn(BASE, words(0xd4000021, 0xd65f03c0));
    cpu.writeRegister("x30", END);
    const result = cpu.run(BASE, END, 20);
    assert.equal(result.reason, "interrupt");
    assert.equal(result.pc, BASE + 4n);
    assert.equal(cpu.run(result.pc, END, 20).reason, "end");
  } finally { cpu.close(); }
});

test("unmapped guest access and invalid host mappings fail visibly", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 5);
    cpu.copyIn(BASE, words(0xf9400020)); // ldr x0, [x1]
    cpu.writeRegister("x1", 0x50000n);
    const result = cpu.run(BASE, END, 20);
    assert.equal(result.reason, "fault");
    assert.match(result.diagnostic ?? "", /memory fault/);
    assert.throws(() => cpu.map(BASE, 4096n, 3), /overlaps/);
    assert.throws(() => cpu.map(BASE + 1n, 4096n, 3), /aligned/);
    assert.throws(() => cpu.copyOut(0x50000n, 1), /outside/);
    assert.throws(() => cpu.copyOut(BASE, 1024 * 1024 + 1), /bounded/);
    cpu.close();
    cpu.close();
    assert.throws(() => cpu.readRegister("x0"), /closed/);
  } finally { cpu.close(); }
});
