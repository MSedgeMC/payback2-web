import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { readDouble, writeDouble } from "../../src/runtime/aarch64-fp.ts";
import { libmHandler } from "../../src/runtime/libm.ts";

test("libm handlers follow the AArch64 floating-point calling convention", async () => {
  const cpu = await createRuntime();
  try {
    const apply = (name: string, ...args: number[]): number => {
      const handler = libmHandler(name); assert.ok(handler, `${name} is missing`);
      args.forEach((value, index) => writeDouble(cpu, index, value));
      writeDouble(cpu, 3, 42);
      handler(cpu);
      assert.equal(readDouble(cpu, 3), 42, `${name} clobbered an unrelated argument register`);
      return readDouble(cpu, 0);
    };
    assert.equal(apply("fmod", 7.5, 2), 1.5); assert.equal(apply("fmod", -7.5, 2), -1.5);
    assert.equal(apply("sqrt", 81), 9); assert.equal(apply("floor", -1.5), -2);
    assert.equal(apply("ceil", -1.5), -1); assert.equal(apply("trunc", -1.5), -1);
    assert.equal(apply("round", 2.5), 3); assert.equal(apply("round", -2.5), -3);
    assert.equal(apply("pow", 2, 10), 1024); assert.equal(apply("atan2", 0, 1), 0);
    assert.ok(Number.isNaN(apply("fmax", Number.NaN, 3)) === false && apply("fmax", Number.NaN, 3) === 3);
    assert.equal(apply("fmin", 4, Number.NaN), 4);
    assert.ok(Number.isNaN(apply("fdim", Number.NaN, 1)));
    assert.equal(apply("fdim", 5, 3), 2); assert.equal(apply("fdim", 1, 3), 0);
    assert.ok(Object.is(apply("copysign", 5, -0), -5)); assert.ok(Object.is(apply("copysign", -5, 0), 5));
    assert.equal(libmHandler("lgamma"), undefined);
  } finally { cpu.close(); }
});

test("floating-point helpers preserve the untouched halves of a vector register", async () => {
  const cpu = await createRuntime();
  try {
    const original = new Uint8Array(16).fill(0x5a); cpu.writeVector(0, original);
    writeDouble(cpu, 0, 1.5);
    const afterDouble = cpu.readVector(0);
    assert.deepEqual([...afterDouble.subarray(8)], [...original.subarray(8)]);
    assert.equal(readDouble(cpu, 0), 1.5);
    cpu.writeVector(1, original); writeDouble(cpu, 1, -0);
    assert.ok(Object.is(readDouble(cpu, 1), -0));
    assert.deepEqual([...cpu.readVector(1).subarray(8)], [...original.subarray(8)]);
  } finally { cpu.close(); }
});
