import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { readCString, writeGuestBytes } from "../../src/runtime/guest-memory.ts";

const BASE = 0x20000n;

test("guest strings terminate at a page edge and can cross adjacent readable mappings", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 3);
    cpu.copyIn(BASE + 4093n, new Uint8Array([97, 98, 0]));
    assert.deepEqual(readCString(cpu, BASE + 4093n, 128), new Uint8Array([97, 98]));
    cpu.map(BASE + 4096n, 4096n, 1);
    cpu.copyIn(BASE + 4095n, new Uint8Array([99]));
    cpu.copyIn(BASE + 4096n, new Uint8Array([100, 0]));
    assert.deepEqual(readCString(cpu, BASE + 4093n, 128), new Uint8Array([97, 98, 99, 100]));
  } finally { cpu.close(); }
});

test("unterminated, unreadable, and unmapped guest strings fail within their bounds", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 3);
    cpu.copyIn(BASE + 4093n, new Uint8Array([97, 98, 99]));
    assert.throws(() => readCString(cpu, BASE + 4093n, 3), /unterminated/);
    assert.throws(() => readCString(cpu, BASE + 4093n, 128), /readable/);
    assert.throws(() => readCString(cpu, BASE, 0), /byte limit/);
    cpu.protect(BASE, 4096n, 2);
    assert.throws(() => readCString(cpu, BASE, 128), /readable/);
  } finally { cpu.close(); }
});

test("native writes respect guest permissions and fail without changing protected bytes", async () => {
  const cpu = await createRuntime();
  try {
    cpu.map(BASE, 4096n, 3);
    writeGuestBytes(cpu, BASE, new Uint8Array([42]));
    cpu.protect(BASE, 4096n, 1);
    assert.throws(() => writeGuestBytes(cpu, BASE, new Uint8Array([0])), /writable/);
    assert.equal(cpu.copyOut(BASE, 1)[0], 42);
    assert.throws(() => writeGuestBytes(cpu, BASE + 4096n, new Uint8Array([0])), /writable/);
  } finally { cpu.close(); }
});
