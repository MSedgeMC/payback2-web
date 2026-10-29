import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { GuestHeap } from "../../src/runtime/heap.ts";

test("guest heap aligns allocations, preserves live blocks, and reuses coalesced frees", async () => {
  const cpu = await createRuntime(), heap = new GuestHeap(cpu);
  try {
    const first = heap.allocate(17n), second = heap.allocate(16n), third = heap.allocate(16n);
    assert.equal(first % 16n, 0n); assert.equal(second - first, 32n); assert.equal(third - second, 16n);
    cpu.copyIn(third, new Uint8Array([1, 2, 3, 4]));
    heap.free(first); heap.free(second);
    assert.equal(heap.allocate(48n), first);
    assert.deepEqual(cpu.copyOut(third, 4), new Uint8Array([1, 2, 3, 4]));
    assert.throws(() => heap.free(first + 1n), /active/);
    heap.free(first); assert.throws(() => heap.free(first), /active/);
    heap.free(0n);
    const empty = heap.allocate(0n); assert.notEqual(empty, 0n); assert.equal(empty % 16n, 0n);
  } finally { heap.dispose(); heap.dispose(); assert.equal(cpu.regions.length, 0); cpu.close(); }
  assert.throws(() => heap.allocate(16n), /disposed/);
});

test("zeroed allocation clears reused data and stays within one owned mapping", async () => {
  const cpu = await createRuntime(), heap = new GuestHeap(cpu);
  try {
    const address = heap.allocate(70_000n);
    cpu.copyIn(address, new Uint8Array(70_000).fill(0x99)); heap.free(address);
    assert.equal(heap.allocate(70_000n, true), address);
    assert.deepEqual(cpu.copyOut(address, 70_000), new Uint8Array(70_000));
    assert.ok(cpu.regions.some(region => address >= region.address && address + 70_000n <= region.address + region.size));
    assert.equal(heap.allocate(64n * 1024n * 1024n + 1n), 0n);
    assert.equal(heap.allocate(1n << 128n), 0n);
    assert.throws(() => heap.allocate(-1n), /Negative/);
  } finally { heap.dispose(); cpu.close(); }
});

test("aggregate heap exhaustion fails cleanly and freed capacity remains reusable", async () => {
  const cpu = await createRuntime(), heap = new GuestHeap(cpu);
  try {
    const size = 32n * 1024n * 1024n;
    const first = heap.allocate(size), second = heap.allocate(size);
    assert.notEqual(first, 0n); assert.notEqual(second, 0n); assert.notEqual(first, second);
    assert.equal(heap.allocate(16n), 0n);
    heap.free(first); assert.equal(heap.allocate(size), first);
  } finally { heap.dispose(); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("tiny allocations cannot grow heap metadata without a bound", async () => {
  const cpu = await createRuntime(), heap = new GuestHeap(cpu);
  try {
    const first = heap.allocate(1n);
    for (let index = 1; index < 65_536; index++) assert.notEqual(heap.allocate(1n), 0n);
    assert.equal(heap.allocate(1n), 0n);
    heap.free(first); assert.equal(heap.allocate(1n), first);
  } finally { heap.dispose(); cpu.close(); }
});
