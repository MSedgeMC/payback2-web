import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { exposeRuntimeHeap, fetchPinnedFile } from "../../tools/prepare_runtime.mjs";

const bytes = new Uint8Array([1, 2, 3, 4]);
const expected = { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
const url = "https://example.invalid/runtime";

test("runtime heap export tracks memory growth and rejects a changed factory", () => {
  const source = `function create() {
    let HEAPU8 = new Uint8Array(2);
    const Module = { grow() { HEAPU8 = new Uint8Array(4); } }, moduleRtn = Module;
    return moduleRtn;
  }`;
  const module = new Function(exposeRuntimeHeap(source) + ";return create();")();
  const first = module.HEAPU8;
  assert.equal(first.byteLength, 2);
  module.grow();
  assert.equal(module.HEAPU8.byteLength, 4);
  assert.notEqual(module.HEAPU8, first);
  assert.throws(() => exposeRuntimeHeap(source.replace("return moduleRtn", "return Module")), /shape/);
  assert.throws(() => exposeRuntimeHeap(source + source), /shape/);
});

test("pinned runtime download accepts a bounded, verified stream", async context => {
  context.mock.method(globalThis, "fetch", async (_url, options) => {
    assert.equal(_url, url);
    assert.ok(options.signal instanceof AbortSignal);
    return new Response(new ReadableStream({ start(controller) {
      controller.enqueue(bytes.subarray(0, 2)); controller.enqueue(bytes.subarray(2)); controller.close();
    } }));
  });
  assert.deepEqual(await fetchPinnedFile(url, expected), bytes);
});

test("pinned runtime download rejects corrupt, truncated, oversized, and failed responses", async context => {
  for (const response of [new Response(new Uint8Array([4, 3, 2, 1])), new Response(bytes.subarray(0, 3)),
                         new Response(new Uint8Array(5)), new Response(bytes, { headers: { "content-length": "5" } }),
                         new Response("missing", { status: 404 })]) {
    const mock = context.mock.method(globalThis, "fetch", async () => response);
    await assert.rejects(fetchPinnedFile(url, expected), /download/);
    mock.mock.restore();
  }
  context.mock.method(globalThis, "fetch", async () => { throw new DOMException("timeout", "TimeoutError"); });
  await assert.rejects(fetchPinnedFile(url, expected), { name: "TimeoutError" });
});

test("an oversized stream is cancelled without reading the remaining chunks", async context => {
  let reads = 0, cancelled = false;
  context.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream({
    pull(controller) { reads++; controller.enqueue(new Uint8Array(5)); },
    cancel() { cancelled = true; },
  }, { highWaterMark: 0 })));
  await assert.rejects(fetchPinnedFile(url, expected), /byte limit/);
  assert.equal(reads, 1);
  assert.equal(cancelled, true);
  await assert.rejects(fetchPinnedFile(url, { ...expected, bytes: 9 * 1024 * 1024 }), /bounds/);
  assert.equal(reads, 1);
});
