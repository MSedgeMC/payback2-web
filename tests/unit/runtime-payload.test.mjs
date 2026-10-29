import assert from "node:assert/strict";
import { test } from "node:test";
import { wasmPayloads } from "../../tools/runtime_payload.mjs";

// A valid WASM module with one empty-name custom section containing synthetic zeros.
const binary = new Uint8Array(5012);
binary.set([0, 97, 115, 109, 1, 0, 0, 0, 0, 0x89, 0x27, 0]);

test("public-output inspection decodes packed and canonical base64 WASM payloads", () => {
  assert.equal(WebAssembly.validate(binary), true);
  const packed = String.fromCharCode(...binary);
  const encoded = `data:application/octet-stream;base64,${Buffer.from(binary).toString("base64")}`;
  for (const payload of [packed, encoded]) {
    assert.deepEqual(wasmPayloads(`const binary = ${JSON.stringify(payload)};`), [binary]);
  }
});

test("large non-WASM strings and malformed base64 cannot pass public-output inspection", () => {
  for (const payload of ["private".repeat(1000), "data:application/wasm;base64," + "_".repeat(5000),
                         "data:application/wasm;base64," + Buffer.alloc(5000).toString("base64")]) {
    assert.throws(() => wasmPayloads(`const binary = ${JSON.stringify(payload)};`));
  }
});
