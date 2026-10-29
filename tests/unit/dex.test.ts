import assert from "node:assert/strict";
import { test } from "node:test";
import { readDexClass } from "../../src/runtime/dex.ts";
import { syntheticDex } from "../fixtures/dex.ts";

test("DEX declarations preserve method signatures and static/native access flags", () => {
  assert.deepEqual(readDexClass(syntheticDex(), "example/Runner"), {
    name: "example/Runner", methods: [
      { name: "execute", descriptor: "([B)Ljava/lang/Object;", isStatic: true, isNative: true },
      { name: "instance", descriptor: "([B)Ljava/lang/Object;", isStatic: false, isNative: true },
    ],
  });
  assert.throws(() => readDexClass(syntheticDex(), "example/Missing"), /missing/);
});

test("DEX identity, table ranges, member indices, and varints fail closed", () => {
  for (const change of [
    (bytes: Uint8Array) => { bytes[0] = 0; },
    (bytes: Uint8Array) => { new DataView(bytes.buffer).setUint32(60, 508, true); },
    (bytes: Uint8Array) => { new DataView(bytes.buffer).setUint32(112, 512, true); },
    (bytes: Uint8Array) => { bytes[220] = 127; },
    (bytes: Uint8Array) => { bytes.fill(255, 216, 221); },
    (bytes: Uint8Array) => { bytes[256] = 1; },
    (bytes: Uint8Array) => { bytes[223] = 96; },
  ]) {
    const bytes = syntheticDex(); change(bytes);
    assert.throws(() => readDexClass(bytes, "example/Runner"), /DEX/);
  }
  assert.throws(() => readDexClass(new Uint8Array(10), "example/Runner"), /DEX/);
  assert.throws(() => readDexClass(syntheticDex(), "../Runner"), /class name/);
});
