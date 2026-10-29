import assert from "node:assert/strict";
import { test } from "node:test";
import { readDex, readDexClass } from "../../src/runtime/dex.ts";
import { syntheticDex, syntheticManagedDex } from "../fixtures/dex.ts";

test("DEX declarations preserve method signatures and static/native access flags", () => {
  assert.deepEqual(readDexClass(syntheticDex(), "example/Runner"), {
    name: "example/Runner", methods: [
      { name: "execute", descriptor: "([B)Ljava/lang/Object;", isStatic: true, isNative: true },
      { name: "instance", descriptor: "([B)Ljava/lang/Object;", isStatic: false, isNative: true },
    ],
  });
  assert.throws(() => readDexClass(syntheticDex(), "example/Missing"), /missing/);
});

test("DEX managed code retains registers, source instructions, member references, and catch ranges", () => {
  const bytes = syntheticManagedDex(), view = new DataView(bytes.buffer);
  view.setUint16(406, 1, true); view.setUint32(420, 0, true); view.setUint16(424, 1, true); view.setUint16(426, 1, true);
  bytes.set([1, 1, 2, 1], 428);
  const dex = readDex(bytes), clazz = dex.readClass("example/Runner");
  assert.equal(clazz.superclass, "java/lang/Object"); assert.equal(dex.readClass("example/Runner"), clazz);
  assert.deepEqual(clazz.methods[0]!.code, { registers: 2, inputs: 1, outputs: 2, instructions: new Uint16Array([0x1007, 0x0011]),
    tries: [{ start: 0, length: 1, catches: [{ className: "java/lang/Object", target: 1 }] }] });
  assert.deepEqual(dex.method(0), { className: "example/Runner", name: "execute", descriptor: "([B)Ljava/lang/Object;" });
  assert.equal(dex.type(1), "[B"); assert.equal(dex.string(3), "execute");
  for (const change of [
    (data: Uint8Array) => { new DataView(data.buffer).setUint16(402, 3, true); },
    (data: Uint8Array) => { new DataView(data.buffer).setUint32(412, 4097, true); },
    (data: Uint8Array) => { new DataView(data.buffer).setUint16(406, 33, true); },
    (data: Uint8Array) => { new DataView(data.buffer).setUint32(420, 2, true); },
    (data: Uint8Array) => { data[426] = 2; },
    (data: Uint8Array) => { data[431] = 2; },
    (data: Uint8Array) => { data[428] = 0; },
  ]) { const copy = bytes.slice(); change(copy); assert.throws(() => readDex(copy).readClass("example/Runner"), /DEX/); }
});

test("DEX static field values preserve signed constants without executable substitutes", () => {
  const bytes = syntheticDex(), view = new DataView(bytes.buffer);
  for (let index = 0; index < 5; index++) view.setUint32(320 + index * 4, view.getUint32(112 + index * 4, true), true);
  view.setUint32(56, 6, true); view.setUint32(60, 320, true); view.setUint32(340, 368, true); bytes.set([1, 73, 0], 368);
  view.setUint32(64, 4, true); view.setUint32(68, 352, true);
  [0, 1, 2, 5].forEach((value, index) => view.setUint32(352 + index * 4, value, true));
  view.setUint32(80, 1, true); view.setUint32(84, 380, true); view.setUint16(382, 3, true); view.setUint32(384, 4, true);
  bytes.set([1, 0, 1, 1, 0, 8, 0, 0x89, 2, 0, 1, 0x81, 2, 0], 216);
  view.setUint32(200, 396, true); bytes.set([1, 0x24, 0, 255], 396);
  const dex = readDex(bytes);
  assert.deepEqual(dex.field(0), { className: "example/Runner", name: "instance", descriptor: "I" });
  assert.deepEqual(dex.readClass("example/Runner").fields, [{ ...dex.field(0), isStatic: true, value: -256 }]);
  bytes[396] = 2; assert.throws(() => readDex(bytes).readClass("example/Runner"), /static values/);
});

test("DEX strings decode modified UTF-8 with exact UTF-16 length", () => {
  const bytes = syntheticDex(), offset = new DataView(bytes.buffer).getUint32(128, true);
  bytes.set([5, 97, 0xc0, 0x80, 0xce, 0xb2, 0xed, 0xa0, 0xbe, 0xed, 0xb6, 0x84, 0], offset);
  assert.equal(readDex(bytes).string(4), "a\0β🦄");
  bytes[offset] = 4; assert.throws(() => readDex(bytes).string(4), /length mismatch/);
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
