import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeModifiedUtf8, MAX_MODIFIED_UTF8_BYTES } from "../../src/runtime/modified-utf8.ts";

test("modified UTF-8 preserves Java NUL, BMP characters, surrogate pairs, and unpaired UTF-16 units", () => {
  assert.equal(decodeModifiedUtf8(new Uint8Array()), "");
  assert.equal(decodeModifiedUtf8(new TextEncoder().encode("ASCII")), "ASCII");
  const bytes = new Uint8Array([65, 0xc0, 0x80, 0xc2, 0xa2, 0xe2, 0x82, 0xac, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80, 0xed, 0xa0, 0x80]);
  assert.equal(decodeModifiedUtf8(bytes), "A\u0000¢€😀\ud800");
  assert.equal(decodeModifiedUtf8(new Uint8Array(MAX_MODIFIED_UTF8_BYTES).fill(65)).length, MAX_MODIFIED_UTF8_BYTES);
});

test("modified UTF-8 rejects malformed, overlong, ordinary four-byte UTF-8, and excessive inputs", () => {
  for (const bytes of [[0], [0x80], [0xbf], [0xc0], [0xc0, 0x81], [0xc1, 0xbf], [0xc2, 32],
    [0xe0, 0x80, 0x80], [0xe2, 0x82], [0xf0, 0x9f, 0x98, 0x80], [0xff]]) {
    assert.throws(() => decodeModifiedUtf8(new Uint8Array(bytes)), /modified UTF-8/);
  }
  assert.throws(() => decodeModifiedUtf8(new Uint8Array(MAX_MODIFIED_UTF8_BYTES + 1)), /byte limit/);
});
