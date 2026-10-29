import assert from "node:assert/strict";
import { test } from "node:test";
import { BoundedZip, readPackageEngine, readPackageLibraries, readPackageBytecode, validateEntryName } from "../../src/assets/importer.ts";
import { SUPPORTED_GAME } from "../../src/assets/baseline.ts";
import { syntheticZip } from "../fixtures/zip.ts";
import { syntheticDex } from "../fixtures/dex.ts";

test("ZIP reader lazily extracts only selected stored and deflated entries", async () => {
  const data = new TextEncoder().encode("synthetic archive fixture".repeat(100));
  for (const deflate of [false, true]) {
    const archive = await BoundedZip.open(syntheticZip([{ name: "assets/sample", bytes: data, deflate }]));
    try {
      assert.deepEqual(await archive.bytes("assets/sample", data.byteLength), data);
      await assert.rejects(archive.bytes("assets/sample", 10), /expanded-size/);
      await assert.rejects(archive.bytes("missing", 10), /missing/);
    } finally { await archive.close(); }
    await assert.rejects(archive.bytes("assets/sample", data.byteLength), /closed/);
  }
});

test("package import extracts both native libraries without selecting unrelated entries", async () => {
  const engine = new Uint8Array([1, 2, 3]), pairip = new Uint8Array([4, 5, 6]);
  const split = syntheticZip([
    { name: "lib/arm64-v8a/libpayback2.so", bytes: engine },
    { name: "lib/arm64-v8a/libpairipcore.so", bytes: pairip, deflate: true },
    { name: "assets/unused", bytes: new Uint8Array(1024), deflate: true },
  ]);
  const packageFile = syntheticZip([
    { name: "info.json", bytes: new TextEncoder().encode(JSON.stringify({ pname: SUPPORTED_GAME.package,
      release_version: SUPPORTED_GAME.version, versioncode: SUPPORTED_GAME.versionCode })) },
    { name: "split_config.arm64_v8a.apk", bytes: new Uint8Array(await split.arrayBuffer()), deflate: true },
  ]);
  for (const file of [new File([split], "split.apk"), new File([packageFile], "game.apkm")]) {
    assert.deepEqual(await readPackageLibraries(file), { engine, pairip });
  }
  const incomplete = syntheticZip([{ name: "lib/arm64-v8a/libpayback2.so", bytes: engine }]);
  await assert.rejects(readPackageLibraries(new File([incomplete], "incomplete.apk")), /libpairipcore.*missing/);
});

test("unsafe names, duplicate paths, and malformed directories are rejected", async () => {
  for (const path of ["../secret", "/absolute", "a/../b", "a//b", "a\\b", "a/./b", "C:drive", "a\0b"]) {
    assert.throws(() => validateEntryName(path), /Unsafe/);
  }
  await assert.rejects(BoundedZip.open(syntheticZip([{ name: "a", bytes: new Uint8Array() }, { name: "a", bytes: new Uint8Array() }])), /Duplicate/);
  const malformed = new Uint8Array(await syntheticZip([]).arrayBuffer());
  new DataView(malformed.buffer).setUint32(12, 0x1000000, true);
  await assert.rejects(BoundedZip.open(new Blob([malformed])), /directory/);
});

test("expanded-size forgery and bad CRC cannot produce silently accepted bytes", async () => {
  const bytes = new Uint8Array(await syntheticZip([{ name: "a", bytes: new Uint8Array(1024), deflate: true }]).arrayBuffer());
  const view = new DataView(bytes.buffer);
  let directory = -1;
  for (let offset = 0; offset < bytes.byteLength - 4; offset++) if (view.getUint32(offset, true) === 0x02014b50) { directory = offset; break; }
  assert.ok(directory > 0);
  view.setUint32(directory + 24, 1, true);
  const archive = await BoundedZip.open(new Blob([bytes]));
  try { await assert.rejects(archive.bytes("a", 1024)); }
  finally { await archive.close(); }
  const corrupt = new Uint8Array(await syntheticZip([{ name: "b", bytes: new Uint8Array([1, 2, 3]) }]).arrayBuffer());
  corrupt[31] = 9; // Change the stored payload, keeping the recorded CRC unchanged.
  const invalidCrc = await BoundedZip.open(new Blob([corrupt]));
  try { await assert.rejects(invalidCrc.bytes("b", 3)); }
  finally { await invalidCrc.close(); }
});

test("package version and missing ARM64 split fail before engine execution", async () => {
  const blob = syntheticZip([{ name: "info.json", bytes: new TextEncoder().encode(JSON.stringify({ pname: "other.package" })) }]);
  await assert.rejects(readPackageEngine(new File([blob], "sample.apkm")), /Unsupported APKM/);
  await assert.rejects(readPackageEngine(new File([syntheticZip([])], "base.apk")), /missing/);
  await assert.rejects(readPackageEngine(new File([new Uint8Array(12)], "engine.so")), /size/);
});

test("startup metadata reads the selected DEX from a bounded local base APK", async () => {
  const bytes = syntheticDex();
  const base = syntheticZip([{ name: SUPPORTED_GAME.startupDexName, bytes, deflate: true }]);
  const info = new TextEncoder().encode(JSON.stringify({ pname: SUPPORTED_GAME.package,
    release_version: SUPPORTED_GAME.version, versioncode: SUPPORTED_GAME.versionCode }));
  const packageFile = syntheticZip([
    { name: "info.json", bytes: info },
    { name: "base.apk", bytes: new Uint8Array(await base.arrayBuffer()), deflate: true },
  ]);
  assert.deepEqual(await readPackageBytecode(new File([packageFile], "game.apkm")), bytes);
  assert.equal(await readPackageBytecode(new File([base], "base.apk")), undefined);
  const missing = syntheticZip([{ name: "info.json", bytes: info }]);
  await assert.rejects(readPackageBytecode(new File([missing], "missing.apkm")), /base.apk.*missing/);
});
