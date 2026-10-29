import assert from "node:assert/strict";
import { test } from "node:test";
import { SUPPORTED_GAME, verifyEngine, verifyPairip, verifyStartupBytecode } from "../../src/assets/baseline.ts";

test("engine identity rejects both truncated files and same-size incompatible binaries", async () => {
  await assert.rejects(verifyEngine(new Uint8Array(16)), /size/);
  await assert.rejects(verifyEngine(new Uint8Array(SUPPORTED_GAME.engineBytes)), /hash/);
});

test("native dependency identity rejects incomplete and same-size incompatible files", async () => {
  await assert.rejects(verifyPairip(new Uint8Array(16)), /size/);
  await assert.rejects(verifyPairip(new Uint8Array(SUPPORTED_GAME.pairipBytes)), /hash/);
});

test("startup bytecode identity rejects incomplete and same-size incompatible declarations", async () => {
  await assert.rejects(verifyStartupBytecode(new Uint8Array(16)), /size/);
  await assert.rejects(verifyStartupBytecode(new Uint8Array(SUPPORTED_GAME.startupDexBytes)), /hash/);
});
