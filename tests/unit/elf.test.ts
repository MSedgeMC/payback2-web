import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf, loadElf } from "../../src/runtime/elf.ts";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { syntheticElf } from "../fixtures/elf.ts";

test("ELF loading copies segments, zeros BSS, applies RELA, and resolves initializers", async () => {
  const image = parseElf(syntheticElf());
  assert.deepEqual(image.needed, ["libsample.so"]);
  const cpu = await createRuntime();
  try {
    const base = 0x10000000n;
    const loaded = loadElf(cpu, image, base, symbol => {
      assert.equal(symbol.name, "host_sample"); return 0x50000000n;
    });
    const pointer = cpu.copyOut(base + 0x22b0n, 8);
    assert.equal(new DataView(pointer.buffer).getBigUint64(0, true), 0x50000008n);
    assert.deepEqual(cpu.copyOut(base + 0x2300n, 512), new Uint8Array(512));
    assert.deepEqual(loaded.initializers, [base + 0x300n, base + 0x300n]);
    assert.equal(loaded.lookupExport("local"), base + 0x300n);
    cpu.writeRegister("x30", base + 0x400n);
    assert.equal(cpu.run(loaded.initializers[0]!, base + 0x400n, 20).reason, "end");
    loaded.dispose(); assert.equal(cpu.regions.length, 0);
  } finally { cpu.close(); }
});

test("unresolved imports fail before mapping or executing the image", async () => {
  const cpu = await createRuntime();
  try {
    assert.throws(() => loadElf(cpu, parseElf(syntheticElf()), 0x10000n, () => { throw new Error("Unknown host_sample"); }), /Unknown host_sample/);
    assert.equal(cpu.regions.length, 0);
  } finally { cpu.close(); }
});

test("malformed ELF headers, segment overlap, and out-of-bounds ranges are rejected", () => {
  for (const [offset, value] of [[18, 62], [5, 2], [54, 48]] as const) {
    const bytes = syntheticElf(); bytes[offset] = value;
    assert.throws(() => parseElf(bytes));
  }
  const overlap = syntheticElf(); new DataView(overlap.buffer).setBigUint64(64 + 56 + 16, 0x800n, true);
  assert.throws(() => parseElf(overlap), /Overlapping/);
  const excessive = syntheticElf(); new DataView(excessive.buffer).setBigUint64(64 + 32, 0xffffffffffffffffn, true);
  assert.throws(() => parseElf(excessive), /safe file index/);
  assert.throws(() => parseElf(syntheticElf().subarray(0, 80)), /out of bounds/);
});

test("unsupported and duplicate relocations cannot be silently accepted", () => {
  const unsupported = syntheticElf(); new DataView(unsupported.buffer).setBigUint64(0x1188, (1n << 32n) | 9999n, true);
  assert.throws(() => parseElf(unsupported), /Unsupported AArch64 relocation/);
  const duplicate = syntheticElf(); new DataView(duplicate.buffer).setBigUint64(0x1198, 0x22b0n, true);
  assert.throws(() => parseElf(duplicate), /Duplicate relocation/);
  const outside = syntheticElf(); new DataView(outside.buffer).setBigUint64(0x1180, 0x5000n, true);
  assert.throws(() => parseElf(outside), /outside guest/);
});

test("GNU hash tables give a bounded symbol count without section headers", () => {
  const bytes = syntheticElf(), view = new DataView(bytes.buffer);
  view.setBigUint64(0x1000 + 5 * 16, 0x6ffffef5n, true);
  view.setUint32(0x12c0, 1, true); view.setUint32(0x12c4, 1, true);
  view.setUint32(0x12c8, 1, true); view.setUint32(0x12cc, 0, true);
  view.setBigUint64(0x12d0, 0n, true); view.setUint32(0x12d8, 1, true);
  view.setUint32(0x12dc, 2, true); view.setUint32(0x12e0, 3, true);
  assert.equal(parseElf(bytes).symbols.length, 3);
  view.setUint32(0x12d8, 65536, true);
  assert.throws(() => parseElf(bytes), /GNU hash bucket/);
});
