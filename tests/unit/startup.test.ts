import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { parseElf } from "../../src/runtime/elf.ts";
import { probeGameStartup } from "../../src/runtime/startup.ts";
import { syntheticElf } from "../fixtures/elf.ts";
import { words } from "../fixtures/aarch64.ts";

function fixtures(refused = false) {
  const core = parseElf(syntheticElf()), engine = parseElf(syntheticElf());
  core.needed = []; core.symbols[2]!.name = "ExecuteProgram";
  core.bytes.set(words(0x91001c00, 0xd65f03c0), 0x300);
  core.symbols.push({ ...core.symbols[2]!, name: "JNI_OnLoad", address: 0x340n, size: 12n });
  core.bytes.set(refused ? words(0x12800000, 0xd65f03c0) : words(0x528000c0, 0x72a00020, 0xd65f03c0), 0x340);
  engine.needed = ["libpairipcore.so"]; engine.symbols[1]!.name = "ExecuteProgram";
  engine.relocations[0]!.addend = 0n;
  const offset = 0x22b0 - 0x308;
  const loadAddress = 0x10000010 | ((offset & 3) << 29) | ((offset >>> 2) << 5);
  engine.bytes.set(words(0xa9bf7bfd, 0x52800460, loadAddress, 0xf9400210, 0xd63f0200, 0xa8c17bfd, 0xd65f03c0), 0x300);
  return { core, engine };
}

test("game startup retains a dependency through JNI and genuine linked engine constructors", async () => {
  const cpu = await createRuntime();
  try {
    const { core, engine } = fixtures(), result = probeGameStartup(cpu, engine, core);
    assert.equal(result.stage, "engine-constructors"); assert.equal(result.result.status, "initializers-returned");
    assert.equal(result.dependencyInitializers?.completedInitializers, 2);
    assert.equal(result.dependencyJni?.registers.x0, 0x10006n);
    assert.equal(result.result.registers.x0, 42n);
    assert.equal(cpu.regions.length, 0);
  } finally { cpu.close(); }
});

test("a refused JNI load cannot advance to engine constructors and still releases resources", async () => {
  const cpu = await createRuntime();
  try {
    const { core, engine } = fixtures(true);
    assert.throws(() => probeGameStartup(cpu, engine, core), /JNI_OnLoad returned an unsupported version: -1/);
    assert.equal(cpu.regions.length, 0);
  } finally { cpu.close(); }
});
