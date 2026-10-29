import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { words } from "../tests/fixtures/aarch64.ts";
import { wasmPayloads } from "./runtime_payload.mjs";

if (process.argv.length !== 3) throw new Error("Pass the compiled runtime output directory");
const directory = resolve(process.argv[2]);
const path = resolve(directory, "unicorn-aarch64.cjs");
const metadataPath = resolve(directory, "runtime-build.json");
const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
const bytes = await readFile(path);
assert.equal(createHash("sha256").update(bytes).digest("hex"), metadata.fileSha256, "Compiled runtime hash mismatch");
const payloads = wasmPayloads(bytes.toString("utf8"));
assert.equal(payloads.length, 1, "Expected one ARM64 WASM payload");
assert.equal(WebAssembly.validate(payloads[0]), true, "Invalid compiled WASM");
const diagnostics = [];
const create = (await import(pathToFileURL(path).href)).default;
const module = await create({ print: () => {}, printErr: message => {
  diagnostics.push(String(message).slice(0, 500));
  if (diagnostics.length > 4) diagnostics.shift();
} });
const BASE = 0x10000n, END = 0x11000n;
const checks = { integer: false, simd: false, pressure: [] };
let failure;

function execute(code, setup, check) {
  const engine = new module.Unicorn(module.ARCH_ARM64, module.MODE_ARM);
  try {
    engine.mem_map(BASE, 4096n, 5); engine.mem_write(BASE, code);
    setup(engine); engine.reg_write_i64(module.ARM64_REG_X30, END);
    engine.emu_start(BASE, END, 0, 1000);
    assert.equal(engine.reg_read_i64(module.ARM64_REG_PC), END, "Guest execution did not return");
    check(engine);
  } finally { engine.close(); module._free(engine.handle_ptr); }
}

try {
  execute(words(0xd2800500, 0x91000800, 0xd65f03c0), () => {}, engine =>
    assert.equal(engine.reg_read_i64(module.ARM64_REG_X0), 42n));
  checks.integer = true;
  execute(words(0x4ea18402, 0xd65f03c0), engine => {
    engine.reg_write(module.ARM64_REG_Q0, new Uint8Array(new Uint32Array([1, 2, 3, 4]).buffer));
    engine.reg_write(module.ARM64_REG_Q1, new Uint8Array(new Uint32Array([5, 6, 7, 8]).buffer));
  }, engine => assert.deepEqual(new Uint32Array(engine.reg_read(module.ARM64_REG_Q2, 16).buffer), new Uint32Array([6, 8, 10, 12])));
  checks.simd = true;
  for (const count of [8, 16, 32, 64, 128]) {
    diagnostics.length = 0;
    const code = Array.from({ length: count }, (_, index) =>
      (0x6ee04400 | (31 << 16) | ((index % 30) << 5) | (index % 30)) >>> 0);
    const sample = { instructions: count, status: "running" };
    checks.pressure.push(sample);
    try {
      execute(words(...code, 0xd65f03c0), engine => {
        for (let index = 0; index < 30; index++) {
          engine.reg_write(module[`ARM64_REG_Q${index}`], new Uint8Array(new BigUint64Array([8n, 16n]).buffer));
        }
        engine.reg_write(module.ARM64_REG_Q31, new Uint8Array(16));
      }, engine => {
        for (let index = 0; index < 30; index++) {
          assert.deepEqual(new BigUint64Array(engine.reg_read(module[`ARM64_REG_Q${index}`], 16).buffer), new BigUint64Array([8n, 16n]));
        }
      });
      sample.status = "passed";
    } catch (error) {
      sample.status = "fault";
      sample.diagnostic = [...diagnostics, String(error)].join("\n").slice(0, 1500);
      throw error;
    }
  }
} catch (error) { failure = error; }
const report = { ...metadata, wasmSha256: createHash("sha256").update(payloads[0]).digest("hex"),
                 wasmBytes: payloads[0].byteLength, checks };
await writeFile(metadataPath, JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify({ checks, wasmBytes: report.wasmBytes }, null, 2));
if (failure) throw failure;
