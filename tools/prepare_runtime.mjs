import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { wasmPayloads } from "./runtime_payload.mjs";

const root = resolve(import.meta.dirname, "..");
const lock = JSON.parse(await readFile(resolve(root, "runtime.lock.json"), "utf8"));
const packageLock = JSON.parse(await readFile(resolve(root, "package-lock.json"), "utf8"));
const dependency = packageLock.packages["node_modules/@alexaltea/unicorn-js"];
if (dependency.version !== lock.version || dependency.integrity !== lock.integrity) {
  throw new Error("Runtime package differs from the reviewed immutable input");
}
const original = await readFile(resolve(root, "node_modules/@alexaltea/unicorn-js/dist/unicorn_aarch64.js"));
const digest = createHash("sha256").update(original).digest("hex");
if (digest !== lock.fileSha256) throw new Error("ARM64 runtime input hash mismatch");
const source = original.toString("utf8");
const wasm = wasmPayloads(source);
if (wasm.length !== 1 || createHash("sha256").update(wasm[0]).digest("hex") !== lock.wasmSha256) {
  throw new Error("Embedded WASM differs from the reviewed runtime");
}
const marker = ";return moduleRtn";
if (source.split(marker).length !== 2) throw new Error("Pinned runtime factory shape changed");
// The published wrapper does not export its heap. A getter keeps measurements
// and future bulk-memory views correct when Emscripten grows the memory.
const derived = source.replace(marker, ';Object.defineProperty(Module,"HEAPU8",{get:()=>HEAPU8});return moduleRtn');
const directory = resolve(root, ".cache/runtime");
await mkdir(directory, { recursive: true });
await writeFile(resolve(directory, "unicorn-aarch64.cjs"), derived);
const manifest = {
  package: lock.package, version: lock.version, variant: lock.variant,
  sourceRevision: lock.sourceRevision, inputSha256: digest,
  outputSha256: createHash("sha256").update(derived).digest("hex"),
  transform: lock.adapterTransform, toolchain: lock.toolchain,
};
await writeFile(resolve(directory, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
const licenses = resolve(root, "public/licenses");
await mkdir(licenses, { recursive: true });
await writeFile(resolve(licenses, "GPL-2.0.txt"), await readFile(resolve(root, "LICENSE")));
await writeFile(resolve(licenses, "ZIP-JS.txt"), await readFile(resolve(root, "node_modules/@zip.js/zip.js/LICENSE")));
console.log(`Prepared verified ${lock.variant} WASM runtime (${original.byteLength} input bytes)`);
