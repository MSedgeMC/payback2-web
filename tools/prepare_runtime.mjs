import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { wasmPayloads } from "./runtime_payload.mjs";

const root = resolve(import.meta.dirname, "..");
const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");

export function exposeRuntimeHeap(source) {
  const marker = "    return moduleRtn;";
  if (source.split(marker).length !== 2) throw new Error("Pinned runtime factory shape changed");
  return source.replace(marker, '    Object.defineProperty(Module, "HEAPU8", { get: () => HEAPU8 });\n' + marker);
}

export async function fetchPinnedFile(url, expected) {
  if (!Number.isSafeInteger(expected.bytes) || expected.bytes < 1 || expected.bytes > 8 * 1024 * 1024 ||
      !/^[a-f0-9]{64}$/.test(expected.sha256)) throw new RangeError("Invalid pinned download bounds");
  const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  const reader = response.body?.getReader();
  try {
    if (!response.ok || !reader) throw new Error(`Runtime download failed: HTTP ${response.status}`);
    const length = response.headers.get("content-length");
    if (length !== null && Number(length) !== expected.bytes) throw new Error("Runtime download size mismatch");
    const bytes = new Uint8Array(expected.bytes);
    let offset = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > bytes.byteLength - offset) throw new Error("Runtime download exceeds its byte limit");
      bytes.set(value, offset); offset += value.byteLength;
    }
    if (offset !== expected.bytes || sha256(bytes) !== expected.sha256) throw new Error("Runtime download hash or size mismatch");
    return bytes;
  } finally {
    await reader?.cancel().catch(() => {});
    reader?.releaseLock();
  }
}

async function prepareRuntime() {
  const lock = JSON.parse(await readFile(resolve(root, "runtime.lock.json"), "utf8"));
  const directory = resolve(root, ".cache/runtime");
  const inputs = resolve(directory, "downloads");
  await mkdir(inputs, { recursive: true });
  async function pinnedFile(name, expected) {
    const path = resolve(inputs, name);
    try {
      const info = await lstat(path);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error("Runtime cache must use regular files");
      if (info.size === expected.bytes) {
        const bytes = await readFile(path);
        if (sha256(bytes) === expected.sha256) return bytes;
      }
    } catch (error) { if (error.code !== "ENOENT") throw error; }
    const bytes = await fetchPinnedFile(`${lock.release.url}/${name}`, expected);
    await writeFile(path, bytes);
    return bytes;
  }
  const metadata = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await pinnedFile("runtime-build.json",
    { bytes: lock.release.manifestBytes, sha256: lock.release.manifestSha256 })));
  if (metadata.sourceRevision !== lock.sourceRevision || metadata.unicornRevision !== lock.build.unicornRevision ||
      metadata.emscriptenVersion !== lock.build.emscriptenVersion || metadata.builderSha256 !== lock.release.builderSha256 ||
      metadata.variant !== lock.variant || metadata.fileBytes !== lock.fileBytes || metadata.fileSha256 !== lock.fileSha256 ||
      metadata.wasmBytes !== lock.wasmBytes || metadata.wasmSha256 !== lock.wasmSha256 ||
      !metadata.checks.integer || !metadata.checks.simd || !metadata.checks.longBlock ||
      metadata.checks.pressure.some(check => check.status !== "passed")) throw new Error("Pinned runtime build provenance mismatch");
  const bytes = await pinnedFile("unicorn-aarch64.cjs", { bytes: lock.fileBytes, sha256: lock.fileSha256 });
  const derived = exposeRuntimeHeap(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  const wasm = wasmPayloads(derived);
  if (wasm.length !== 1 || wasm[0].byteLength !== lock.wasmBytes || sha256(wasm[0]) !== lock.wasmSha256 ||
      !WebAssembly.validate(wasm[0])) throw new Error("Embedded WASM differs from the pinned runtime");
  await writeFile(resolve(directory, "unicorn-aarch64.cjs"), derived);
  await writeFile(resolve(directory, "manifest.json"), JSON.stringify({ ...metadata,
    adapterTransform: lock.adapterTransform, outputSha256: sha256(derived) }, null, 2) + "\n");
  const licenses = resolve(root, "public/licenses");
  await mkdir(licenses, { recursive: true });
  await writeFile(resolve(licenses, "GPL-2.0.txt"), await readFile(resolve(root, "LICENSE")));
  await writeFile(resolve(licenses, "ZIP-JS.txt"), await readFile(resolve(root, "node_modules/@zip.js/zip.js/LICENSE")));
  console.log(`Prepared verified ${lock.variant} WASM runtime (${bytes.byteLength} bytes, Emscripten ${metadata.emscriptenVersion})`);
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) await prepareRuntime();
