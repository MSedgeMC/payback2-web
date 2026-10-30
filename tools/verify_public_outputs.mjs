import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstat, readFile, readdir } from "node:fs/promises";
import { resolve, relative, sep } from "node:path";
import { wasmPayloads } from "./runtime_payload.mjs";

const root = resolve(import.meta.dirname, "..");
const mode = process.argv[2] ?? "source";
const sourceRoots = new Set([".gitignore", "README.md", "LICENSE", "THIRD_PARTY_NOTICES", "package.json",
  "package-lock.json", "runtime.lock.json", "tsconfig.json", "vite.config.ts", "playwright.config.ts", "index.html"]);
const sourcePatterns = [
  /^src\/[a-zA-Z0-9_./-]+\.(?:ts|css)$/,
  /^tools\/[a-zA-Z0-9_.-]+\.(?:py|mjs|ts)$/,
  /^tests\/[a-zA-Z0-9_./-]+\.(?:ts|py|mjs)$/,
  /^public\/licenses\/(?:GPL-2\.0|ZIP-JS)\.txt$/,
  /^\.github\/workflows\/[a-zA-Z0-9_-]+\.yml$/,
  /^docs\/PERFORMANCE\.md$/, // measured runtime throughput quoted by the readme
];
const distPatterns = [/^index\.html$/, /^assets\/[a-zA-Z0-9_.-]+\.(?:js|css)$/,
                      /^licenses\/(?:GPL-2\.0|ZIP-JS)\.txt$/];
const runtimeFiles = new Set(["unicorn-aarch64.cjs", "runtime-build.json", "GPL-2.0.txt"]);
const tokenPattern = /\b(?:gh[pousr]_|github_pat_|sk-proj-)[A-Za-z0-9_]{20,}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/;
const runtimeLock = JSON.parse(await readFile(resolve(root, "runtime.lock.json"), "utf8"));

async function files(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) output.push(...await files(path));
    else output.push(path);
  }
  return output;
}

let paths;
const base = mode === "dist" ? resolve(root, "dist") : mode === "runtime" ? resolve(root, ".local/runtime-build") : root;
let runtimeManifest;
if (mode === "runtime") {
  const manifestPath = resolve(base, "runtime-build.json");
  const info = await lstat(manifestPath);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 16 * 1024) throw new Error("Invalid public runtime manifest");
  runtimeManifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const manifestKeys = new Set(["sourceRevision", "unicornRevision", "emscriptenVersion", "variant", "builderSha256",
    "buildType", "cFlags", "linkFlags", "workers", "fileSha256", "fileBytes", "purpose", "wasmSha256", "wasmBytes", "checks"]);
  if (Object.keys(runtimeManifest).some(key => !manifestKeys.has(key))) throw new Error("Unapproved public runtime metadata");
  const builderSha256 = createHash("sha256").update(await readFile(resolve(root, "tools/build_runtime.py"))).digest("hex");
  if (runtimeManifest.sourceRevision !== runtimeLock.sourceRevision || runtimeManifest.unicornRevision !== runtimeLock.build.unicornRevision ||
      runtimeManifest.emscriptenVersion !== runtimeLock.build.emscriptenVersion || runtimeManifest.builderSha256 !== builderSha256 ||
      runtimeManifest.variant !== "aarch64" || !/^[a-f0-9]{64}$/.test(runtimeManifest.fileSha256) || !/^[a-f0-9]{64}$/.test(runtimeManifest.wasmSha256)) {
    throw new Error("Public runtime build provenance mismatch");
  }
}
if (mode === "source") {
  paths = [...new Set(execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean))].map(path => resolve(root, path));
} else if (mode === "dist" || mode === "runtime") paths = await files(base);
else throw new Error("Expected source, dist, or runtime mode");

let total = 0, wasmCount = 0;
for (const path of paths) {
  const name = relative(base, path).split(sep).join("/");
  const allowed = mode === "source" ? sourceRoots.has(name) || sourcePatterns.some(pattern => pattern.test(name))
    : mode === "runtime" ? runtimeFiles.has(name) : distPatterns.some(pattern => pattern.test(name));
  if (!allowed || name.split("/").some(part => part === "..")) throw new Error(`Public allowlist rejected ${name}`);
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Public output must be a regular file: ${name}`);
  if (info.size > (mode === "source" ? 512 * 1024 : mode === "runtime" ? 8 * 1024 * 1024 : 5 * 1024 * 1024)) throw new Error(`Public file size limit exceeded: ${name}`);
  total += info.size;
  const bytes = await readFile(path);
  if (bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) || bytes.subarray(0, 2).equals(Buffer.from("PK")) ||
      bytes.includes(0) && !(mode === "dist" && name.endsWith(".js") || mode === "runtime" && name === "unicorn-aarch64.cjs")) {
    throw new Error(`Binary/archive data is forbidden in ${name}`);
  }
  const text = bytes.toString("utf8");
  if (tokenPattern.test(text)) throw new Error(`Credential-like content found in ${name}`);
  if (mode === "runtime" && name === "unicorn-aarch64.cjs") {
    const payloads = wasmPayloads(text);
    if (createHash("sha256").update(bytes).digest("hex") !== runtimeManifest.fileSha256 || payloads.length !== 1 ||
        createHash("sha256").update(payloads[0]).digest("hex") !== runtimeManifest.wasmSha256 || !WebAssembly.validate(payloads[0])) {
      throw new Error("Public runtime output differs from its verified build");
    }
    wasmCount += payloads.length;
  }
  if (mode === "runtime" && name === "GPL-2.0.txt" && !bytes.equals(await readFile(resolve(root, "LICENSE")))) {
    throw new Error("Public runtime license differs from GPL-2.0");
  }
  if (mode === "source" && /\b(?:from\s+|import\s*(?:\(\s*)?|require\s*\(\s*)["'][^"'\n]*\/\.local\//.test(text)) {
    throw new Error(`Private working data referenced by public source: ${name}`);
  }
  if (mode === "dist" && name.endsWith(".js")) {
    for (const wasm of wasmPayloads(text)) {
      if (createHash("sha256").update(wasm).digest("hex") !== runtimeLock.wasmSha256) throw new Error(`Unapproved embedded binary in ${name}`);
      wasmCount++;
    }
  }
}
if (mode === "dist" && wasmCount !== 1) throw new Error(`Expected exactly one verified ARM64 WASM payload, found ${wasmCount}`);
if (mode === "runtime" && (paths.length !== runtimeFiles.size || wasmCount !== 1)) throw new Error("Incomplete public runtime outputs");
if (total > (mode === "source" ? 4 * 1024 * 1024 : 10 * 1024 * 1024)) throw new Error("Public output size budget exceeded");
console.log(`Public ${mode} allowlist passed: ${paths.length} files, ${total} bytes`);
