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
];
const distPatterns = [/^index\.html$/, /^assets\/[a-zA-Z0-9_.-]+\.(?:js|css)$/,
                      /^licenses\/(?:GPL-2\.0|ZIP-JS)\.txt$/];
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
const base = mode === "dist" ? resolve(root, "dist") : root;
if (mode === "source") {
  paths = [...new Set(execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean))].map(path => resolve(root, path));
} else if (mode === "dist") paths = await files(base);
else throw new Error("Expected source or dist mode");

let total = 0, wasmCount = 0;
for (const path of paths) {
  const name = relative(base, path).split(sep).join("/");
  const allowed = mode === "source" ? sourceRoots.has(name) || sourcePatterns.some(pattern => pattern.test(name)) : distPatterns.some(pattern => pattern.test(name));
  if (!allowed || name.split("/").some(part => part === "..")) throw new Error(`Public allowlist rejected ${name}`);
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Public output must be a regular file: ${name}`);
  if (info.size > (mode === "source" ? 512 * 1024 : 5 * 1024 * 1024)) throw new Error(`Public file size limit exceeded: ${name}`);
  total += info.size;
  const bytes = await readFile(path);
  if (bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) || bytes.subarray(0, 2).equals(Buffer.from("PK")) || bytes.includes(0) && !(mode === "dist" && name.endsWith(".js"))) {
    throw new Error(`Binary/archive data is forbidden in ${name}`);
  }
  const text = bytes.toString("utf8");
  if (tokenPattern.test(text)) throw new Error(`Credential-like content found in ${name}`);
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
if (total > (mode === "source" ? 4 * 1024 * 1024 : 10 * 1024 * 1024)) throw new Error("Public output size budget exceeded");
console.log(`Public ${mode} allowlist passed: ${paths.length} files, ${total} bytes`);
