// Decodes one bounded byte range with the hand-written AArch64 decoder and writes a
// single JSON document to stdout, so tools/verify_decoder.py can diff it against Capstone.
//
// The range is addressed by guest virtual address; for the vendored libpairipcore.so the
// first PT_LOAD maps vaddr 0 at file offset 0, so below 0x79420 a virtual address is also
// the file offset. That identity is assumed here and is the only situation this tool is
// meant to be pointed at.
//
// Usage: node tools/dump_decode.ts <file> [start] [length] [--max instructions]
//   start/length accept decimal or 0x-hex; --max caps the number of words decoded.
// Only the requested slice is read. Nothing but the JSON document goes to stdout.

import { existsSync, readFileSync } from "node:fs";
import { decode, UnsupportedInstruction } from "../src/runtime/translate/arm64.ts";

const MAX_RANGE_BYTES = 0x10000;
const USAGE = "usage: node tools/dump_decode.ts <file> [start] [length] [--max instructions]";

function die(message: string): never {
  console.error(`dump_decode: ${message}`);
  process.exit(2);
}

function parseInteger(text: string, label: string): number {
  const trimmed = text.trim();
  if (!/^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/.test(trimmed)) die(`${label} must be decimal or 0x-hex, got ${JSON.stringify(text)}`);
  const value = trimmed.slice(0, 2).toLowerCase() === "0x" ? Number.parseInt(trimmed.slice(2), 16) : Number.parseInt(trimmed, 10);
  if (!Number.isSafeInteger(value)) die(`${label} is out of range: ${text}`);
  return value;
}

function readBytes(file: string): Buffer {
  if (!existsSync(file)) die(`cannot read ${file}: no such file`);
  try { return readFileSync(file); }
  catch (error) { die(`cannot read ${file}: ${(error as Error).message}`); }
}

const argv = process.argv.slice(2), positional: string[] = [];
let max = Number.MAX_SAFE_INTEGER;
for (let index = 0; index < argv.length; index++) {
  const argument = argv[index]!;
  if (argument === "--max") {
    const value = argv[++index];
    if (value === undefined) die(`--max needs a value\n${USAGE}`);
    max = parseInteger(value, "--max");
  } else if (argument.startsWith("--max=")) {
    max = parseInteger(argument.slice("--max=".length), "--max");
  } else if (argument === "-h" || argument === "--help") {
    console.error(USAGE);
    process.exit(0);
  } else if (argument.startsWith("-") && argument !== "-") {
    die(`unknown option ${argument}\n${USAGE}`);
  } else {
    positional.push(argument);
  }
}

const file = positional[0];
if (file === undefined) die(USAGE);
if (positional.length > 3) die(`too many arguments: ${positional.slice(3).join(" ")}\n${USAGE}`);
const start = parseInteger(positional[1] ?? "0x47c00", "start");
const length = parseInteger(positional[2] ?? "0x400", "length");
if (start % 4 !== 0) die(`start 0x${start.toString(16)} is not a multiple of 4`);
if (length <= 0 || length % 4 !== 0) die(`length ${length} must be a positive multiple of 4`);
if (length > MAX_RANGE_BYTES) die(`length ${length} exceeds the ${MAX_RANGE_BYTES}-byte safety cap`);
if (max < 0) die("--max must not be negative");

const bytes = readBytes(file);
if (start + length > bytes.length) die(`range 0x${start.toString(16)}+0x${length.toString(16)} exceeds ${file} (${bytes.length} bytes)`);

const decoded: Record<string, unknown>[] = [];
let unsupported = 0;
for (let offset = 0; offset < length && offset / 4 < max; offset += 4) {
  const address = start + offset;                      // vaddr == file offset for this binary
  const word = bytes.readUInt32LE(address);
  try {
    decoded.push({ address, word, ...decode(address, word) });
  } catch (error) {
    if (!(error instanceof UnsupportedInstruction)) throw error;
    unsupported++;
    decoded.push({ address, word, kind: "unsupported" });
  }
}

const json = JSON.stringify({ file, start, length, decoded }, (_key, value) => typeof value === "bigint" ? `0x${value.toString(16)}` : value);
process.stdout.write(`${json}\n`);
const cap = max === Number.MAX_SAFE_INTEGER ? "" : `, capped at ${max}`;
console.error(`dump_decode: ${decoded.length} instruction(s) at 0x${start.toString(16)} from ${file}, ${unsupported} unsupported${cap}`);
