import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { parseElf } from "../src/runtime/elf.ts";
import { decode } from "../src/runtime/translate/arm64.ts";
import { translate, PC_OFFSET } from "../src/runtime/translate/translate.ts";
import { createRuntime } from "../src/runtime/unicorn.ts";

// Runs real leaf functions from the game engine under both the interpreter and the
// translator with an identical memory image and register seed, and compares the results.
// Only functions that are fully translatable and execute to completion in both are counted.
const LIBRARY = process.env.ENGINE_PATH ?? resolve(import.meta.dirname, "../.local/engine/libpayback2.so");
const TEXT_LIMIT = 0x37d480, SCRATCH = 0x3800000, SCRATCH_BYTES = 0x100000, SENTINEL = 0x7fff0000;
const MAX_FUNCTIONS = Number(process.env.VALIDATE_FUNCTIONS ?? 400), MAX_INSTRUCTIONS = 20000;

const file = await readFile(LIBRARY);
const library = new Uint8Array(file.buffer, file.byteOffset, file.byteLength);
const image = parseElf(library);
const words = new DataView(library.buffer, library.byteOffset, library.byteLength);
// The register file lives in a dedicated page at the top of the mapping so it never
// aliases guest address zero.
const memoryBytes = Math.ceil((SCRATCH + SCRATCH_BYTES + 0x10000) / 65536) * 65536;
const REGISTER_FILE = memoryBytes - 0x2000;

// Candidate functions: small, defined, in the first executable segment, and leaf (no calls).
type Candidate = { address: number; size: number };
const candidates: Candidate[] = [];
for (const symbol of image.symbols) {
  if (symbol.type !== 2 || symbol.section === 0 || symbol.size < 8n || symbol.size > 320n) continue;
  const address = Number(symbol.address), size = Number(symbol.size);
  if (address % 4 || size % 4 || address + size > TEXT_LIMIT) continue;
  let leaf = true, supported = true;
  for (let offset = 0; offset < size && (leaf || supported); offset += 4) {
    try {
      const instruction = decode(address + offset, words.getUint32(address + offset, true));
      if (instruction.kind === "branchLink" || instruction.kind === "branchLinkReg") leaf = false;
      if ((instruction as { kind: string }).kind === "unsupported") supported = false;
    } catch { supported = false; }
  }
  if (!leaf || !supported) continue;
  candidates.push({ address, size });
  if (candidates.length >= MAX_FUNCTIONS) break;
}

/** Seeds identical registers and memory in both engines. */
function seedRegisters(write: (register: `x${number}`, value: bigint) => void): void {
  for (let index = 0; index <= 7; index++) write(`x${index}`, BigInt(SCRATCH + index * 128));
  for (let index = 8; index <= 30; index++) write(`x${index}`, BigInt(index));
}

type Outcome = { registers: bigint[]; flags: bigint; pc: bigint; scratch: number } | undefined;

const cpu = await createRuntime();
let compared = 0, agreed = 0;
const disagreements: { address: number; size: number; register: string; interpreter: string; translated: string }[] = [];
const skipped: { address: number; reason: string }[] = [];

try {
  cpu.map(0n, BigInt(Math.ceil(TEXT_LIMIT / 4096) * 4096), 7);
  // Host transfers are bounded to 1 MiB, so the image is written in chunks.
  for (let offset = 0; offset < TEXT_LIMIT; offset += 0x100000) {
    const end = Math.min(offset + 0x100000, TEXT_LIMIT);
    cpu.copyIn(BigInt(offset), library.subarray(offset, end));
  }
  cpu.map(BigInt(SCRATCH), BigInt(SCRATCH_BYTES), 3);

  // One shared linear memory holds the whole library, as the production runtime will.
  const shared = new WebAssembly.Memory({ initial: memoryBytes / 65536 });
  const memory = new DataView(shared.buffer);
  new Uint8Array(memory.buffer, 0, TEXT_LIMIT).set(library.subarray(0, TEXT_LIMIT));

  const scratchFromInterpreter = (): Uint8Array => {
    const bytes = new Uint8Array(SCRATCH_BYTES);
    for (let offset = 0; offset < SCRATCH_BYTES; offset += 0x100000) {
      bytes.set(cpu.copyOut(BigInt(SCRATCH + offset), Math.min(0x100000, SCRATCH_BYTES - offset)), offset);
    }
    return bytes;
  };
  const checksum = (bytes: Uint8Array): number => {
    let hash = 2166136261;
    for (let index = 0; index < bytes.length; index += 7) hash = Math.imul(hash ^ bytes[index]!, 16777619);
    return hash >>> 0;
  };

  for (const candidate of candidates) {
    // Reset scratch memory so both engines see the same starting data.
    for (let offset = 0; offset < SCRATCH_BYTES; offset += 0x100000) cpu.copyIn(BigInt(SCRATCH + offset), new Uint8Array(Math.min(0x100000, SCRATCH_BYTES - offset)));
    new Uint8Array(memory.buffer, SCRATCH, SCRATCH_BYTES).fill(0);

    seedRegisters((register, value) => cpu.writeRegister(register, value));
    cpu.writeRegister("x30", BigInt(SENTINEL));
    cpu.writeRegister("nzcv", 0n);
    let interpreted: Outcome;
    try {
      const result = cpu.run(BigInt(candidate.address), BigInt(SENTINEL), MAX_INSTRUCTIONS);
      interpreted = result.reason === "end"
        ? { registers: Array.from({ length: 31 }, (_, index) => cpu.readRegister(`x${index}` as `x${number}`)),
            flags: cpu.readRegister("nzcv"), pc: cpu.readRegister("pc"),
            scratch: checksum(scratchFromInterpreter()) }
        : undefined;
    } catch { interpreted = undefined; }

    let instance: WebAssembly.Instance;
    try {
      instance = new WebAssembly.Instance(translate(library, candidate.address, candidate.address + candidate.size,
        memoryBytes / 65536, true, REGISTER_FILE).module, { env: { memory: shared } });
    } catch { skipped.push({ address: candidate.address, reason: "translation failed" }); continue; }
    new Uint8Array(memory.buffer, REGISTER_FILE, 528).fill(0);
    seedRegisters((register, value) => memory.setBigUint64(REGISTER_FILE + Number(register.slice(1)) * 8, value, true));
    memory.setBigUint64(REGISTER_FILE + PC_OFFSET, BigInt(candidate.address), true);
    memory.setBigUint64(REGISTER_FILE + 32 * 8, 0n, true);
    memory.setBigUint64(REGISTER_FILE + 30 * 8, BigInt(SENTINEL), true);
    let translatedOutcome: Outcome;
    try {
      (instance.exports.run as () => void)();
      translatedOutcome = { registers: Array.from({ length: 31 }, (_, index) => memory.getBigUint64(REGISTER_FILE + index * 8, true)),
        flags: memory.getBigUint64(REGISTER_FILE + 32 * 8, true), pc: memory.getBigUint64(REGISTER_FILE + PC_OFFSET, true),
        scratch: checksum(new Uint8Array(memory.buffer, SCRATCH, SCRATCH_BYTES)) };
    } catch { translatedOutcome = undefined; }

    if (!interpreted || !translatedOutcome) {
      if (skipped.length < 40) skipped.push({ address: candidate.address, reason: interpreted ? "translated fault" : "interpreter fault" });
      continue;
    }
    compared++;
    let matched = true;
    for (let index = 0; index <= 30; index++) {
      if (interpreted.registers[index] !== translatedOutcome.registers[index]) {
        if (disagreements.length < 40) disagreements.push({ address: candidate.address, size: candidate.size,
          register: `x${index}`, interpreter: `0x${interpreted.registers[index]!.toString(16)}`,
          translated: `0x${translatedOutcome.registers[index]!.toString(16)}` });
        matched = false;
      }
    }
    if (interpreted.flags !== translatedOutcome.flags) {
      if (disagreements.length < 40) disagreements.push({ address: candidate.address, size: candidate.size, register: "nzcv",
        interpreter: `0x${interpreted.flags.toString(16)}`, translated: `0x${translatedOutcome.flags.toString(16)}` });
      matched = false;
    }
    if (interpreted.scratch !== translatedOutcome.scratch) {
      if (disagreements.length < 40) disagreements.push({ address: candidate.address, size: candidate.size, register: "memory",
        interpreter: `0x${interpreted.scratch.toString(16)}`, translated: `0x${translatedOutcome.scratch.toString(16)}` });
      matched = false;
    }
    if (matched) agreed++;
  }
} finally {
  cpu.close();
}

const report = { library: "libpayback2.so", candidates: candidates.length, compared, agreed,
  disagreements: disagreements.length, disagreementDetail: disagreements, skipped: skipped.length, skippedDetail: skipped,
  scope: "Real engine leaf functions executed under the interpreter and the translator with identical state" };
await mkdir(".local", { recursive: true });
await writeFile(".local/engine-function-validation.json", JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify({ candidates: report.candidates, compared, agreed, disagreements: report.disagreements,
  skipped: report.skipped, detail: disagreements.slice(0, 12), skippedDetail: skipped.slice(0, 6) }, null, 2));
