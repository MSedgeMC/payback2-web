// Differential test: every case executes the same AArch64 instruction stream twice,
// once under the Unicorn interpreter and once under the ahead-of-time WASM translator,
// then compares the final architectural state register by register.
//
// Guest layout (identical for both engines):
//   0x0000..0x0fff  code      (the translated range starts at 0)
//   0x1000..0x1fff  data      (within the translator's default one-page memory)
//   0x8000          sentinel  (placed in x30; both engines stop when pc reaches it)
//
// Instructions come from the subset handled by src/runtime/translate/arm64.ts. If the
// translator reports an instruction outside that subset, the case is skipped with the
// offending address/word so the gap stays visible instead of silently passing.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { translate, PC_OFFSET } from "../../src/runtime/translate/translate.ts";
import type { TranslationResult } from "../../src/runtime/translate/translate.ts";
import type { Register } from "../../src/runtime/adapter.ts";
import { words } from "../fixtures/aarch64.ts";

const CODE_BASE = 0n;
const CODE_SIZE = 4096n;
const DATA_BASE = 0x1000n;
const DATA_SIZE = 4096n;
const END = 0x8000n;
const DEFAULT_INSTRUCTION_LIMIT = 10_000;

// Documented register-file layout of the translated module's linear memory.
const STACK_POINTER_BYTE_OFFSET = 248;
const FLAGS_BYTE_OFFSET = 256;

const RET = 0xd65f03c0;

const REGISTER_NAMES: readonly Register[] = Array.from(
  { length: 31 },
  (_, index) => `x${index}` as Register,
);

type DifferentialCase = {
  /** Unique name; also used as the test name so failures identify the case. */
  readonly name: string;
  /** Instruction words, placed at CODE_BASE. */
  readonly code: Uint8Array;
  /** Byte offset inside `code` where execution starts; defaults to 0. */
  readonly entry?: number;
  /** Values for x0..x30; unlisted registers start at zero. Do not seed x30 (it holds END). */
  readonly seeds?: Readonly<Record<number, bigint>>;
  /** Optional initial contents of the data page. */
  readonly data?: Uint8Array;
  /** Interpreter instruction budget; enough for the case but small enough to fail fast. */
  readonly instructionLimit?: number;
};

type Snapshot = { readonly registers: readonly bigint[]; readonly pc: bigint };

const format = (value: bigint): string => `0x${value.toString(16).padStart(16, "0")}`;

function dataWord(value: bigint): Uint8Array {
  const bytes = new Uint8Array(16);
  new DataView(bytes.buffer).setBigUint64(0, value, true);
  return bytes;
}

/** Runs one case under the Unicorn interpreter and returns its final register state. */
async function runInterpreter(differentialCase: DifferentialCase): Promise<Snapshot> {
  const cpu = await createRuntime();
  let codeMapped = false, dataMapped = false;
  try {
    cpu.map(CODE_BASE, CODE_SIZE, 5);
    codeMapped = true;
    cpu.map(DATA_BASE, DATA_SIZE, 3);
    dataMapped = true;
    cpu.copyIn(CODE_BASE, differentialCase.code);
    if (differentialCase.data) cpu.copyIn(DATA_BASE, differentialCase.data);
    for (let index = 0; index < REGISTER_NAMES.length; index++) {
      cpu.writeRegister(REGISTER_NAMES[index]!, differentialCase.seeds?.[index] ?? 0n);
    }
    cpu.writeRegister("x30", END);
    cpu.writeRegister("nzcv", 0n);
    const entry = CODE_BASE + BigInt(differentialCase.entry ?? 0);
    const result = cpu.run(entry, END, differentialCase.instructionLimit ?? DEFAULT_INSTRUCTION_LIMIT);
    assert.equal(
      result.reason,
      "end",
      `${differentialCase.name}: interpreter stopped with reason "${result.reason}" instead of reaching x30 (${format(END)}); pc=${format(result.pc)}${result.diagnostic ? `; diagnostic: ${result.diagnostic}` : ""}`,
    );
    return {
      registers: REGISTER_NAMES.map(register => cpu.readRegister(register)),
      pc: cpu.readRegister("pc"),
    };
  } finally {
    if (dataMapped) cpu.unmap(DATA_BASE, DATA_SIZE);
    if (codeMapped) cpu.unmap(CODE_BASE, CODE_SIZE);
    assert.equal(cpu.regions.length, 0);
    cpu.close();
  }
}

/** Runs the same case through the translated module and reads its register file back. */
function runTranslated(differentialCase: DifferentialCase, translation: TranslationResult): Snapshot {
  const instance = new WebAssembly.Instance(translation.module, {});
  assert.equal(typeof instance.exports.run, "function", `${differentialCase.name}: translated module must export run`);
  assert.ok(instance.exports.memory instanceof WebAssembly.Memory, `${differentialCase.name}: translated module must export its linear memory`);
  const memory = instance.exports.memory;
  const view = new DataView(memory.buffer);
  for (let index = 0; index < REGISTER_NAMES.length; index++) {
    view.setBigUint64(index * 8, differentialCase.seeds?.[index] ?? 0n, true);
  }
  view.setBigUint64(30 * 8, END, true);
  view.setBigUint64(STACK_POINTER_BYTE_OFFSET, 0n, true);
  view.setBigUint64(FLAGS_BYTE_OFFSET, 0n, true);
  view.setBigUint64(PC_OFFSET, BigInt(translation.entry + (differentialCase.entry ?? 0)), true);
  if (differentialCase.data) new Uint8Array(memory.buffer).set(differentialCase.data, Number(DATA_BASE));
  try {
    (instance.exports.run as () => void)();
  } catch (error) {
    assert.fail(`${differentialCase.name}: translated module trapped: ${error instanceof Error ? error.message : String(error)}`);
  }
  return {
    registers: REGISTER_NAMES.map((_, index) => view.getBigUint64(index * 8, true)),
    pc: view.getBigUint64(PC_OFFSET, true),
  };
}

function compare(caseName: string, expected: Snapshot, actual: Snapshot): void {
  const divergences: string[] = [];
  for (let index = 0; index < REGISTER_NAMES.length; index++) {
    const name = REGISTER_NAMES[index]!;
    if (actual.registers[index] !== expected.registers[index]) {
      divergences.push(`${name}: interpreter ${format(expected.registers[index]!)} translator ${format(actual.registers[index]!)}`);
    }
  }
  if (actual.pc !== expected.pc) divergences.push(`pc: interpreter ${format(expected.pc)} translator ${format(actual.pc)}`);
  assert.deepEqual(divergences, [], `${caseName}: translator diverged from the interpreter:\n  ${divergences.join("\n  ")}`);
}

// ---------------------------------------------------------------------------
// Case table
// ---------------------------------------------------------------------------

// add x1, x1, #1 ; subs x0, x0, #1 ; b.ne -8 ; ret
const COUNTDOWN = words(0x91000421, 0xf1000400, 0x54ffffc1, RET);

// ldr x2, [x1] ; add x2, x2, #1 ; str x2, [x1] ; ldr x4, [x1] ; cmp x4, x2
// b.ne +8 ; b +8 ; movz x2, #0 ; ret  -- a failed round trip lands on the marker.
const MEMORY_ROUND_TRIP = words(
  0xf9400022, 0x91000442, 0xf9000022, 0xf9400024, 0xeb02009f,
  0x54000041, 0x14000002, 0xd2800002, RET,
);

// movz x2, #0x1234 ; str x2, [x1, #8] ; ldr x3, [x1, #8] ; ldr x4, [x1] ; ret
const MEMORY_OFFSET = words(0xd2824682, 0xf9000422, 0xf9400423, 0xf9400024, RET);

// add x2,x0,#0x123 ; sub x3,x0,#1 ; add x4,x0,x1 ; sub x5,x0,x1 ;
// orr x6,x0,x1 ; and x7,x0,x1 ; eor x8,x0,x1 ; add x0,x0,x1 ; sub x1,x1,x0 ; ret
const REGISTER_ARITHMETIC = words(
  0x91048c02, 0xd1000403, 0x8b010004, 0xcb010005,
  0xaa010006, 0x8a010007, 0xca010008, 0x8b010000, 0xcb000021, RET,
);

// sub x2, x0, x1 ; subs x3, x0, x1 ; ret
const SUBTRACT_REGISTERS = words(0xcb010002, 0xeb010003, RET);

// movz x0, #0xdef0 ; movk x0, #0x9abc, lsl #16 ; movk x0, #0x5678, lsl #32 ;
// movk x0, #0x1234, lsl #48 ; ret
const MOVE_WIDE = words(0xd29bde00, 0xf2b37800, 0xf2cacf00, 0xf2e46800, RET);

// movz x1, #0xffff, lsl #16 ; movk x1, #0x1234 ; movk x1, #0x5678, lsl #32 ; ret
const MOVE_KEEP = words(0xd2bfffe1, 0xf2824681, 0xf2cacf01, RET);

type FlagCase = { readonly name: string; readonly code: number; readonly taken: readonly [bigint, bigint]; readonly notTaken: readonly [bigint, bigint] };

// Condition codes follow the decoder's table (eq=0 ... le=13). `cmp x0, x1` is
// `subs xzr, x0, x1`; the branch skips a `b` to the ret on the false path.
const FLAG_CASES: readonly FlagCase[] = [
  { name: "eq", code: 0, taken: [7n, 7n], notTaken: [7n, 8n] },
  { name: "ne", code: 1, taken: [7n, 8n], notTaken: [7n, 7n] },
  { name: "cs", code: 2, taken: [7n, 3n], notTaken: [3n, 7n] },
  { name: "cc", code: 3, taken: [3n, 7n], notTaken: [7n, 3n] },
  { name: "mi", code: 4, taken: [3n, 7n], notTaken: [7n, 3n] },
  { name: "pl", code: 5, taken: [7n, 3n], notTaken: [3n, 7n] },
  { name: "vs", code: 6, taken: [0x8000000000000000n, 1n], notTaken: [7n, 3n] },
  { name: "vc", code: 7, taken: [7n, 3n], notTaken: [0x8000000000000000n, 1n] },
  { name: "hi", code: 8, taken: [7n, 3n], notTaken: [3n, 3n] },
  { name: "ls", code: 9, taken: [3n, 3n], notTaken: [7n, 3n] },
  { name: "ge", code: 10, taken: [7n, 3n], notTaken: [3n, 7n] },
  { name: "lt", code: 11, taken: [3n, 7n], notTaken: [7n, 3n] },
  { name: "gt", code: 12, taken: [7n, 3n], notTaken: [3n, 3n] },
  { name: "le", code: 13, taken: [3n, 3n], notTaken: [7n, 3n] },
];

function flagCase(flag: FlagCase, taken: boolean, operands: readonly [bigint, bigint]): DifferentialCase {
  return {
    name: `b.${flag.name} ${taken ? "taken" : "not taken"} (x0=${format(operands[0])}, x1=${format(operands[1])})`,
    // cmp x0, x1 ; b.<cond> +8 ; b +8 ; movz x2, #1 ; ret
    code: words(0xeb01001f, 0x54000040 | flag.code, 0x14000002, 0xd2800022, RET),
    seeds: { 0: operands[0], 1: operands[1], 2: 0n },
  };
}

function compareZeroCase(name: string, word: number, registerValue: bigint): DifferentialCase {
  return {
    // cbz/cbnz x2, +12 ; movz x3, #2 ; b +8 ; movz x3, #1 ; ret
    name: `cbz/cbnz ${name} (x2=${format(registerValue)})`,
    code: words(word, 0xd2800043, 0x14000002, 0xd2800023, RET),
    seeds: { 2: registerValue, 3: 0n },
  };
}

const CASES: readonly DifferentialCase[] = [
  ...[1, 5, 64].map(count => ({
    name: `countdown loop with ${count} iteration(s)`,
    code: COUNTDOWN,
    seeds: { 0: BigInt(count) },
    instructionLimit: 4 * count + 16,
  })),
  {
    name: "store/load round trip through memory with cmp and a conditional branch",
    code: MEMORY_ROUND_TRIP,
    seeds: { 1: DATA_BASE },
    data: dataWord(0x40n),
  },
  {
    name: "store/load 64-bit with unsigned offsets",
    code: MEMORY_OFFSET,
    seeds: { 1: DATA_BASE },
    data: dataWord(0n),
  },
  ...FLAG_CASES.flatMap(flag => [flagCase(flag, true, flag.taken), flagCase(flag, false, flag.notTaken)]),
  compareZeroCase("cbz taken", 0xb4000062, 0n),
  compareZeroCase("cbz not taken", 0xb4000062, 5n),
  compareZeroCase("cbnz taken", 0xb5000062, 5n),
  compareZeroCase("cbnz not taken", 0xb5000062, 0n),
  {
    // b +8 ; movz x0, #1 ; add x1, x1, #2 ; ret -- starts at the branch target at offset 4.
    name: "nonzero entry offset at a branch-target block",
    code: words(0x14000002, 0xd2800020, 0x91000821, RET),
    entry: 4,
    seeds: { 1: 5n },
  },
  {
    name: "register arithmetic with immediate and shifted-register forms",
    code: REGISTER_ARITHMETIC,
    seeds: { 0: 0x00ff00ff00ff00ffn, 1: 0x0f0f0f0f0f0f0f0fn },
  },
  {
    name: "subtraction without borrow",
    code: SUBTRACT_REGISTERS,
    seeds: { 0: 9n, 1: 4n },
  },
  {
    name: "subtraction that borrows",
    code: SUBTRACT_REGISTERS,
    seeds: { 0: 3n, 1: 5n },
  },
  {
    name: "movz/movk builds a large immediate",
    code: MOVE_WIDE,
    seeds: { 0: 0n },
  },
  {
    name: "movz zeroes a dirty register and movk preserves unrelated bits",
    code: MOVE_KEEP,
    seeds: { 1: 0xaaaaaaaaaaaaaaaan },
  },
];

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

function translateSafely(differentialCase: DifferentialCase): TranslationResult {
  try {
    return translate(differentialCase.code, 0, differentialCase.code.length);
  } catch (error) {
    assert.fail(`${differentialCase.name}: translator threw instead of translating: ${error instanceof Error ? error.message : String(error)}`);
  }
}

for (const differentialCase of CASES) {
  test(`differential: ${differentialCase.name}`, async (t) => {
    const translation = translateSafely(differentialCase);
    if (translation.unsupported.length > 0) {
      const sites = translation.unsupported
        .map(site => `0x${site.address.toString(16)} (word 0x${site.word.toString(16).padStart(8, "0")})`)
        .join(", ");
      t.skip(`translator reports unsupported instruction(s) at ${sites}; case not compared`);
      return;
    }
    const expected = await runInterpreter(differentialCase);
    const actual = runTranslated(differentialCase, translation);
    compare(differentialCase.name, expected, actual);
  });
}
