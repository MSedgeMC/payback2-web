import { createRuntime } from "../src/runtime/unicorn.ts";
import { translate, PC_OFFSET } from "../src/runtime/translate/translate.ts";

// Runs one small guest function under both engines with a shared data image and prints both
// register files, so a disagreement can be read directly.
const hex = process.argv[2];
if (!hex) throw new Error("Pass the function's machine code as hex");
const bytes = new Uint8Array(hex.match(/../g)!.map(byte => parseInt(byte, 16)));
// Code and data live away from the register file, which occupies the lowest bytes.
const CODE = 0x8000, DATA = 0x10000, SENTINEL = 0x2000, span = 0x20000;
const value = BigInt(process.argv[3] ?? 0);

const segment = new Uint8Array(span), view = new DataView(segment.buffer);
segment.set(bytes, CODE);
view.setUint32(DATA + 0x198, Number(value), true);
view.setBigUint64(DATA + 0x8, 0x1111n, true);
view.setBigUint64(DATA + 0x10, BigInt(DATA + 0x300), true);

const cpu = await createRuntime();
const registers: bigint[] = [];
try {
  cpu.map(0n, BigInt(span), 7);
  for (let offset = 0; offset < span; offset += 0x100000) cpu.copyIn(BigInt(offset), segment.subarray(offset, Math.min(offset + 0x100000, span)));
  cpu.writeRegister("x0", BigInt(DATA)); cpu.writeRegister("x30", BigInt(SENTINEL)); cpu.writeRegister("nzcv", 0n);
  const result = cpu.run(BigInt(CODE), BigInt(SENTINEL), 1000);
  for (let index = 0; index <= 30; index++) registers.push(cpu.readRegister(`x${index}` as `x${number}`));
  console.log("interpreter:", result.reason, registers.map((value, index) => value ? `x${index}=0x${value.toString(16)}` : "").filter(Boolean).join(" "), `nzcv=0x${cpu.readRegister("nzcv").toString(16)}`);
} finally { cpu.close(); }

const shared = new WebAssembly.Memory({ initial: Math.ceil(span / 65536) });
const translation = translate(segment, CODE, CODE + bytes.length, Math.ceil(span / 65536), true);
console.log(`blocks=${translation.blocks} unsupported=${JSON.stringify(translation.unsupported)}`);
const instance = new WebAssembly.Instance(translation.module, { env: { memory: shared } });
const memory = new DataView(shared.buffer);
new Uint8Array(shared.buffer, 0, span).set(segment);
memory.setBigUint64(0, BigInt(DATA), true);
memory.setBigUint64(PC_OFFSET, BigInt(CODE), true);
(instance.exports.run as () => void)();
const out: string[] = [];
for (let index = 0; index <= 30; index++) { const value = memory.getBigUint64(index * 8, true); if (value) out.push(`x${index}=0x${value.toString(16)}`); }
console.log("translated: ", out.join(" "), `nzcv=0x${memory.getBigUint64(32 * 8, true).toString(16)}`,
  `pc=0x${memory.getBigUint64(PC_OFFSET, true).toString(16)}`);
