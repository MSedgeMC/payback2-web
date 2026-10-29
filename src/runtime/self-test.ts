import type { RuntimeAdapter } from "./adapter.ts";

export function checkRuntime(cpu: RuntimeAdapter): { name: string; wasmMemoryBytes: number } {
  const base = 0x10000n, end = 0x11000n;
  const bytes = (...words: number[]): Uint8Array => {
    const result = new Uint8Array(words.length * 4), view = new DataView(result.buffer);
    words.forEach((word, index) => view.setUint32(index * 4, word, true));
    return result;
  };
  cpu.map(base, 4096n, 5);
  try {
    cpu.writeRegister("x30", end);
    cpu.copyIn(base, bytes(0xd28006e0, 0xd2800441, 0x8b010002, 0xd65f03c0));
    if (cpu.run(base, end, 20).reason !== "end" || cpu.readRegister("x2") !== 0x59n) throw new Error("ARM64 integer execution failed");
    cpu.copyIn(base, bytes(0x4ea18402, 0xd65f03c0));
    cpu.writeVector(0, new Uint8Array(new Uint32Array([1, 2, 3, 4]).buffer));
    cpu.writeVector(1, new Uint8Array(new Uint32Array([5, 6, 7, 8]).buffer));
    if (cpu.run(base, end, 20).reason !== "end") throw new Error("ARM64 SIMD execution failed");
    const lanes = new Uint32Array(cpu.readVector(2).buffer);
    if (lanes.some((value, index) => value !== 6 + index * 2)) throw new Error("ARM64 SIMD results are incorrect");
    cpu.copyIn(base, bytes(0x14000000));
    if (cpu.run(base, end, 1000).reason !== "budget") throw new Error("ARM64 instruction budget failed");
    return { name: cpu.name, wasmMemoryBytes: cpu.wasmMemoryBytes };
  } finally { cpu.unmap(base, 4096n); }
}
