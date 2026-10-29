import type { RuntimeAdapter } from "./adapter.ts";
import type { ElfSymbol } from "./elf.ts";

export type DiagnosticImport = { symbol: ElfSymbol; address: bigint; kind: "function" | "data" };

// This registry is only for failure localization. Function imports stop at SVC;
// unknown data is inaccessible. It implements no API and never returns success.
// shortcut: initialization is diagnostic; implement native ABI/JNI before gameplay.
export class DiagnosticImports {
  readonly entries: DiagnosticImport[] = [];
  private readonly cpu: RuntimeAdapter;
  private readonly codeBase: bigint;
  private readonly dataBase: bigint;
  private readonly mappings: { address: bigint; size: bigint }[] = [];
  private readonly byName = new Map<string, DiagnosticImport>();
  private codeCount = 0;
  private dataCount = 0;

  constructor(cpu: RuntimeAdapter, codeBase = 0x70000000n, dataBase = 0x71000000n) {
    this.cpu = cpu; this.codeBase = codeBase; this.dataBase = dataBase;
    cpu.map(codeBase, 4096n, 5); this.mappings.push({ address: codeBase, size: 4096n });
  }

  resolve = (symbol: ElfSymbol): bigint => {
    const key = `${symbol.name}\0${symbol.version?.name ?? ""}\0${symbol.version?.library ?? ""}`;
    const existing = this.byName.get(key);
    if (existing) {
      if (existing.symbol.type !== symbol.type) throw new Error("Conflicting import symbol types");
      return existing.address;
    }
    let entry: DiagnosticImport;
    if (symbol.type === 2) {
      if (this.codeCount >= 256) throw new RangeError("Diagnostic function import budget exceeded");
      const address = this.codeBase + BigInt(this.codeCount++ * 16);
      // svc #1; ret. The owning probe stops on the interrupt before executing ret.
      this.cpu.copyIn(address, new Uint8Array([0x21, 0, 0, 0xd4, 0xc0, 3, 0x5f, 0xd6]));
      entry = { symbol, address, kind: "function" };
    } else if (symbol.type === 1) {
      if (this.dataCount >= 32 || symbol.size > 4096n) throw new RangeError("Diagnostic data import budget exceeded");
      const address = this.dataBase + BigInt(this.dataCount++ * 4096);
      this.cpu.map(address, 4096n, 0); this.mappings.push({ address, size: 4096n });
      entry = { symbol, address, kind: "data" };
    } else throw new Error(`Unsupported diagnostic import type ${symbol.type} for ${symbol.name}`);
    this.entries.push(entry); this.byName.set(key, entry);
    return entry.address;
  };

  atInterrupt(pc: bigint): DiagnosticImport | undefined {
    return this.entries.find(entry => entry.kind === "function" && entry.address + 4n === pc);
  }

  dispose(): void {
    for (const mapping of this.mappings.splice(0).reverse()) this.cpu.unmap(mapping.address, mapping.size);
  }
}
