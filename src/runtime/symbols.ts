import type { RuntimeAdapter } from "./adapter.ts";
import type { ElfSymbol } from "./elf.ts";

export type NativeImport = { symbol: ElfSymbol; address: bigint; kind: "function" | "data" };

// Unknown function imports stop at SVC; unknown data remains inaccessible.
// shortcut: native coverage is incremental; essential missing APIs block initialization.
export class NativeImports {
  readonly entries: NativeImport[] = [];
  private readonly cpu: RuntimeAdapter;
  private readonly codeBase: bigint;
  private readonly dataBase: bigint;
  private readonly mappings: { address: bigint; size: bigint }[] = [];
  private readonly byName = new Map<string, NativeImport>();
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
    let entry: NativeImport;
    if (symbol.type === 2) {
      if (this.codeCount >= 256) throw new RangeError("Diagnostic function import budget exceeded");
      const address = this.codeBase + BigInt(this.codeCount++ * 16);
      // svc #1; ret. The owning probe dispatches supported APIs after stopping.
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

  atInterrupt(pc: bigint): NativeImport | undefined {
    return this.entries.find(entry => entry.kind === "function" && entry.address + 4n === pc);
  }

  handleInterrupt(pc: bigint): boolean {
    const symbol = this.atInterrupt(pc)?.symbol;
    if (symbol?.name !== "getauxval" || symbol.version?.library !== "libc.so" || symbol.version.name !== "LIBC") return false;
    const query = this.cpu.readRegister("x0");
    if (query !== 16n && query !== 26n) return false;
    // AT_HWCAP advertises verified FP/NEON; AT_HWCAP2 advertises no extra features.
    this.cpu.writeRegister("x0", query === 16n ? 3n : 0n);
    this.cpu.writeRegister("pc", this.cpu.readRegister("x30"));
    return true;
  }

  dispose(): void {
    for (const mapping of this.mappings.splice(0).reverse()) this.cpu.unmap(mapping.address, mapping.size);
  }
}
