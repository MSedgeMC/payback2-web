import type { RuntimeAdapter } from "./adapter.ts";
import type { ElfSymbol } from "./elf.ts";
import { writeGuestBytes } from "./guest-memory.ts";
import type { NativeImports } from "./symbols.ts";

const version = 0x00010006;
const supportedVersions = new Set([0x00010001, 0x00010002, 0x00010004, version]);
const methodNames: Record<number, string> = { 4: "GetVersion", 6: "FindClass" };
const symbol = (name: string, library: string): ElfSymbol => ({ name, type: 2, binding: 1, visibility: 0,
  section: 0, address: 0n, size: 0n, version: { name: "JNI", library } });

export class JniEnvironment {
  readonly vmAddress = 0x72000000n;
  readonly environmentAddress = this.vmAddress + 8n;
  private readonly cpu: RuntimeAdapter;
  private readonly threadPointer: bigint;
  private mapped = false;
  private disposed = false;

  constructor(cpu: RuntimeAdapter, imports: NativeImports) {
    this.cpu = cpu; this.threadPointer = cpu.readRegister("tpidr_el0");
    try {
      cpu.map(this.vmAddress, 4096n, 3); this.mapped = true;
      const bytes = new Uint8Array(4096), view = new DataView(bytes.buffer);
      const vmTable = this.vmAddress + 256n, environmentTable = this.vmAddress + 512n;
      view.setBigUint64(0, vmTable, true); view.setBigUint64(8, environmentTable, true);
      const vmMethods = ["DestroyJavaVM", "AttachCurrentThread", "DetachCurrentThread", "GetEnv", "AttachCurrentThreadAsDaemon"];
      for (const [index, name] of vmMethods.entries()) {
        const entry = symbol(`JavaVM.${name}`, "JavaVM");
        const address = name === "GetEnv" ? imports.bind(entry, () => this.getEnvironment()) : imports.resolve(entry);
        view.setBigUint64(256 + (index + 3) * 8, address, true);
      }
      // JNI 1.6 has 233 slots, including four reserved pointers; unknown methods retain distinct traps.
      for (let index = 4; index < 233; index++) {
        const entry = symbol(`JNI.${methodNames[index] ?? `slot_${index}`}`, "JNIEnv");
        const address = index === 4 ? imports.bind(entry, () => {
          this.assertEnvironment(); cpu.writeRegister("x0", BigInt(version));
        }) : imports.resolve(entry);
        view.setBigUint64(512 + index * 8, address, true);
      }
      cpu.copyIn(this.vmAddress, bytes); cpu.protect(this.vmAddress, 4096n, 1);
    } catch (error) { this.dispose(); throw error; }
  }

  private assertEnvironment(): void {
    if (this.disposed || this.cpu.readRegister("x0") !== this.environmentAddress ||
        this.cpu.readRegister("tpidr_el0") !== this.threadPointer) throw new Error("Foreign or detached JNIEnv");
  }

  private getEnvironment(): void {
    if (this.disposed || this.cpu.readRegister("x0") !== this.vmAddress) throw new Error("Foreign JavaVM");
    const requestedVersion = Number(BigInt.asUintN(32, this.cpu.readRegister("x2")));
    const result = !supportedVersions.has(requestedVersion) ? -3
      : this.cpu.readRegister("tpidr_el0") !== this.threadPointer ? -2 : 0;
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, result === 0 ? this.environmentAddress : 0n, true);
    writeGuestBytes(this.cpu, this.cpu.readRegister("x1"), bytes);
    this.cpu.writeRegister("x0", BigInt(result));
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.mapped) this.cpu.unmap(this.vmAddress, 4096n);
  }
}
