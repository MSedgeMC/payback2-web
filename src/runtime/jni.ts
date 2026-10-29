import type { RuntimeAdapter } from "./adapter.ts";
import type { ElfSymbol } from "./elf.ts";
import { readCString, writeGuestBytes } from "./guest-memory.ts";
import type { NativeImports } from "./symbols.ts";

const version = 0x00010006;
const supportedVersions = new Set([0x00010001, 0x00010002, 0x00010004, version]);
export function isSupportedJniVersion(value: number): boolean { return supportedVersions.has(value); }
const methodNames: Record<number, string> = { 4: "GetVersion", 6: "FindClass", 21: "NewGlobalRef", 22: "DeleteGlobalRef", 23: "DeleteLocalRef", 33: "GetMethodID" };
type JavaMethod = { className: string; name: string; descriptor: string };
// shortcut: observed standard Java methods only; extend definitions when native callers require them.
const classMethods: Record<string, readonly string[]> = {
  "java/lang/Float": ["<init>(F)V", "floatValue()F"],
  "java/lang/Double": ["<init>(D)V", "doubleValue()D"],
  "java/lang/Long": ["<init>(J)V", "longValue()J"],
  "java/lang/Integer": ["<init>(I)V", "intValue()I"],
};
const symbol = (name: string, library: string): ElfSymbol => ({ name, type: 2, binding: 1, visibility: 0,
  section: 0, address: 0n, size: 0n, version: { name: "JNI", library } });

export class JniEnvironment {
  readonly vmAddress = 0x72000000n;
  readonly environmentAddress = this.vmAddress + 8n;
  private readonly cpu: RuntimeAdapter;
  private readonly threadPointer: bigint;
  private readonly references = new Map<bigint, { name: string; global: boolean }>();
  private readonly methods = new Map<bigint, JavaMethod>();
  private nextReference = 0x73000000n;
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
      const handlers: Record<number, () => void | boolean> = {
        4: () => { this.assertEnvironment(); cpu.writeRegister("x0", BigInt(version)); },
        6: () => this.findClass(),
        21: () => this.retainGlobalReference(),
        22: () => this.deleteReference(true),
        23: () => this.deleteReference(false),
        33: () => this.getMethod(),
      };
      // JNI 1.6 has 233 slots, including four reserved pointers; unknown methods retain distinct traps.
      for (let index = 4; index < 233; index++) {
        const entry = symbol(`JNI.${methodNames[index] ?? `slot_${index}`}`, "JNIEnv");
        const handler = handlers[index];
        const address = handler ? imports.bind(entry, handler) : imports.resolve(entry);
        view.setBigUint64(512 + index * 8, address, true);
      }
      cpu.copyIn(this.vmAddress, bytes); cpu.protect(this.vmAddress, 4096n, 1);
    } catch (error) { this.dispose(); throw error; }
  }

  private findClass(): boolean {
    this.assertEnvironment();
    const name = new TextDecoder("utf-8", { fatal: true }).decode(readCString(this.cpu, this.cpu.readRegister("x1"), 256));
    if (!Object.hasOwn(classMethods, name)) return false;
    this.cpu.writeRegister("x0", this.addReference(name, false));
    return true;
  }

  private getMethod(): boolean {
    this.assertEnvironment();
    const entry = this.references.get(this.cpu.readRegister("x1"));
    if (!entry) throw new RangeError("Invalid JNI class reference");
    const decode = (index: number): string => new TextDecoder("utf-8", { fatal: true })
      .decode(readCString(this.cpu, this.cpu.readRegister(`x${index}`), 256));
    const name = decode(2), descriptor = decode(3);
    if (!classMethods[entry.name]?.includes(name + descriptor)) return false;
    let address = [...this.methods].find(([, method]) => method.className === entry.name && method.name === name && method.descriptor === descriptor)?.[0];
    if (address === undefined) {
      if (this.methods.size >= 256) throw new RangeError("JNI method identifier limit exceeded");
      address = 0x74000000n + BigInt(this.methods.size * 8);
      this.methods.set(address, { className: entry.name, name, descriptor });
    }
    this.cpu.writeRegister("x0", address); return true;
  }

  private addReference(name: string, global: boolean): bigint {
    if (this.references.size >= 256) throw new RangeError("JNI class reference limit exceeded");
    const reference = this.nextReference; this.nextReference += 8n;
    this.references.set(reference, { name, global });
    return reference;
  }

  private retainGlobalReference(): void {
    this.assertEnvironment();
    const reference = this.cpu.readRegister("x1");
    if (reference === 0n) { this.cpu.writeRegister("x0", 0n); return; }
    const entry = this.references.get(reference);
    if (!entry) throw new RangeError("Invalid JNI class reference");
    this.cpu.writeRegister("x0", this.addReference(entry.name, true));
  }

  private deleteReference(global: boolean): void {
    this.assertEnvironment();
    const reference = this.cpu.readRegister("x1");
    if (reference === 0n) return;
    const entry = this.references.get(reference);
    if (!entry || entry.global !== global) throw new RangeError("Invalid JNI reference or lifetime");
    this.references.delete(reference);
  }

  private assertEnvironment(): void {
    if (this.disposed || this.cpu.readRegister("x0") !== this.environmentAddress ||
        this.cpu.readRegister("tpidr_el0") !== this.threadPointer) throw new Error("Foreign or detached JNIEnv");
  }

  private getEnvironment(): void {
    if (this.disposed || this.cpu.readRegister("x0") !== this.vmAddress) throw new Error("Foreign JavaVM");
    const requestedVersion = Number(BigInt.asUintN(32, this.cpu.readRegister("x2")));
    const result = !isSupportedJniVersion(requestedVersion) ? -3
      : this.cpu.readRegister("tpidr_el0") !== this.threadPointer ? -2 : 0;
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, result === 0 ? this.environmentAddress : 0n, true);
    writeGuestBytes(this.cpu, this.cpu.readRegister("x1"), bytes);
    this.cpu.writeRegister("x0", BigInt(result));
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.references.clear();
    this.methods.clear();
    if (this.mapped) this.cpu.unmap(this.vmAddress, 4096n);
  }
}
