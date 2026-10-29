import type { RuntimeAdapter } from "./adapter.ts";
import type { ElfSymbol } from "./elf.ts";
import type { JavaClass } from "./dex.ts";
import { readCString, readGuestBytes, writeGuestBytes } from "./guest-memory.ts";
import { decodeModifiedUtf8, MAX_MODIFIED_UTF8_BYTES } from "./modified-utf8.ts";
import type { NativeImports } from "./symbols.ts";

const version = 0x00010006;
const supportedVersions = new Set([0x00010001, 0x00010002, 0x00010004, version]);
export function isSupportedJniVersion(value: number): boolean { return supportedVersions.has(value); }
const methodNames: Record<number, string> = { 4: "GetVersion", 6: "FindClass", 17: "ExceptionClear", 21: "NewGlobalRef", 22: "DeleteGlobalRef", 23: "DeleteLocalRef", 33: "GetMethodID", 113: "GetStaticMethodID", 144: "GetStaticFieldID", 167: "NewStringUTF", 215: "RegisterNatives" };
type JavaMethod = { className: string; name: string; descriptor: string; isStatic: boolean; isNative: boolean };
type JavaValue = { kind: "class"; name: string } | { kind: "string"; value: string };
// shortcut: observed standard Java methods only; extend definitions when native callers require them.
const classMethods: Record<string, readonly string[]> = {
  "java/lang/Object": [],
  "java/lang/Float": ["<init>(F)V", "floatValue()F"],
  "java/lang/Double": ["<init>(D)V", "doubleValue()D"],
  "java/lang/Long": ["<init>(J)V", "longValue()J"],
  "java/lang/Integer": ["<init>(I)V", "intValue()I"],
  "java/lang/Short": ["<init>(S)V", "shortValue()S"],
  "java/lang/Byte": ["<init>(B)V", "byteValue()B"],
  "java/lang/Character": ["<init>(C)V", "charValue()C"],
  "java/lang/Boolean": ["<init>(Z)V", "booleanValue()Z"],
  "android/content/Intent": [
    "<init>(Ljava/lang/String;)V", "setFlags(I)Landroid/content/Intent;", "getFlags()I",
    "putExtra(Ljava/lang/String;I)Landroid/content/Intent;",
    "putExtra(Ljava/lang/String;Ljava/lang/CharSequence;)Landroid/content/Intent;",
    "putExtra(Ljava/lang/String;[B)Landroid/content/Intent;",
    "hasExtra(Ljava/lang/String;)Z",
    "getIntExtra(Ljava/lang/String;I)I",
    "getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
    "getByteArrayExtra(Ljava/lang/String;)[B",
    "getAction()Ljava/lang/String;",
    "setPackage(Ljava/lang/String;)Landroid/content/Intent;",
    "getPackage()Ljava/lang/String;",
    "setData(Landroid/net/Uri;)Landroid/content/Intent;",
    "getData()Landroid/net/Uri;",
  ],
  "android/net/Uri": ["toString()Ljava/lang/String;"],
  "android/content/Context": ["sendBroadcast(Landroid/content/Intent;)V", "startActivity(Landroid/content/Intent;)V"],
};
const staticMethods: Record<string, readonly string[]> = {
  "android/net/Uri": ["parse(Ljava/lang/String;)Landroid/net/Uri;"],
};
const staticFields: Record<string, Readonly<Record<string, bigint | string>>> = {
  "android/content/Intent": { FLAG_ACTIVITY_NEW_TASK: 0x10000000n, ACTION_VIEW: "android.intent.action.VIEW" },
};
const symbol = (name: string, library: string): ElfSymbol => ({ name, type: 2, binding: 1, visibility: 0,
  section: 0, address: 0n, size: 0n, version: { name: "JNI", library } });

export class JniEnvironment {
  readonly vmAddress = 0x72000000n;
  readonly environmentAddress = this.vmAddress + 8n;
  private readonly cpu: RuntimeAdapter;
  private readonly threadPointer: bigint;
  private readonly references = new Map<bigint, JavaValue & { global: boolean }>();
  private readonly methods = new Map<bigint, JavaMethod>();
  private readonly classes = new Map<string, JavaClass>();
  private readonly nativeMethods = new Map<string, bigint>();
  private readonly fields = new Map<bigint, { className: string; name: string; value: bigint | string }>();
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
        // shortcut: supported methods leave no pending exception; add exception state with the first throwing JNI API.
        17: () => this.assertEnvironment(),
        21: () => this.retainGlobalReference(),
        22: () => this.deleteReference(true),
        23: () => this.deleteReference(false),
        33: () => this.getMethod(false),
        113: () => this.getMethod(true),
        144: () => this.getStaticField(),
        167: () => this.newStringUtf(),
        215: () => this.registerNatives(),
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

  defineClass(definition: JavaClass): void {
    if (this.disposed || !/^[A-Za-z_$][\w$]*(?:\/[A-Za-z_$][\w$]*)*$/.test(definition.name) || definition.name.length > 256 ||
        Object.hasOwn(classMethods, definition.name) || this.classes.has(definition.name) || this.classes.size >= 16 || definition.methods.length > 256) {
      throw new Error("Invalid, duplicate, or excessive Java class definition");
    }
    const keys = new Set<string>();
    for (const method of definition.methods) {
      const key = `${method.name}\0${method.descriptor}\0${method.isStatic}`;
      if (!method.name || method.name.length > 256 || method.name.includes("(") || method.descriptor.length > 256 ||
          !method.descriptor.startsWith("(") || typeof method.isStatic !== "boolean" || typeof method.isNative !== "boolean" || keys.has(key)) {
        throw new Error("Invalid or duplicate Java method declaration");
      }
      keys.add(key);
    }
    this.classes.set(definition.name, { name: definition.name, methods: definition.methods.map(method => ({ ...method })) });
  }

  private findClass(): boolean {
    this.assertEnvironment();
    const name = this.argumentString(1);
    if (!Object.hasOwn(classMethods, name) && !this.classes.has(name)) return false;
    this.cpu.writeRegister("x0", this.addReference({ kind: "class", name }, false));
    return true;
  }

  private argumentString(index: number): string {
    return new TextDecoder("utf-8", { fatal: true }).decode(readCString(this.cpu, this.cpu.readRegister(`x${index}`), 256));
  }

  private getMethod(isStatic: boolean): boolean {
    this.assertEnvironment();
    const entry = this.classReference(this.cpu.readRegister("x1"));
    const name = this.argumentString(2), descriptor = this.argumentString(3);
    const definitions = isStatic ? staticMethods : classMethods;
    const builtin = Object.hasOwn(definitions, entry.name) && definitions[entry.name]!.includes(name + descriptor);
    const declared = this.classes.get(entry.name)?.methods.find(method => method.name === name && method.descriptor === descriptor && method.isStatic === isStatic);
    if (name.includes("(") || !descriptor.startsWith("(") || !builtin && !declared) return false;
    let address = [...this.methods].find(([, method]) => method.className === entry.name && method.name === name &&
      method.descriptor === descriptor && method.isStatic === isStatic)?.[0];
    if (address === undefined) {
      if (this.methods.size >= 256) throw new RangeError("JNI method identifier limit exceeded");
      address = 0x74000000n + BigInt(this.methods.size * 8);
      this.methods.set(address, { className: entry.name, name, descriptor, isStatic, isNative: declared?.isNative ?? false });
    }
    this.cpu.writeRegister("x0", address); return true;
  }

  private getStaticField(): boolean {
    this.assertEnvironment();
    const entry = this.classReference(this.cpu.readRegister("x1"));
    const name = this.argumentString(2), descriptor = this.argumentString(3);
    const definitions = Object.hasOwn(staticFields, entry.name) ? staticFields[entry.name] : undefined;
    const value = definitions && Object.hasOwn(definitions, name) ? definitions[name] : undefined;
    if (value === undefined || descriptor !== (typeof value === "bigint" ? "I" : "Ljava/lang/String;")) return false;
    let address = [...this.fields].find(([, field]) => field.className === entry.name && field.name === name)?.[0];
    if (address === undefined) {
      if (this.fields.size >= 256) throw new RangeError("JNI field identifier limit exceeded");
      address = 0x75000000n + BigInt(this.fields.size * 8);
      this.fields.set(address, { className: entry.name, name, value });
    }
    this.cpu.writeRegister("x0", address); return true;
  }

  private classReference(address: bigint): { name: string } {
    const entry = this.references.get(address);
    if (entry?.kind !== "class") throw new RangeError("Invalid JNI class reference");
    return entry;
  }

  private addReference(value: JavaValue, global: boolean): bigint {
    if (this.references.size >= 256) throw new RangeError("JNI reference limit exceeded");
    const reference = this.nextReference; this.nextReference += 8n;
    this.references.set(reference, { ...value, global });
    return reference;
  }

  private newStringUtf(): void {
    this.assertEnvironment();
    const pointer = this.cpu.readRegister("x1");
    if (pointer === 0n) { this.cpu.writeRegister("x0", 0n); return; }
    const value = decodeModifiedUtf8(readCString(this.cpu, pointer, MAX_MODIFIED_UTF8_BYTES));
    this.cpu.writeRegister("x0", this.addReference({ kind: "string", value }, false));
  }

  lookupNative(className: string, name: string, descriptor: string): bigint | undefined {
    return this.nativeMethods.get(`${className}\0${name}\0${descriptor}`);
  }

  private registerNatives(): boolean {
    this.assertEnvironment();
    const entry = this.classReference(this.cpu.readRegister("x1"));
    const count = Number(BigInt.asIntN(32, this.cpu.readRegister("x3"))), table = this.cpu.readRegister("x2");
    if (count < 0 || count > 256) throw new RangeError("JNI native registration count exceeds its limit");
    if (count && table % 8n) throw new RangeError("JNI native registration table is not aligned");
    const bytes = readGuestBytes(this.cpu, table, count * 24), view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const string = (offset: number): string => new TextDecoder("utf-8", { fatal: true }).decode(readCString(this.cpu, view.getBigUint64(offset, true), 256));
    const pending = new Map<string, bigint>();
    for (let index = 0; index < count; index++) {
      const offset = index * 24, name = string(offset), descriptor = string(offset + 8), address = view.getBigUint64(offset + 16, true);
      const declarations = this.classes.get(entry.name)?.methods.filter(method => method.name === name && method.descriptor === descriptor);
      if (declarations?.length !== 1 || !declarations[0]!.isNative) return false;
      if (address % 4n || !this.cpu.regions.some(region => (region.permissions & 4) && address >= region.address && address + 4n <= region.address + region.size)) {
        throw new RangeError("JNI native method is outside executable guest memory");
      }
      pending.set(`${entry.name}\0${name}\0${descriptor}`, address);
    }
    const additions = [...pending.keys()].filter(key => !this.nativeMethods.has(key)).length;
    if (this.nativeMethods.size + additions > 256) throw new RangeError("JNI native method limit exceeded");
    for (const [key, address] of pending) this.nativeMethods.set(key, address);
    this.cpu.writeRegister("x0", 0n); return true;
  }

  private retainGlobalReference(): void {
    this.assertEnvironment();
    const reference = this.cpu.readRegister("x1");
    if (reference === 0n) { this.cpu.writeRegister("x0", 0n); return; }
    const entry = this.references.get(reference);
    if (!entry) throw new RangeError("Invalid JNI reference");
    this.cpu.writeRegister("x0", this.addReference(entry, true));
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
    this.classes.clear();
    this.nativeMethods.clear();
    this.fields.clear();
    if (this.mapped) this.cpu.unmap(this.vmAddress, 4096n);
  }
}
