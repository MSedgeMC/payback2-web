import type { RuntimeAdapter } from "./adapter.ts";
import type { ElfSymbol } from "./elf.ts";
import type { DexFile, JavaClass } from "./dex.ts";
import type { BoundedZip } from "../assets/importer.ts";
import { readCString, readGuestBytes, writeGuestBytes } from "./guest-memory.ts";
import { decodeModifiedUtf8, MAX_MODIFIED_UTF8_BYTES } from "./modified-utf8.ts";
import { readVariadicWords } from "./aarch64-varargs.ts";
import type { NativeDispatch, NativeImports } from "./symbols.ts";
import type { JavaDatum, JavaExecution, JavaRequest, JavaValue } from "./java-values.ts";
import { parseJavaMethod } from "./java-descriptors.ts";
import { JavaMachine } from "./java-machine.ts";
import { JavaPlatform } from "./java-platform.ts";

const version = 0x00010006;
const supportedVersions = new Set([0x00010001, 0x00010002, 0x00010004, version]);
export function isSupportedJniVersion(value: number): boolean { return supportedVersions.has(value); }
const methodNames: Record<number, string> = { 4: "GetVersion", 6: "FindClass", 17: "ExceptionClear", 21: "NewGlobalRef", 22: "DeleteGlobalRef", 23: "DeleteLocalRef", 24: "IsSameObject", 29: "NewObjectV", 30: "NewObjectA", 33: "GetMethodID", 35: "CallObjectMethodV", 38: "CallBooleanMethodV", 50: "CallIntMethodV", 53: "CallLongMethodV", 62: "CallVoidMethodV", 113: "GetStaticMethodID", 115: "CallStaticObjectMethodV", 144: "GetStaticFieldID", 167: "NewStringUTF", 171: "GetArrayLength", 172: "NewObjectArray", 173: "GetObjectArrayElement", 174: "SetObjectArrayElement", 200: "GetByteArrayRegion", 215: "RegisterNatives", 228: "ExceptionCheck" };
type JavaMethod = { className: string; name: string; descriptor: string; isStatic: boolean; isNative: boolean };
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
  private readonly imports: NativeImports;
  private readonly threadPointer: bigint;
  private readonly references = new Map<bigint, { value: JavaValue; global: boolean }>();
  private readonly localFrames: Set<bigint>[] = [new Set()];
  private readonly methods = new Map<bigint, JavaMethod>();
  private readonly classes = new Map<string, JavaClass>();
  private readonly nativeMethods = new Map<string, bigint>();
  private readonly fields = new Map<bigint, { className: string; name: string; value: bigint | string }>();
  private nextReference = 0x73000000n;
  private allocatedValueBytes = 0;
  private mapped = false;
  private disposed = false;
  private java: JavaMachine | undefined;

  constructor(cpu: RuntimeAdapter, imports: NativeImports) {
    this.cpu = cpu; this.imports = imports; this.threadPointer = cpu.readRegister("tpidr_el0");
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
      const handlers: Record<number, () => NativeDispatch> = {
        4: () => { this.assertEnvironment(); cpu.writeRegister("x0", BigInt(version)); },
        6: () => this.findClass(),
        // shortcut: supported methods leave no pending exception; add exception state with the first throwing JNI API.
        17: () => this.assertEnvironment(),
        21: () => this.retainGlobalReference(),
        22: () => this.deleteReference(true),
        23: () => this.deleteReference(false),
        24: () => this.isSameObject(),
        29: () => this.newObjectV(),
        30: () => this.newObjectA(),
        33: () => this.getMethod(false),
        113: () => this.getMethod(true),
        35: () => this.callMethodV("object"),
        38: () => this.callMethodV("boolean"),
        50: () => this.callMethodV("int"),
        53: () => this.callMethodV("long"),
        62: () => this.callMethodV("void"),
        115: () => this.callStaticObjectMethodV(),
        144: () => this.getStaticField(),
        167: () => this.newStringUtf(),
        171: () => this.getArrayLength(),
        172: () => this.newObjectArray(),
        173: () => this.getObjectArrayElement(),
        174: () => this.setObjectArrayElement(),
        200: () => this.getByteArrayRegion(),
        215: () => this.registerNatives(),
        228: () => this.exceptionCheck(),
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

  attachBytecode(dex: DexFile, base: BoundedZip | undefined, libraryLoaded: (name: string) => boolean): void {
    if (this.disposed || this.java) throw new Error("JNI bytecode environment is disposed or already attached");
    this.java = new JavaMachine(dex, bytes => this.reserveValueBytes(bytes), machine => new JavaPlatform(machine, base, libraryLoaded));
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
    if (!Object.hasOwn(classMethods, name) && !this.classes.has(name) && !this.java?.hasClass(name)) {
      this.imports.explain(`class ${name}`);
      return false;
    }
    this.cpu.writeRegister("x0", this.addReference(this.java?.classValue(name) ?? { kind: "class", name }, false));
    return true;
  }

  private argumentString(index: number): string {
    return new TextDecoder("utf-8", { fatal: true }).decode(readCString(this.cpu, this.cpu.readRegister(`x${index}`), 256));
  }

  private getMethod(isStatic: boolean): NativeDispatch {
    this.assertEnvironment();
    const entry = this.classReference(this.cpu.readRegister("x1"));
    const name = this.argumentString(2), descriptor = this.argumentString(3);
    const definitions = isStatic ? staticMethods : classMethods;
    const builtin = Object.hasOwn(definitions, entry.name) && definitions[entry.name]!.includes(name + descriptor) ||
      (!isStatic && (this.java?.hasHostMethod(entry.name, name, descriptor) ?? false));
    const definitions_ = this.classes.get(entry.name) ?? this.java?.sourceClass(entry.name);
    const declared = definitions_?.methods.find(method => method.name === name && method.descriptor === descriptor && method.isStatic === isStatic);
    if (name.includes("(") || !descriptor.startsWith("(") || !builtin && !declared) {
      this.imports.explain(`method ${entry.name}.${name}${descriptor}`);
      return false;
    }
    let address = [...this.methods].find(([, method]) => method.className === entry.name && method.name === name &&
      method.descriptor === descriptor && method.isStatic === isStatic)?.[0];
    if (address === undefined) {
      if (this.methods.size >= 256) throw new RangeError("JNI method identifier limit exceeded");
      address = 0x74000000n + BigInt(this.methods.size * 8);
      this.methods.set(address, { className: entry.name, name, descriptor, isStatic, isNative: declared?.isNative ?? false });
    }
    const complete = (): NativeDispatch => { this.cpu.writeRegister("x0", address!); return true; };
    return this.java?.sourceClass(entry.name) ? this.runJava(this.java.initializeClass(entry.name), complete) : complete();
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
    const entry = this.references.get(address)?.value;
    if (entry?.kind !== "class") throw new RangeError("Invalid JNI class reference");
    return entry;
  }

  private arrayReference(address: bigint): Extract<JavaValue, { kind: "object-array" | "byte-array" }> {
    const entry = this.references.get(address)?.value;
    if (entry?.kind !== "object-array" && entry?.kind !== "byte-array") {
      throw new RangeError(`Invalid JNI array reference${entry ? `: ${entry.kind}` : ""}`);
    }
    return entry;
  }

  private addReference(value: JavaValue, global: boolean): bigint {
    if (this.references.size >= 256) throw new RangeError("JNI reference limit exceeded");
    const reference = this.nextReference; this.nextReference += 8n;
    this.references.set(reference, { value, global });
    if (!global) this.localFrames.at(-1)!.add(reference);
    return reference;
  }

  private newStringUtf(): void {
    this.assertEnvironment();
    const pointer = this.cpu.readRegister("x1");
    if (pointer === 0n) { this.cpu.writeRegister("x0", 0n); return; }
    const value = decodeModifiedUtf8(readCString(this.cpu, pointer, MAX_MODIFIED_UTF8_BYTES));
    this.cpu.writeRegister("x0", this.allocateReference({ kind: "string", value }, 64 + value.length * 2));
  }

  private allocateReference(value: JavaValue, bytes: number): bigint {
    this.reserveValueBytes(bytes);
    return this.addReference(value, false);
  }

  private reserveValueBytes(bytes: number): void {
    // shortcut: cumulative 16 MiB startup value budget; reclaim accounting with guest garbage collection.
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new RangeError("Invalid JNI value allocation size");
    if (this.allocatedValueBytes + bytes > 16 * 1024 * 1024) throw new RangeError("JNI value allocation budget exceeded");
    this.allocatedValueBytes += bytes;
  }

  private newObjectArray(): boolean {
    this.assertEnvironment();
    const length = Number(BigInt.asIntN(32, this.cpu.readRegister("x1")));
    if (length < 0 || length > 16384) throw new RangeError("JNI object array length exceeds its limit");
    const elementClass = this.classReference(this.cpu.readRegister("x2"));
    // shortcut: Object arrays only; add assignability when an observed caller needs a typed array.
    if (elementClass.name !== "java/lang/Object") return false;
    const initialHandle = this.cpu.readRegister("x3"), initial = initialHandle === 0n ? null : this.references.get(initialHandle)?.value;
    if (initial === undefined) throw new RangeError("Invalid JNI initial element reference");
    const elements = new Array<JavaValue | null>(length).fill(initial);
    this.cpu.writeRegister("x0", this.allocateReference({ kind: "object-array", elements }, 64 + length * 8));
    return true;
  }

  private exceptionCheck(): void {
    this.assertEnvironment();
    // shortcut: managed Java exceptions are handled inside the machine or abort with a diagnostic,
    // so no JNI call can leave one pending; add pending-exception state when a caller depends on it.
    this.cpu.writeRegister("x0", 0n);
  }

  private isSameObject(): void {
    this.assertEnvironment();
    // References hold shared value objects, so identity comparison survives distinct handles.
    const left = this.referenceValue(this.cpu.readRegister("x1")),
      right = this.referenceValue(this.cpu.readRegister("x2"));
    this.cpu.writeRegister("x0", left === right ? 1n : 0n);
  }

  private getArrayLength(): void {
    this.assertEnvironment();
    const array = this.arrayReference(this.cpu.readRegister("x1"));
    this.cpu.writeRegister("x0", BigInt(array.kind === "object-array" ? array.elements.length : array.bytes.length));
  }

  private getByteArrayRegion(): void {
    this.assertEnvironment();
    const array = this.arrayReference(this.cpu.readRegister("x1"));
    if (array.kind !== "byte-array") throw new RangeError("JNI byte array region requires a byte array");
    const start = Number(BigInt.asIntN(32, this.cpu.readRegister("x2"))), length = Number(BigInt.asIntN(32, this.cpu.readRegister("x3")));
    if (start < 0 || length < 0 || start + length > array.bytes.length) throw new RangeError("JNI byte array region is outside the array bounds");
    // shortcut: an out-of-range region is a diagnostic failure; add real ArrayIndexOutOfBoundsException state when a caller depends on it.
    writeGuestBytes(this.cpu, this.cpu.readRegister("x4"), array.bytes.subarray(start, start + length));
  }

  private newObjectV(): NativeDispatch {
    this.assertEnvironment();
    const clazz = this.classReference(this.cpu.readRegister("x1")), method = this.constructorMethod(clazz.name);
    const signature = parseJavaMethod(method.descriptor);
    if (signature.parameters.some(type => type === "F" || type === "D")) return false;
    return this.construct(clazz.name, method, readVariadicWords(this.cpu, this.cpu.readRegister("x3"), signature.parameters.length), signature);
  }

  private newObjectA(): NativeDispatch {
    this.assertEnvironment();
    const clazz = this.classReference(this.cpu.readRegister("x1")), method = this.constructorMethod(clazz.name);
    const signature = parseJavaMethod(method.descriptor);
    return this.construct(clazz.name, method, this.readJValues(this.cpu.readRegister("x3"), signature.parameters.length), signature);
  }

  private constructorMethod(className: string): JavaMethod {
    const method = this.methods.get(this.cpu.readRegister("x2"));
    if (!method || method.className !== className || method.name !== "<init>" || method.isStatic) {
      throw new RangeError("Invalid JNI constructor identifier");
    }
    return method;
  }

  /** Decodes a `const jvalue*` array; each jvalue occupies eight bytes on AArch64. */
  private readJValues(address: bigint, count: number): bigint[] {
    const bytes = readGuestBytes(this.cpu, address, count * 8), view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return Array.from({ length: count }, (_, index) => view.getBigUint64(index * 8, true));
  }

  private construct(className: string, method: JavaMethod, words: readonly bigint[], signature: ReturnType<typeof parseJavaMethod>): NativeDispatch {
    // shortcut: boxed Long keeps its dedicated value kind; route every other constructor through the managed environment.
    if (className === "java/lang/Long" && signature.parameters.length === 1 && signature.parameters[0] === "J") {
      this.cpu.writeRegister("x0", this.allocateReference({ kind: "boxed-long", value: BigInt.asIntN(64, words[0]!) }, 72));
      return true;
    }
    if (!this.java) return false;
    const args = signature.parameters.map((type, index): JavaDatum => {
      const word = words[index]!;
      if (type.startsWith("L") || type.startsWith("[")) return this.referenceValue(word);
      if (type === "J") return BigInt.asIntN(64, word);
      if ("ZBCSI".includes(type)) return Number(BigInt.asIntN(32, word));
      throw new Error(`Unsupported JNI constructor argument type ${type}`);
    });
    const object: JavaValue = this.java.make({ kind: "instance", className, fields: new Map<string, JavaDatum>() }, 64);
    const reference = { className, name: "<init>", descriptor: method.descriptor };
    return this.runJava(this.java.invoke(reference, [object, ...args], "direct"), () => {
      this.cpu.writeRegister("x0", this.addReference(object, false));
    });
  }

  private getObjectArrayElement(): void {
    this.assertEnvironment();
    const array = this.arrayReference(this.cpu.readRegister("x1"));
    if (array.kind !== "object-array") throw new RangeError("JNI Object array element requires an Object array");
    const index = Number(BigInt.asIntN(32, this.cpu.readRegister("x2")));
    if (index < 0 || index >= array.elements.length) throw new RangeError("JNI Object array index is outside bounds");
    const element = array.elements[index] ?? null;
    this.cpu.writeRegister("x0", element ? this.addReference(element, false) : 0n);
  }

  private setObjectArrayElement(): void {
    this.assertEnvironment();
    const array = this.references.get(this.cpu.readRegister("x1"))?.value;
    if (array?.kind !== "object-array") throw new RangeError("Invalid JNI Object array reference");
    const index = Number(BigInt.asIntN(32, this.cpu.readRegister("x2")));
    if (index < 0 || index >= array.elements.length) throw new RangeError("JNI Object array index is outside bounds");
    const handle = this.cpu.readRegister("x3"), value = handle === 0n ? null : this.references.get(handle)?.value;
    if (value === undefined) throw new RangeError("Invalid JNI array element reference");
    array.elements[index] = value;
  }

  lookupNative(className: string, name: string, descriptor: string): bigint | undefined {
    return this.nativeMethods.get(`${className}\0${name}\0${descriptor}`);
  }

  referenceValue(reference: bigint): JavaValue | null {
    if (this.disposed) throw new Error("JNI environment is disposed");
    if (reference === 0n) return null;
    const entry = this.references.get(reference);
    if (!entry) throw new RangeError("Invalid JNI reference");
    return entry.value;
  }

  private callStaticObjectMethodV(): NativeDispatch {
    this.assertEnvironment();
    const clazz = this.classReference(this.cpu.readRegister("x1")), method = this.methods.get(this.cpu.readRegister("x2"));
    if (!method || !method.isStatic || method.className !== clazz.name) throw new RangeError("Invalid JNI static method identifier");
    const signature = parseJavaMethod(method.descriptor);
    if (!signature.result.startsWith("L") && !signature.result.startsWith("[")) throw new RangeError("JNI static Object call has a different return type");
    if (!this.java) return false;
    if (signature.parameters.some(type => type === "F" || type === "D")) return false;
    const words = readVariadicWords(this.cpu, this.cpu.readRegister("x3"), signature.parameters.length);
    const args = signature.parameters.map((type, index): JavaDatum => {
      const word = words[index]!;
      if (type.startsWith("L") || type.startsWith("[")) return this.referenceValue(word);
      if (type === "J") return BigInt.asIntN(64, word);
      if ("ZBCSI".includes(type)) return Number(BigInt.asIntN(32, word));
      throw new Error(`Unsupported JNI variadic argument type ${type}`);
    });
    return this.runJava(this.java.invoke(method, args), value => {
      const object = this.java!.object(value); this.cpu.writeRegister("x0", object ? this.addReference(object, false) : 0n);
    });
  }

  private callMethodV(result: "object" | "boolean" | "int" | "long" | "void"): NativeDispatch {
    this.assertEnvironment();
    const receiver = this.referenceValue(this.cpu.readRegister("x1")), method = this.methods.get(this.cpu.readRegister("x2"));
    if (!method || method.isStatic) throw new RangeError("Invalid JNI instance method identifier");
    if (!receiver) throw new RangeError("JNI instance call requires a receiver object");
    const signature = parseJavaMethod(method.descriptor);
    const matches = result === "object" ? signature.result.startsWith("L") || signature.result.startsWith("[")
      : signature.result === { boolean: "Z", int: "I", long: "J", void: "V" }[result];
    if (!matches) throw new RangeError(`JNI ${result} call disagrees with ${method.descriptor}`);
    if (signature.parameters.some(type => type === "F" || type === "D")) return false;
    if (!this.java) return false;
    const words = readVariadicWords(this.cpu, this.cpu.readRegister("x3"), signature.parameters.length);
    const args = signature.parameters.map((type, index): JavaDatum => {
      const word = words[index]!;
      if (type.startsWith("L") || type.startsWith("[")) return this.referenceValue(word);
      if (type === "J") return BigInt.asIntN(64, word);
      if ("ZBCSI".includes(type)) return Number(BigInt.asIntN(32, word));
      throw new Error(`Unsupported JNI instance argument type ${type}`);
    });
    const reference = { className: method.className, name: method.name, descriptor: method.descriptor };
    return this.runJava(this.java.invoke(reference, [receiver, ...args], "virtual"), value => {
      if (result === "void") this.cpu.writeRegister("x0", 0n);
      else if (result === "object") {
        const object = this.java!.object(value); this.cpu.writeRegister("x0", object ? this.addReference(object, false) : 0n);
      } else if (result === "long") this.cpu.writeRegister("x0", BigInt.asUintN(64, value as bigint));
      else this.cpu.writeRegister("x0", BigInt.asUintN(32, BigInt(this.java!.integer(value))));
    });
  }

  private runJava(execution: JavaExecution, complete: (value: JavaDatum) => NativeDispatch,
                  step = execution.next()): NativeDispatch {
    if (this.disposed || !this.java || this.cpu.readRegister("tpidr_el0") !== this.threadPointer) throw new Error("Foreign or disposed managed JNI call");
    if (step.done) return complete(step.value);
    const request = step.value;
    if (request.kind === "wait") return { kind: "wait", ready: request.ready,
      onReady: value => this.runJava(execution, complete, execution.next(value as JavaDatum)),
      onError: error => this.runJava(execution, complete, execution.throw(error)) };
    return this.enterJavaNative(request, value => this.runJava(execution, complete, execution.next(value)));
  }

  private enterJavaNative(request: Extract<JavaRequest, { kind: "native" }>, returned: (value: JavaDatum) => NativeDispatch): NativeDispatch {
    const method = request.method, signature = parseJavaMethod(method.descriptor), address = this.lookupNative(method.className, method.name, method.descriptor);
    if (address === undefined) throw new Error(`Java native method is not registered: ${method.className}.${method.name}`);
    if (signature.parameters.length > 6 || signature.parameters.some(type => type === "F" || type === "D") || this.localFrames.length >= 32) throw new Error("Unsupported Java native arguments or excessive frame nesting");
    const frame = new Set<bigint>(); this.localFrames.push(frame);
    let args: bigint[];
    try {
      const receiver = request.isStatic ? this.java!.classValue(method.className) : this.java!.object(request.args[0]!)!;
      args = [this.environmentAddress, this.addReference(receiver, false), ...signature.parameters.map((type, index) => {
        const value = request.args[index + (request.isStatic ? 0 : 1)]!;
        if (type.startsWith("L") || type.startsWith("[")) { const object = this.java!.object(value); return object ? this.addReference(object, false) : 0n; }
        return typeof value === "bigint" ? BigInt.asUintN(64, value) : BigInt(this.java!.integer(value));
      })];
    } catch (error) { this.closeLocalFrame(frame); throw error; }
    return { kind: "call", address, args, onReturn: bits => {
      let value: JavaDatum;
      if (signature.result === "V") value = null;
      else if (signature.result.startsWith("L") || signature.result.startsWith("[")) value = this.referenceValue(bits);
      else if (signature.result === "J") value = BigInt.asIntN(64, bits);
      else if ("ZBCSI".includes(signature.result)) value = Number(BigInt.asIntN(32, bits));
      else throw new Error(`Unsupported Java native return type ${signature.result}`);
      this.closeLocalFrame(frame); return returned(value);
    } };
  }

  private closeLocalFrame(frame: Set<bigint>): void {
    if (this.localFrames.at(-1) !== frame) throw new Error("JNI local frames returned out of order");
    for (const reference of frame) this.references.delete(reference);
    this.localFrames.pop();
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
      const declarations = (this.classes.get(entry.name) ?? this.java?.sourceClass(entry.name))?.methods.filter(method => method.name === name && method.descriptor === descriptor);
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
    this.cpu.writeRegister("x0", this.addReference(entry.value, true));
  }

  private deleteReference(global: boolean): void {
    this.assertEnvironment();
    const reference = this.cpu.readRegister("x1");
    if (reference === 0n) return;
    const entry = this.references.get(reference);
    if (!entry || entry.global !== global) throw new RangeError("Invalid JNI reference or lifetime");
    this.references.delete(reference);
    if (!global) for (const frame of this.localFrames) frame.delete(reference);
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
    this.java?.dispose(); this.java = undefined;
    this.references.clear();
    this.localFrames.length = 0;
    this.methods.clear();
    this.classes.clear();
    this.nativeMethods.clear();
    this.fields.clear();
    if (this.mapped) this.cpu.unmap(this.vmAddress, 4096n);
  }
}
