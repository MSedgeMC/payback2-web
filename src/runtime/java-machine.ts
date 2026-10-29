import type { DexClass, DexCode, DexFieldReference, DexFile, DexMethodReference } from "./dex.ts";
import { DexClassMissing } from "./dex.ts";
import { javaTypeWords, parseJavaMethod } from "./java-descriptors.ts";
import type { JavaDatum, JavaExecution, JavaValue } from "./java-values.ts";
import { javaClassName, JavaThrown } from "./java-values.ts";

export type JavaHostCalls = { hasClass(name: string): boolean; invoke(method: DexMethodReference, args: JavaDatum[]): JavaExecution; dispose(): void };
const fieldKey = (field: DexFieldReference): string => `${field.className}\0${field.name}\0${field.descriptor}`;
const wideTail = Symbol("wide register tail");
const exceptionParents: Record<string, string> = {
  "java/lang/Throwable": "java/lang/Object", "java/lang/Exception": "java/lang/Throwable",
  "java/lang/RuntimeException": "java/lang/Exception", "java/io/IOException": "java/lang/Exception",
  "java/io/FileNotFoundException": "java/io/IOException", "java/lang/StringIndexOutOfBoundsException": "java/lang/IndexOutOfBoundsException",
  "java/lang/Error": "java/lang/Throwable", "java/lang/LinkageError": "java/lang/Error", "java/lang/UnsatisfiedLinkError": "java/lang/LinkageError",
  "java/lang/ReflectiveOperationException": "java/lang/Exception",
  "java/lang/ClassNotFoundException": "java/lang/ReflectiveOperationException",
  "java/lang/ArithmeticException": "java/lang/RuntimeException", "java/lang/NullPointerException": "java/lang/RuntimeException",
  "java/lang/IndexOutOfBoundsException": "java/lang/RuntimeException", "java/lang/ArrayIndexOutOfBoundsException": "java/lang/IndexOutOfBoundsException",
  "java/lang/NegativeArraySizeException": "java/lang/RuntimeException", "java/lang/ClassCastException": "java/lang/RuntimeException",
  "java/lang/IllegalMonitorStateException": "java/lang/RuntimeException",
};

function instructionWidth(opcode: number): number {
  if ([0, 1, 4, 7, 0x1d, 0x1e, 0x21, 0x27, 0x28].includes(opcode) || opcode >= 0x0a && opcode <= 0x12 ||
      opcode >= 0x7b && opcode <= 0x8f || opcode >= 0xb0 && opcode <= 0xcf) return 1;
  if ([2, 5, 8, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x29].includes(opcode) ||
      opcode >= 0x2d && opcode <= 0x3d || opcode >= 0x44 && opcode <= 0x6d || opcode >= 0x90 && opcode <= 0xaf ||
      opcode >= 0xd0 && opcode <= 0xe2) return 2;
  if ([3, 6, 9, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c].includes(opcode) ||
      opcode >= 0x6e && opcode <= 0x72 || opcode >= 0x74 && opcode <= 0x78) return 3;
  if (opcode === 0x18) return 5;
  throw new Error(`Unsupported DEX opcode 0x${opcode.toString(16)}`);
}

export class JavaMachine {
  private readonly dex: DexFile;
  private readonly reserve: (bytes: number) => void;
  private readonly host: JavaHostCalls | undefined;
  private readonly classes = new Map<string, { definition: DexClass; fields: Map<string, JavaDatum>; state: "new" | "initializing" | "ready" | "failed"; error?: unknown }>();
  private readonly classValues = new Map<string, Extract<JavaValue, { kind: "class" }>>();
  private readonly strings = new Map<string, Extract<JavaValue, { kind: "string" }>>();
  private readonly monitors = new Map<JavaValue, number>();
  private depth = 0;
  private instructions = 0;
  private disposed = false;

  constructor(dex: DexFile, reserve: (bytes: number) => void, host?: (machine: JavaMachine) => JavaHostCalls) {
    this.dex = dex; this.reserve = reserve; this.host = host?.(this);
  }

  assertActive(): void { if (this.disposed) throw new Error("Java machine is disposed"); }

  sourceClass(name: string): DexClass | undefined {
    try { return this.dex.readClass(name); } catch (error) { if (error instanceof DexClassMissing) return undefined; throw error; }
  }

  hasClass(name: string): boolean { return !!this.sourceClass(name) || !!this.host?.hasClass(name); }

  make<T extends JavaValue>(value: T, bytes: number): T {
    this.accountBytes(bytes); return value;
  }

  accountBytes(bytes: number): void { this.assertActive(); this.reserve(bytes); }

  stringValue(value: string, intern = false): Extract<JavaValue, { kind: "string" }> {
    const existing = intern && this.strings.get(value); if (existing) return existing;
    const object = this.make({ kind: "string", value }, 64 + value.length * 2);
    if (intern) this.strings.set(value, object);
    return object;
  }

  classValue(name: string): Extract<JavaValue, { kind: "class" }> {
    let value = this.classValues.get(name);
    if (!value) { value = this.make({ kind: "class", name }, 64 + name.length * 2); this.classValues.set(name, value); }
    return value;
  }

  raise(className: string, message: string): never {
    const fields = new Map<string, JavaDatum>([["detailMessage", this.stringValue(message)]]);
    throw new JavaThrown(this.make({ kind: "instance", className, fields }, 64));
  }

  object(value: JavaDatum): JavaValue | null {
    if (value === null || value === 0) return null;
    if (typeof value !== "object") throw new Error("DEX value is not an object");
    return value;
  }

  integer(value: JavaDatum): number {
    if (typeof value !== "number" || !Number.isInteger(value) || value < -0x80000000 || value > 0x7fffffff) throw new Error("DEX value is not a signed integer");
    return value;
  }

  isAssignable(actual: string, expected: string): boolean {
    if (expected === "java/lang/Object" || actual === expected) return true;
    for (let depth = 0; depth < 32; depth++) {
      if (actual.startsWith("[")) return false;
      const parent = exceptionParents[actual] ?? this.sourceClass(actual)?.superclass;
      if (!parent) return false;
      if (parent === expected) return true;
      actual = parent;
    }
    throw new Error("Java superclass nesting exceeds its limit");
  }

  private checkValue(value: JavaDatum, descriptor: string): JavaDatum {
    if (descriptor.startsWith("L") || descriptor.startsWith("[")) {
      const object = this.object(value), expected = descriptor.startsWith("L") ? descriptor.slice(1, -1) : descriptor;
      if (object && !this.isAssignable(javaClassName(object), expected)) throw new Error("Java argument or field has an incompatible object type");
      return object;
    }
    if (descriptor === "J") { if (typeof value !== "bigint") throw new Error("Java argument is not a long"); return BigInt.asIntN(64, value); }
    if (!"ZBCSI".includes(descriptor)) throw new Error(`Unsupported Java value descriptor ${descriptor}`);
    return this.integer(value);
  }

  private classState(name: string) {
    let state = this.classes.get(name);
    if (!state) {
      const definition = this.sourceClass(name); if (!definition) return undefined;
      const fields = new Map<string, JavaDatum>();
      for (const field of definition.fields) if (field.isStatic) fields.set(fieldKey(field), this.checkValue(typeof field.value === "string" ? this.stringValue(field.value, true) : field.value, field.descriptor));
      state = { definition, fields, state: "new" }; this.classes.set(name, state);
    }
    return state;
  }

  *initializeClass(name: string): JavaExecution {
    this.assertActive();
    const state = this.classState(name);
    if (!state) { if (!this.host?.hasClass(name)) throw new Error(`Unsupported Java class ${name}`); return null; }
    if (state.state === "failed") throw state.error;
    if (state.state !== "new") return null;
    state.state = "initializing";
    try {
      if (state.definition.superclass) yield* this.initializeClass(state.definition.superclass);
      const method = state.definition.methods.find(method => method.name === "<clinit>" && method.descriptor === "()V");
      if (method) yield* this.invoke({ className: name, name: "<clinit>", descriptor: "()V" }, [], "static");
      state.state = "ready";
    } catch (error) { state.state = "failed"; state.error = error; throw error; }
    return null;
  }

  *invoke(reference: DexMethodReference, args: JavaDatum[], kind: "static" | "direct" | "virtual" = "static"): JavaExecution {
    this.assertActive();
    // shortcut: 32 managed frames and 100,000 instructions per invocation; revise from observed startup work.
    if (this.depth >= 32) throw new Error("Java call nesting limit exceeded");
    if (this.depth === 0) this.instructions = 0;
    this.depth++;
    try {
      const signature = parseJavaMethod(reference.descriptor), isStatic = kind === "static";
      if (args.length !== signature.parameters.length + (isStatic ? 0 : 1)) throw new Error("Java call argument count disagrees with its descriptor");
      const receiver = isStatic ? null : this.object(args[0]!);
      if (!isStatic && !receiver) this.raise("java/lang/NullPointerException", "Null Java method receiver");
      if (receiver && !this.isAssignable(javaClassName(receiver), reference.className)) throw new Error("Java method receiver has an incompatible class");
      const checked = signature.parameters.map((type, index) => this.checkValue(args[index + (isStatic ? 0 : 1)]!, type));
      if (receiver) checked.unshift(receiver);
      let owner = reference.className, definition = this.sourceClass(owner);
      if (kind === "virtual" && receiver && definition) {
        let actual = javaClassName(receiver);
        for (let depth = 0; depth < 32 && actual !== owner; depth++) {
          const candidate = this.sourceClass(actual);
          if (!candidate) break;
          if (candidate.methods.some(method => method.name === reference.name && method.descriptor === reference.descriptor && !method.isStatic)) { owner = actual; definition = candidate; break; }
          if (!candidate.superclass) break; actual = candidate.superclass;
        }
      }
      let value: JavaDatum;
      if (!definition) {
        if (!this.host) throw new Error(`Unsupported Java call ${owner}.${reference.name}${reference.descriptor}`);
        value = yield* this.host.invoke(reference, checked);
      } else {
        const method = definition.methods.find(method => method.name === reference.name && method.descriptor === reference.descriptor);
        if (!method || method.isStatic !== isStatic) throw new Error("DEX invoke disagrees with the declared Java method");
        yield* this.initializeClass(owner);
        if (method.isNative) value = yield { kind: "native", method: { ...reference, className: owner }, isStatic, args: checked };
        else {
          if (!method.code) throw new Error("Java method has no executable code");
          value = yield* this.execute(method.code, checked, signature.parameters, isStatic, reference);
        }
      }
      this.assertActive();
      return signature.result === "V" ? null : this.checkValue(value, signature.result);
    } finally { this.depth--; }
  }

  private newArray(descriptor: string, length: number): JavaValue {
    if (length < 0) this.raise("java/lang/NegativeArraySizeException", "Negative Java array length");
    if (descriptor === "[B") {
      if (length > 16 * 1024 * 1024) throw new Error("Java byte array exceeds its limit");
      this.reserve(64 + length); return { kind: "byte-array", bytes: new Uint8Array(length) };
    }
    if (!/^\[L[A-Za-z_$][\w$/]*;$/.test(descriptor) || length > 16384) throw new Error("Unsupported or excessive Java object array");
    this.reserve(64 + length * 8);
    return { kind: "object-array", elements: new Array<JavaValue | null>(length).fill(null), elementClass: descriptor.slice(2, -1) };
  }

  private newInstance(name: string): JavaValue {
    if (!this.hasClass(name)) throw new Error(`Unsupported Java object class ${name}`);
    const fields = new Map<string, JavaDatum>();
    let owner: string | null = name;
    for (let depth = 0; owner && depth < 32; depth++) {
      const definition = this.sourceClass(owner); if (!definition) break;
      for (const field of definition.fields) if (!field.isStatic) fields.set(fieldKey(field), this.checkValue(typeof field.value === "string" ? this.stringValue(field.value, true) : field.value, field.descriptor));
      owner = definition.superclass;
      if (depth === 31 && owner) throw new Error("Java object superclass nesting exceeds its limit");
    }
    return this.make({ kind: "instance", className: name, fields }, 64 + fields.size * 16);
  }

  private *execute(code: DexCode, args: JavaDatum[], parameters: string[], isStatic: boolean, reference: DexMethodReference): JavaExecution {
    const words = code.instructions, boundaries = new Set<number>();
    for (let offset = 0; offset < words.length;) {
      if (words[offset] !== 0 && (words[offset]! & 255) === 0) throw new Error("DEX instruction payloads are unsupported");
      boundaries.add(offset); const width = instructionWidth(words[offset]! & 255);
      if (offset + width > words.length) throw new Error("Truncated DEX instruction");
      offset += width;
    }
    for (const range of code.tries) {
      if (!boundaries.has(range.start) || range.start + range.length !== words.length && !boundaries.has(range.start + range.length) || range.catches.some(handler => !boundaries.has(handler.target))) throw new Error("DEX exception range crosses an instruction boundary");
    }
    const registers = new Array<JavaDatum | typeof wideTail | undefined>(code.registers);
    const index = (register: number): number => { if (!Number.isInteger(register) || register < 0 || register >= registers.length) throw new Error("DEX register is outside method bounds"); return register; };
    const read = (register: number): JavaDatum => { const value = registers[index(register)]; if (value === undefined || value === wideTail) throw new Error("DEX register is uninitialized or part of a wide value"); return value; };
    const write = (register: number, value: JavaDatum): void => {
      index(register);
      if (registers[register] === wideTail) registers[register - 1] = undefined;
      if (registers[register + 1] === wideTail) registers[register + 1] = undefined;
      registers[register] = value;
    };
    const readWide = (register: number): bigint => { const value = read(register); if (typeof value !== "bigint" || registers[index(register + 1)] !== wideTail) throw new Error("Invalid DEX wide register pair"); return value; };
    const writeWide = (register: number, value: bigint): void => { index(register + 1); write(register, BigInt.asIntN(64, value)); write(register + 1, null); registers[register + 1] = wideTail; };
    const inputTypes = isStatic ? parameters : ["Ljava/lang/Object;", ...parameters];
    if (inputTypes.reduce((count, type) => count + javaTypeWords(type), 0) !== code.inputs) throw new Error("DEX input registers disagree with the method descriptor");
    let input = code.registers - code.inputs;
    inputTypes.forEach((type, arg) => { if (type === "J") writeWide(input, args[arg] as bigint); else write(input, args[arg]!); input += javaTypeWords(type); });
    let pc = 0, result: JavaDatum | undefined, resultType = "V", exception: JavaValue | undefined;
    const branch = (target: number): number => { if (!boundaries.has(target)) throw new Error("DEX branch is outside an instruction boundary"); return target; };
    const int = (register: number): number => this.integer(read(register));
    const object = (register: number): JavaValue | null => this.object(read(register));
    const requiredObject = (register: number): JavaValue => { const value = object(register); if (!value) this.raise("java/lang/NullPointerException", "Null Java object"); return value; };
    const signed16 = (value: number): number => value << 16 >> 16;
    const int32 = (offset: number): number => words[offset]! | words[offset + 1]! << 16;
    const array = (register: number): Extract<JavaValue, { kind: "byte-array" | "object-array" }> => { const value = requiredObject(register); if (value.kind !== "byte-array" && value.kind !== "object-array") throw new Error("DEX value is not an array"); return value; };
    const arrayIndex = (value: ReturnType<typeof array>, offset: number): number => { const length = value.kind === "byte-array" ? value.bytes.length : value.elements.length; if (offset < 0 || offset >= length) this.raise("java/lang/ArrayIndexOutOfBoundsException", "Java array index is outside bounds"); return offset; };
    const binaryInt = (opcode: number, left: number, right: number): number => {
      if ((opcode === 0x93 || opcode === 0x94) && right === 0) this.raise("java/lang/ArithmeticException", "Integer division by zero");
      if (opcode === 0x90) return left + right | 0; if (opcode === 0x91) return left - right | 0;
      if (opcode === 0x92) return Math.imul(left, right); if (opcode === 0x93) return Math.trunc(left / right) | 0;
      if (opcode === 0x94) return left % right | 0; if (opcode === 0x95) return left & right;
      if (opcode === 0x96) return left | right; if (opcode === 0x97) return left ^ right;
      if (opcode === 0x98) return left << (right & 31); if (opcode === 0x99) return left >> (right & 31);
      if (opcode === 0x9a) return left >>> (right & 31) | 0;
      throw new Error("Unsupported DEX integer operation");
    };
    while (pc < words.length) {
      this.assertActive(); if (++this.instructions > 100000) throw new Error("Java instruction budget exhausted");
      const start = pc, word = words[pc]!, opcode = word & 255, a = word >>> 8, lowA = a & 15, b = word >>> 12;
      const next = pc + instructionWidth(opcode);
      try {
        if (opcode < 0x0a || opcode > 0x0c) { result = undefined; resultType = "V"; }
        if (opcode === 0) { /* nop */ }
        else if (opcode >= 1 && opcode <= 9) {
          const layout = (opcode - 1) % 3, group = Math.floor((opcode - 1) / 3), destination = layout === 0 ? lowA : layout === 1 ? a : words[pc + 1]!, source = layout === 0 ? b : words[pc + (layout === 1 ? 1 : 2)]!;
          if (group === 1) writeWide(destination, readWide(source)); else write(destination, group === 2 ? object(source) : int(source));
        } else if (opcode >= 0x0a && opcode <= 0x0c) {
          if (result === undefined || resultType === "V" || (opcode === 0x0b) !== (resultType === "J") || (opcode === 0x0c) !== (resultType.startsWith("L") || resultType.startsWith("["))) throw new Error("DEX move-result disagrees with its invocation");
          if (opcode === 0x0b) writeWide(a, result as bigint); else write(a, result);
          result = undefined; resultType = "V";
        } else if (opcode === 0x0d) { if (!exception) throw new Error("DEX move-exception has no pending exception"); write(a, exception); exception = undefined; }
        else if (opcode >= 0x0e && opcode <= 0x11) {
          const expected = parseJavaMethod(reference.descriptor).result;
          if (opcode === 0x0e) { if (expected !== "V") throw new Error("DEX void return disagrees with its descriptor"); return null; }
          if (opcode === 0x10) return readWide(a);
          return opcode === 0x11 ? object(a) : int(a);
        } else if (opcode === 0x12) write(lowA, word >> 12 << 28 >> 28);
        else if (opcode === 0x13) write(a, signed16(words[pc + 1]!));
        else if (opcode === 0x14) write(a, int32(pc + 1));
        else if (opcode === 0x15) write(a, words[pc + 1]! << 16);
        else if (opcode === 0x16 || opcode === 0x17) writeWide(a, BigInt(opcode === 0x16 ? signed16(words[pc + 1]!) : int32(pc + 1)));
        else if (opcode === 0x18 || opcode === 0x19) { let value = 0n; for (let index = 0; index < (opcode === 0x18 ? 4 : 1); index++) value |= BigInt(words[pc + 1 + index]!) << BigInt(opcode === 0x18 ? index * 16 : 48); writeWide(a, value); }
        else if (opcode === 0x1a || opcode === 0x1b) write(a, this.stringValue(this.dex.string(opcode === 0x1a ? words[pc + 1]! : int32(pc + 1) >>> 0), true));
        else if (opcode === 0x1c) { const type = this.dex.type(words[pc + 1]!); if (!type.startsWith("L")) throw new Error("Primitive and array Class literals are unsupported"); write(a, this.classValue(type.slice(1, -1))); }
        else if (opcode === 0x1d || opcode === 0x1e) {
          const value = requiredObject(a), count = this.monitors.get(value) ?? 0;
          // shortcut: reentrant monitors on the single managed thread; add waiters with guest scheduling.
          if (opcode === 0x1d) { if (this.monitors.size >= 256 && !count) throw new Error("Java monitor limit exceeded"); this.monitors.set(value, count + 1); }
          else { if (!count) this.raise("java/lang/IllegalMonitorStateException", "Java monitor is not owned"); if (count === 1) this.monitors.delete(value); else this.monitors.set(value, count - 1); }
        } else if (opcode === 0x1f) { const type = this.dex.type(words[pc + 1]!), value = object(a); if (value && !this.isAssignable(javaClassName(value), type.startsWith("L") ? type.slice(1, -1) : type)) this.raise("java/lang/ClassCastException", "Incompatible Java cast"); }
        else if (opcode === 0x21) { const value = array(b); write(lowA, value.kind === "byte-array" ? value.bytes.length : value.elements.length); }
        else if (opcode === 0x22) { const type = this.dex.type(words[pc + 1]!); if (!type.startsWith("L")) throw new Error("Invalid Java instance descriptor"); const name = type.slice(1, -1); yield* this.initializeClass(name); write(a, this.newInstance(name)); }
        else if (opcode === 0x23) write(lowA, this.newArray(this.dex.type(words[pc + 1]!), int(b)));
        else if (opcode === 0x27) throw new JavaThrown(requiredObject(a));
        else if (opcode >= 0x28 && opcode <= 0x2a) { pc = branch(start + (opcode === 0x28 ? a << 24 >> 24 : opcode === 0x29 ? signed16(words[pc + 1]!) : int32(pc + 1))); continue; }
        else if (opcode === 0x31) { const left = readWide(words[pc + 1]! & 255), right = readWide(words[pc + 1]! >>> 8); write(a, left < right ? -1 : left > right ? 1 : 0); }
        else if (opcode >= 0x32 && opcode <= 0x3d) {
          const zero = opcode >= 0x38, operation = opcode - (zero ? 0x38 : 0x32), left = read(zero ? a : lowA), right = zero ? 0 : read(b);
          const equal = left === right || (left === null || left === 0) && (right === null || right === 0);
          const condition = operation === 0 ? equal : operation === 1 ? !equal : operation === 2 ? this.integer(left) < this.integer(right) : operation === 3 ? this.integer(left) >= this.integer(right) : operation === 4 ? this.integer(left) > this.integer(right) : this.integer(left) <= this.integer(right);
          if (condition) { pc = branch(start + signed16(words[pc + 1]!)); continue; }
        } else if ([0x46, 0x48, 0x4d, 0x4f].includes(opcode)) {
          const value = array(words[pc + 1]! & 255), offset = arrayIndex(value, int(words[pc + 1]! >>> 8));
          if (opcode === 0x46 || opcode === 0x4d) {
            if (value.kind !== "object-array") throw new Error("DEX object access requires an object array");
            if (opcode === 0x46) write(a, value.elements[offset]!);
            else value.elements[offset] = this.checkValue(object(a), `L${value.elementClass ?? "java/lang/Object"};`) as JavaValue | null;
          } else { if (value.kind !== "byte-array") throw new Error("DEX byte access requires a byte array"); if (opcode === 0x48) write(a, value.bytes[offset]! << 24 >> 24); else value.bytes[offset] = int(a) & 255; }
        } else if (opcode >= 0x52 && opcode <= 0x6d) {
          const field = this.dex.field(words[pc + 1]!), static_ = opcode >= 0x60, put = static_ ? opcode >= 0x67 : opcode >= 0x59;
          const valueKind = (opcode - (static_ ? 0x60 : 0x52)) % 7;
          const compatible = valueKind === 0 ? field.descriptor === "I" : valueKind === 1 ? field.descriptor === "J" : valueKind === 2 ? field.descriptor.startsWith("L") || field.descriptor.startsWith("[") : field.descriptor === ["Z", "B", "C", "S"][valueKind - 3];
          if (!compatible) throw new Error("DEX field opcode disagrees with its declared type");
          let fields: Map<string, JavaDatum>;
          if (static_) { yield* this.initializeClass(field.className); const state = this.classState(field.className); if (!state) throw new Error("Unsupported Java static field owner"); fields = state.fields; }
          else { const value = requiredObject(b); if (value.kind !== "instance") throw new Error("Java instance field requires an object instance"); fields = value.fields; }
          const key = fieldKey(field), register = static_ ? a : lowA;
          if (!fields.has(key)) throw new Error("Java field is not declared on its owner");
          if (put) fields.set(key, this.checkValue(field.descriptor === "J" ? readWide(register) : read(register), field.descriptor));
          else { const value = fields.get(key)!; if (field.descriptor === "J") writeWide(register, value as bigint); else write(register, value); }
        } else if (opcode >= 0x6e && opcode <= 0x72 || opcode >= 0x74 && opcode <= 0x78) {
          const range = opcode >= 0x74, normalized = range ? opcode - 6 : opcode, method = this.dex.method(words[pc + 1]!), signature = parseJavaMethod(method.descriptor);
          const count = range ? a : a >>> 4, encoded = words[pc + 2]!, slots = range ? Array.from({ length: count }, (_, index) => encoded + index) : [encoded & 15, encoded >>> 4 & 15, encoded >>> 8 & 15, encoded >>> 12, lowA].slice(0, count);
          const types = normalized === 0x71 ? signature.parameters : ["Ljava/lang/Object;", ...signature.parameters];
          if ((!range && count > 5) || count > code.outputs || types.reduce((sum, type) => sum + javaTypeWords(type), 0) !== slots.length) throw new Error("DEX invocation argument words disagree with its descriptor");
          let slot = 0;
          const values = types.map(type => { const register = slots[slot]!; slot += javaTypeWords(type); if (javaTypeWords(type) === 2 && slots[slot - 1] !== register + 1) throw new Error("DEX invocation splits a wide argument"); return type === "J" ? readWide(register) : read(register); });
          result = yield* this.invoke(method, values, normalized === 0x71 ? "static" : normalized === 0x6e || normalized === 0x72 ? "virtual" : "direct");
          resultType = signature.result;
        } else if (opcode === 0x7b || opcode === 0x7c) write(lowA, opcode === 0x7b ? -int(b) | 0 : ~int(b));
        else if (opcode === 0x7d || opcode === 0x7e) writeWide(lowA, opcode === 0x7d ? -readWide(b) : ~readWide(b));
        else if (opcode === 0x81) writeWide(lowA, BigInt(int(b)));
        else if (opcode === 0x84) write(lowA, Number(BigInt.asIntN(32, readWide(b))));
        else if (opcode >= 0x8d && opcode <= 0x8f) write(lowA, opcode === 0x8d ? int(b) << 24 >> 24 : opcode === 0x8e ? int(b) & 65535 : int(b) << 16 >> 16);
        else if (opcode >= 0x90 && opcode <= 0x9a || opcode >= 0xb0 && opcode <= 0xba || opcode >= 0xd0 && opcode <= 0xe2) {
          let operation: number, destination: number, left: number, right: number;
          if (opcode <= 0x9a) { operation = opcode; destination = a; left = int(words[pc + 1]! & 255); right = int(words[pc + 1]! >>> 8); }
          else if (opcode <= 0xba) { operation = opcode - 0x20; destination = lowA; left = int(lowA); right = int(b); }
          else if (opcode <= 0xd7) { operation = opcode - 0x40; destination = lowA; left = int(b); right = signed16(words[pc + 1]!); }
          else { operation = opcode - 0x48; destination = a; left = int(words[pc + 1]! & 255); right = words[pc + 1]! >> 8 << 24 >> 24; }
          if (operation === 0x91 && opcode >= 0xd0) [left, right] = [right, left];
          write(destination, binaryInt(operation, left, right));
        } else if (opcode === 0x9b || opcode === 0x9c || opcode === 0xbb || opcode === 0xbc) {
          const two = opcode >= 0xbb, destination = two ? lowA : a, left = readWide(two ? lowA : words[pc + 1]! & 255), right = readWide(two ? b : words[pc + 1]! >>> 8);
          writeWide(destination, opcode === 0x9b || opcode === 0xbb ? left + right : left - right);
        } else throw new Error(`Unsupported DEX opcode 0x${opcode.toString(16)} at ${reference.className}.${reference.name} + ${start}`);
        pc = next;
      } catch (error) {
        if (!(error instanceof JavaThrown)) throw error;
        const range = code.tries.find(range => start >= range.start && start < range.start + range.length);
        const handler = range?.catches.find(handler => handler.className === null || this.isAssignable(javaClassName(error.value), handler.className));
        if (!handler) throw error;
        exception = error.value; result = undefined; resultType = "V"; pc = branch(handler.target);
      }
    }
    throw new Error("DEX method fell through without returning");
  }

  dispose(): void { if (this.disposed) return; this.disposed = true; this.host?.dispose(); this.classes.clear(); this.classValues.clear(); this.strings.clear(); this.monitors.clear(); }
}
