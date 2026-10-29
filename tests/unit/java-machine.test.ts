import assert from "node:assert/strict";
import { test } from "node:test";
import { readDex } from "../../src/runtime/dex.ts";
import { JavaMachine } from "../../src/runtime/java-machine.ts";
import { parseJavaMethod } from "../../src/runtime/java-descriptors.ts";
import { JavaThrown } from "../../src/runtime/java-values.ts";
import type { JavaValue } from "../../src/runtime/java-values.ts";
import { syntheticManagedDex } from "../fixtures/dex.ts";

const method = { className: "example/Runner", name: "execute", descriptor: "([B)Ljava/lang/Object;" };
const input = (): JavaValue => ({ kind: "byte-array", bytes: new Uint8Array([0]) });
function machine(bytes: Uint8Array): JavaMachine {
  return new JavaMachine(readDex(bytes), () => {}, () => ({ hasClass: name => name === "java/lang/Object",
    *invoke(reference) { throw new Error(`Unsupported Java call ${reference.name}`); }, dispose() {} }));
}

test("managed DEX returns the actual object input and validates descriptors and registers", () => {
  const value = input(), java = machine(syntheticManagedDex());
  try {
    const result = java.invoke(method, [value]).next(); assert.equal(result.done, true); assert.equal(result.value, value);
    assert.throws(() => java.invoke(method, []).next(), /argument count/);
    assert.throws(() => java.invoke(method, [42]).next(), /not an object/);
  } finally { java.dispose(); }
  const invalid = machine(syntheticManagedDex([0x2007, 0x0011]));
  try { assert.throws(() => invalid.invoke(method, [input()]).next(), /register.*bounds/); } finally { invalid.dispose(); }
  assert.deepEqual(parseJavaMethod("(J[B[[Ljava/lang/String;)Ljava/lang/Object;"), { parameters: ["J", "[B", "[[Ljava/lang/String;"], result: "Ljava/lang/Object;" });
  for (const descriptor of ["J)V", "(V)V", "([V)V", "(Ljava/lang/String)V", "()Vextra", "(I)", "(L../Secret;)V"]) assert.throws(() => parseJavaMethod(descriptor), /descriptor/);
});

test("managed integer overflow, unsigned shifts, byte writes, and signed long wrapping match Java values", () => {
  const bytes = syntheticManagedDex([0x0012, 0x0114, 0xffff, 0x7fff, 0x01d8, 0x0101, 0x01e2, 0x1f01, 0x014f, 0x0002, 0x0211]);
  new DataView(bytes.buffer).setUint16(400, 3, true);
  const java = machine(bytes), value = input();
  try { assert.equal(java.invoke(method, [value]).next().value, value); assert.ok(value.kind === "byte-array"); assert.equal(value.bytes[0], 1); }
  finally { java.dispose(); }
  const dex = readDex(syntheticManagedDex([0x0016, 0xffff, 0x02bb, 0x0210])), definition = dex.readClass(method.className).methods[0]!;
  definition.descriptor = "(J)J"; definition.code!.registers = 4; definition.code!.inputs = 2;
  const wide = new JavaMachine(dex, () => {}, () => ({ hasClass: name => name === "java/lang/Object", *invoke() { throw new Error("unexpected call"); }, dispose() {} }));
  try {
    assert.equal(wide.invoke({ ...method, descriptor: "(J)J" }, [-0x8000000000000000n]).next().value, 0x7fffffffffffffffn);
    assert.equal(wide.invoke({ ...method, descriptor: "(J)J" }, [0x7fffffffffffffffn]).next().value, 0x7ffffffffffffffen);
  } finally { wide.dispose(); }
});

test("managed native calls suspend at declared methods and continue with their genuine returned object", () => {
  const bytes = syntheticManagedDex([0x1071, 1, 1, 0x000c, 0x0011]); bytes[218] = 2; bytes[219] = 0; bytes[225] = 0x89;
  const java = machine(bytes), value = input(), execution = java.invoke(method, [value]);
  try {
    assert.deepEqual(execution.next(), { done: false, value: { kind: "native", method: { ...method, name: "instance" }, isStatic: true, args: [value] } });
    assert.deepEqual(execution.next(value), { done: true, value });
  } finally { java.dispose(); }
});

test("managed exception handlers catch Java throwables while unsupported runtime failures remain visible", () => {
  const bytes = syntheticManagedDex([0x1071, 1, 1, 0x000c, 0x0011, 0x000d, 0x0111]), view = new DataView(bytes.buffer);
  bytes[218] = 2; bytes[219] = 0; bytes[225] = 0x89;
  view.setUint16(406, 1, true); view.setUint32(432, 0, true); view.setUint16(436, 3, true); view.setUint16(438, 1, true); bytes.set([1, 0, 5], 440);
  const java = machine(bytes), value = input();
  try {
    const execution = java.invoke(method, [value]); assert.equal(execution.next().done, false);
    const exception: JavaValue = { kind: "instance", className: "java/lang/ClassNotFoundException", fields: new Map() };
    assert.deepEqual(execution.throw(new JavaThrown(exception)), { done: true, value });
    const unsupported = java.invoke(method, [value]); unsupported.next(); assert.throws(() => unsupported.throw(new Error("Unsupported native operation")), /Unsupported native/);
    assert.equal(java.isAssignable("java/lang/ClassNotFoundException", "java/lang/Exception"), true);
    assert.equal(java.isAssignable("java/io/IOException", "java/lang/ClassNotFoundException"), false);
  } finally { java.dispose(); }
});

test("malformed branches, unsupported instructions, and endless managed loops fail within bounds", () => {
  for (const [instructions, message] of [
    [[0x0013, 1, 0xff28], /instruction boundary/], [[0x0020, 2, 0x0111], /Unsupported DEX opcode/], [[0x0028], /budget exhausted/],
  ] as const) {
    const java = machine(syntheticManagedDex([...instructions]));
    try { assert.throws(() => java.invoke(method, [input()]).next(), message); } finally { java.dispose(); }
  }
});
