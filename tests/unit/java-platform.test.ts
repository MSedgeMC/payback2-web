import assert from "node:assert/strict";
import { test } from "node:test";
import { BoundedZip } from "../../src/assets/importer.ts";
import { readDex } from "../../src/runtime/dex.ts";
import { JavaMachine } from "../../src/runtime/java-machine.ts";
import { BASE_APK_PATH, JavaPlatform } from "../../src/runtime/java-platform.ts";
import { javaClassName, JavaThrown } from "../../src/runtime/java-values.ts";
import type { JavaDatum, JavaExecution, JavaValue } from "../../src/runtime/java-values.ts";
import { syntheticManagedDex } from "../fixtures/dex.ts";
import { syntheticZip } from "../fixtures/zip.ts";

async function finish(execution: JavaExecution): Promise<JavaDatum> {
  let step = execution.next();
  while (!step.done) {
    assert.equal(step.value.kind, "wait"); assert.ok(step.value.kind === "wait");
    let value: JavaDatum;
    try { value = await step.value.ready; } catch (error) { step = execution.throw(error); continue; }
    step = execution.next(value);
  }
  return step.value;
}
function call(java: JavaMachine, className: string, name: string, descriptor: string, args: JavaDatum[], kind: "static" | "direct" | "virtual" = "static") {
  return java.invoke({ className, name, descriptor }, args, kind);
}
function instance(java: JavaMachine, className: string): JavaValue { return java.make({ kind: "instance", className, fields: new Map() }, 64); }
const thrown = (name: string) => (error: unknown): boolean => error instanceof JavaThrown && javaClassName(error.value) === name;

test("Java class reflection reports missing Android internals and resources resolve to the actual base archive", async () => {
  const archive = await BoundedZip.open(syntheticZip([{ name: "AndroidManifest.xml", bytes: new Uint8Array([1]) }]));
  const java = new JavaMachine(readDex(syntheticManagedDex()), () => {}, machine => new JavaPlatform(machine, archive, name => name === "libfixture.so"));
  try {
    assert.throws(() => call(java, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", [java.stringValue("android.app.LoadedApk")]).next(), thrown("java/lang/ClassNotFoundException"));
    const clazz = await finish(call(java, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", [java.stringValue("example.Runner")]));
    assert.equal(clazz, java.classValue("example/Runner"));
    const url = await finish(call(java, "java/lang/Class", "getResource", "(Ljava/lang/String;)Ljava/net/URL;", [clazz, java.stringValue("/AndroidManifest.xml")], "virtual"));
    const text = await finish(call(java, "java/net/URL", "toString", "()Ljava/lang/String;", [url], "virtual")), textValue = java.object(text);
    assert.ok(textValue?.kind === "string"); assert.equal(textValue.value, `jar:file:${BASE_APK_PATH}!/AndroidManifest.xml`);
    const bang = await finish(call(java, "java/lang/String", "lastIndexOf", "(I)I", [text, 33], "virtual"));
    const path = await finish(call(java, "java/lang/String", "substring", "(II)Ljava/lang/String;", [text, 9, bang], "virtual"));
    assert.deepEqual(path, { kind: "string", value: BASE_APK_PATH });
    assert.equal(await finish(call(java, "java/lang/Class", "getResource", "(Ljava/lang/String;)Ljava/net/URL;", [clazz, java.stringValue("/missing")], "virtual")), null);
    assert.equal(await finish(call(java, "java/lang/System", "loadLibrary", "(Ljava/lang/String;)V", [java.stringValue("fixture")])), null);
    assert.throws(() => call(java, "java/lang/System", "loadLibrary", "(Ljava/lang/String;)V", [java.stringValue("missing")]).next(), thrown("java/lang/UnsatisfiedLinkError"));
  } finally { java.dispose(); await archive.close(); }
});

test("Java ZIP streams lazily read verified bytes, honor offsets and EOF, and close without closing the shared archive", async () => {
  const data = new Uint8Array([3, 1, 4]), archive = await BoundedZip.open(syntheticZip([{ name: "assets/sample", bytes: data, deflate: true }]));
  const java = new JavaMachine(readDex(syntheticManagedDex()), () => {}, machine => new JavaPlatform(machine, archive, () => false));
  try {
    const file = instance(java, "java/util/zip/ZipFile");
    await finish(call(java, "java/util/zip/ZipFile", "<init>", "(Ljava/lang/String;)V", [file, java.stringValue(BASE_APK_PATH)], "direct"));
    const entry = await finish(call(java, "java/util/zip/ZipFile", "getEntry", "(Ljava/lang/String;)Ljava/util/zip/ZipEntry;", [file, java.stringValue("assets/sample")], "virtual"));
    assert.equal(await finish(call(java, "java/util/zip/ZipEntry", "getSize", "()J", [entry], "virtual")), 3n);
    const stream = await finish(call(java, "java/util/zip/ZipFile", "getInputStream", "(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;", [file, entry], "virtual"));
    const target = java.make({ kind: "byte-array", bytes: new Uint8Array(8).fill(0x77) }, 72);
    const pending = call(java, "java/io/InputStream", "read", "([BII)I", [stream, target, 1, 2], "virtual"), first = pending.next();
    assert.equal(first.done, false); assert.ok(!first.done && first.value.kind === "wait");
    const loaded = await first.value.ready; assert.deepEqual(target.bytes, new Uint8Array(8).fill(0x77));
    assert.deepEqual(pending.next(loaded), { done: true, value: 2 });
    assert.equal(await finish(call(java, "java/io/InputStream", "read", "([BII)I", [stream, target, 3, 4], "virtual")), 1);
    assert.deepEqual(target.bytes, new Uint8Array([0x77, 3, 1, 4, 0x77, 0x77, 0x77, 0x77]));
    assert.equal(await finish(call(java, "java/io/InputStream", "read", "([BII)I", [stream, target, 0, 1], "virtual")), -1);
    assert.equal(await finish(call(java, "java/io/InputStream", "read", "([BII)I", [stream, target, 0, 0], "virtual")), 0);
    assert.throws(() => call(java, "java/io/InputStream", "read", "([BII)I", [stream, target, 7, 2], "virtual").next(), thrown("java/lang/IndexOutOfBoundsException"));
    await finish(call(java, "java/util/zip/ZipFile", "close", "()V", [file], "virtual"));
    assert.throws(() => call(java, "java/io/InputStream", "read", "([BII)I", [stream, target, 0, 1], "virtual").next(), thrown("java/io/IOException"));
    assert.deepEqual(await archive.bytes("assets/sample", 3), data);
  } finally { java.dispose(); await archive.close(); }
});

test("bad asset CRC becomes a Java IOException without changing the stream destination", async () => {
  const name = "assets/sample", bytes = new Uint8Array(await syntheticZip([{ name, bytes: new Uint8Array([1, 2, 3]) }]).arrayBuffer());
  bytes[30 + name.length] = 9;
  const archive = await BoundedZip.open(new Blob([bytes])), java = new JavaMachine(readDex(syntheticManagedDex()), () => {}, machine => new JavaPlatform(machine, archive, () => false));
  try {
    const file = instance(java, "java/util/zip/ZipFile"); await finish(call(java, "java/util/zip/ZipFile", "<init>", "(Ljava/lang/String;)V", [file, java.stringValue(BASE_APK_PATH)], "direct"));
    const entry = await finish(call(java, "java/util/zip/ZipFile", "getEntry", "(Ljava/lang/String;)Ljava/util/zip/ZipEntry;", [file, java.stringValue(name)], "virtual"));
    const stream = await finish(call(java, "java/util/zip/ZipFile", "getInputStream", "(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;", [file, entry], "virtual"));
    const target = java.make({ kind: "byte-array", bytes: new Uint8Array(3).fill(7) }, 67);
    await assert.rejects(finish(call(java, "java/io/InputStream", "read", "([BII)I", [stream, target, 0, 3], "virtual")), thrown("java/io/IOException"));
    assert.deepEqual(target.bytes, new Uint8Array([7, 7, 7]));
  } finally { java.dispose(); await archive.close(); }
});
