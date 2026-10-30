import type { BoundedZip } from "../assets/importer.ts";
import type { DexMethodReference } from "./dex.ts";
import type { JavaHostCalls, JavaMachine } from "./java-machine.ts";
import type { JavaDatum, JavaExecution, JavaValue } from "./java-values.ts";

export const BASE_APK_PATH = "/app/base.apk";
const classes = new Set(["java/lang/Object", "java/lang/Class", "java/lang/String", "java/lang/StringBuilder", "java/lang/System",
  "java/lang/Long", "java/lang/Integer", "java/net/URL", "java/util/zip/ZipFile", "java/util/zip/ZipEntry", "java/io/InputStream",
  "java/lang/Throwable", "java/lang/Exception", "java/lang/RuntimeException", "java/lang/ReflectiveOperationException",
  "java/lang/ClassNotFoundException", "java/io/IOException", "java/io/FileNotFoundException", "java/lang/NullPointerException",
  "java/lang/IndexOutOfBoundsException", "java/lang/StringIndexOutOfBoundsException", "java/lang/ArrayIndexOutOfBoundsException",
  "java/lang/NegativeArraySizeException", "java/lang/ArithmeticException", "java/lang/ClassCastException",
  "java/lang/IllegalMonitorStateException", "java/lang/UnsatisfiedLinkError", "android/content/Context",
  "java/io/File"]);
// The browser port exposes the user's package as one read-only file. Nothing else exists on
// the guest file system, so missing paths report honestly instead of pretending to be writable.
const VIRTUAL_APP_DIRECTORY = "/app";
type ZipState = { kind: "zip"; closed: boolean; streams: Set<StreamState> };
type StreamState = { kind: "stream"; file: ZipState; name: string; size: number; closed: boolean; position: number; bytes?: Uint8Array };
type HostState = ZipState | StreamState | { kind: "entry"; file: ZipState; name: string; size: number }
  | { kind: "builder"; value: string } | { kind: "url"; value: string } | { kind: "file"; path: string };

export class JavaPlatform implements JavaHostCalls {
  private readonly machine: JavaMachine;
  private readonly base: BoundedZip | undefined;
  private readonly libraryLoaded: (name: string) => boolean;
  private states = new WeakMap<JavaValue, HostState>();
  private readonly files = new Set<ZipState>();

  constructor(machine: JavaMachine, base: BoundedZip | undefined, libraryLoaded: (name: string) => boolean) {
    this.machine = machine; this.base = base; this.libraryLoaded = libraryLoaded;
  }

  hasClass(name: string): boolean { return classes.has(name); }

  /** Methods this platform implements, keyed as `name+descriptor` per class. */
  private static readonly hostMethods: Record<string, readonly string[]> = {
    "java/io/File": ["<init>(Ljava/lang/String;)V", "getPath()Ljava/lang/String;", "toString()Ljava/lang/String;",
      "getAbsolutePath()Ljava/lang/String;", "getCanonicalPath()Ljava/lang/String;", "getName()Ljava/lang/String;",
      "getParent()Ljava/lang/String;", "exists()Z", "isFile()Z", "isDirectory()Z", "length()J", "equals(Ljava/lang/Object;)Z",
      "hashCode()I", "delete()Z", "mkdir()Z", "mkdirs()Z", "createNewFile()Z", "renameTo(Ljava/io/File;)Z", "setLastModified(J)Z"],
  };

  hasMethod(className: string, name: string, descriptor: string): boolean {
    return JavaPlatform.hostMethods[className]?.includes(name + descriptor) ?? false;
  }

  /** Path of an existing or prospective entry in the virtual file system. */
  private filePath(value: JavaDatum): string {
    const object = this.machine.object(value);
    if (!object) this.machine.raise("java/lang/NullPointerException", "Null java.io.File");
    const state = this.states.get(object);
    if (state?.kind !== "file") throw new Error("Invalid java.io.File receiver");
    return state.path;
  }

  private fileExists(path: string): boolean {
    return path === "/" || path === VIRTUAL_APP_DIRECTORY || this.fileLength(path) !== undefined;
  }

  private fileLength(path: string): number | undefined {
    return path === BASE_APK_PATH ? this.base?.byteLength : undefined;
  }

  private file(method: DexMethodReference, args: JavaDatum[]): JavaDatum {
    const key = `java/io/File.${method.name}${method.descriptor}`;
    if (key === "java/io/File.<init>(Ljava/lang/String;)V") {
      const receiver = this.machine.object(args[0]!);
      if (receiver?.kind !== "instance" || receiver.className !== "java/io/File") throw new Error("Invalid java.io.File construction");
      const path = this.text(args[1]!);
      if (!path.startsWith("/") || path.length > 4096 || path.includes("\0") || path.split("/").includes("..")) {
        this.machine.raise("java/lang/IllegalArgumentException", "Unsupported guest file path");
      }
      this.states.set(receiver, { kind: "file", path: path.length > 1 ? path.replace(/\/+$/, "") : path });
      return null;
    }
    const path = this.filePath(args[0]!);
    if (key === "java/io/File.getPath()Ljava/lang/String;" || key === "java/io/File.toString()Ljava/lang/String;") {
      return this.machine.stringValue(path);
    }
    // The virtual file system has no relative roots, so absolute and canonical paths are equal.
    if (key === "java/io/File.getAbsolutePath()Ljava/lang/String;" || key === "java/io/File.getCanonicalPath()Ljava/lang/String;") {
      return this.machine.stringValue(path);
    }
    if (key === "java/io/File.getName()Ljava/lang/String;") {
      const slash = path.lastIndexOf("/");
      return this.machine.stringValue(path.slice(slash + 1));
    }
    if (key === "java/io/File.getParent()Ljava/lang/String;") {
      const slash = path.lastIndexOf("/");
      if (slash < 0) return null;
      return this.machine.stringValue(slash === 0 ? "/" : path.slice(0, slash));
    }
    if (key === "java/io/File.exists()Z") return this.fileExists(path) ? 1 : 0;
    if (key === "java/io/File.isFile()Z") return this.fileLength(path) === undefined ? 0 : 1;
    if (key === "java/io/File.isDirectory()Z") return path === "/" || path === VIRTUAL_APP_DIRECTORY ? 1 : 0;
    if (key === "java/io/File.length()J") return BigInt(this.fileLength(path) ?? 0);
    if (key === "java/io/File.equals(Ljava/lang/Object;)Z") {
      const other = this.machine.object(args[1]!);
      if (other?.kind !== "instance" || this.states.get(other)?.kind !== "file") return 0;
      return this.filePath(other) === path ? 1 : 0;
    }
    if (key === "java/io/File.hashCode()I") {
      let hash = 0;
      for (const character of path) hash = (Math.imul(hash, 31) + character.codePointAt(0)!) | 0;
      return hash;
    }
    // shortcut: the guest file system is read-only user data; mutation reports failure rather than faking a write.
    if (["java/io/File.delete()Z", "java/io/File.mkdir()Z", "java/io/File.mkdirs()Z", "java/io/File.createNewFile()Z",
         "java/io/File.renameTo(Ljava/io/File;)Z", "java/io/File.setLastModified(J)Z"].includes(key)) return 0;
    throw new Error(`Unsupported java.io.File call ${method.name}${method.descriptor}`);
  }

  private text(value: JavaDatum): string {
    const object = this.machine.object(value);
    if (!object) this.machine.raise("java/lang/NullPointerException", "Null Java string");
    if (object.kind !== "string") throw new Error("Java platform requires a string");
    return object.value;
  }

  private state<K extends HostState["kind"]>(value: JavaDatum, kind: K): Extract<HostState, { kind: K }> {
    const object = this.machine.object(value);
    if (!object) this.machine.raise("java/lang/NullPointerException", "Null Java platform receiver");
    const state = this.states.get(object);
    if (state?.kind !== kind) throw new Error(`Invalid Java ${kind} receiver`);
    return state as Extract<HostState, { kind: K }>;
  }

  private instance(className: string, state: HostState): JavaValue {
    const value = this.machine.make({ kind: "instance", className, fields: new Map<string, JavaDatum>() }, 64);
    this.states.set(value, state); return value;
  }

  private closeStream(stream: StreamState): void { stream.closed = true; stream.bytes = undefined; stream.file.streams.delete(stream); }
  private closeFile(file: ZipState): void { file.closed = true; for (const stream of file.streams) this.closeStream(stream); this.files.delete(file); }

  *invoke(method: DexMethodReference, args: JavaDatum[]): JavaExecution {
    this.machine.assertActive();
    const key = `${method.className}.${method.name}${method.descriptor}`;
    if (method.className === "java/io/File") return this.file(method, args);
    if (key === "java/lang/Object.<init>()V") return null;
    if (key === "java/lang/System.currentTimeMillis()J") return BigInt(Date.now());
    if (key === "java/lang/System.loadLibrary(Ljava/lang/String;)V") {
      const name = this.text(args[0]!);
      if (!/^[A-Za-z0-9_.-]{1,128}$/.test(name) || !this.libraryLoaded(`lib${name}.so`)) this.machine.raise("java/lang/UnsatisfiedLinkError", `Native library is not loaded: ${name}`);
      return null;
    }
    if (key === "java/lang/Class.forName(Ljava/lang/String;)Ljava/lang/Class;") {
      const name = this.text(args[0]!).replaceAll(".", "/");
      if (!/^[A-Za-z_$][\w$]*(?:\/[A-Za-z_$][\w$]*)*$/.test(name) || !this.machine.hasClass(name)) this.machine.raise("java/lang/ClassNotFoundException", name);
      yield* this.machine.initializeClass(name); return this.machine.classValue(name);
    }
    if (key === "java/lang/Class.getResource(Ljava/lang/String;)Ljava/net/URL;") {
      const clazz = this.machine.object(args[0]!); if (clazz?.kind !== "class") throw new Error("Resource lookup requires a Java Class");
      const resource = this.text(args[1]!), slash = clazz.name.lastIndexOf("/");
      const name = resource.startsWith("/") ? resource.slice(1) : `${slash < 0 ? "" : clazz.name.slice(0, slash + 1)}${resource}`;
      if (!this.base || this.base.entrySize(name) === undefined) return null;
      return this.instance("java/net/URL", { kind: "url", value: `jar:file:${BASE_APK_PATH}!/${name}` });
    }
    if (key === "java/net/URL.toString()Ljava/lang/String;") return this.machine.stringValue(this.state(args[0]!, "url").value);
    if (key === "java/lang/String.equals(Ljava/lang/Object;)Z") {
      const other = this.machine.object(args[1]!); return other?.kind === "string" && this.text(args[0]!) === other.value ? 1 : 0;
    }
    if (key === "java/lang/String.lastIndexOf(I)I") {
      const character = this.machine.integer(args[1]!); return character < 0 || character > 0x10ffff ? -1 : this.text(args[0]!).lastIndexOf(String.fromCodePoint(character));
    }
    if (key === "java/lang/String.substring(II)Ljava/lang/String;") {
      const value = this.text(args[0]!), start = this.machine.integer(args[1]!), end = this.machine.integer(args[2]!);
      if (start < 0 || start > end || end > value.length) this.machine.raise("java/lang/StringIndexOutOfBoundsException", "Java substring is outside bounds");
      return this.machine.stringValue(value.slice(start, end));
    }
    if (method.className === "java/lang/StringBuilder") {
      const receiver = this.machine.object(args[0]!); if (receiver?.kind !== "instance") throw new Error("StringBuilder requires a Java object");
      if (method.name === "<init>" && ["()V", "(Ljava/lang/String;)V"].includes(method.descriptor)) {
        const value = args.length === 1 ? "" : this.text(args[1]!);
        this.machine.accountBytes(32 + value.length * 2); this.states.set(receiver, { kind: "builder", value }); return null;
      }
      const builder = this.state(receiver, "builder");
      if (method.name === "append" && ["(Ljava/lang/String;)Ljava/lang/StringBuilder;", "(I)Ljava/lang/StringBuilder;"].includes(method.descriptor)) {
        const value = method.descriptor.startsWith("(I)") ? String(this.machine.integer(args[1]!)) : args[1] === null ? "null" : this.text(args[1]!);
        if (builder.value.length + value.length > 65536) throw new Error("Java StringBuilder exceeds its startup limit");
        this.machine.accountBytes(value.length * 2); builder.value += value; return receiver;
      }
      if (method.name === "toString" && method.descriptor === "()Ljava/lang/String;") return this.machine.stringValue(builder.value);
    }
    if (key === "java/lang/Long.valueOf(J)Ljava/lang/Long;") {
      if (typeof args[0] !== "bigint") throw new Error("Long.valueOf requires a long");
      return this.machine.make({ kind: "boxed-long", value: BigInt.asIntN(64, args[0]) }, 72);
    }
    if (key === "java/lang/Long.longValue()J") {
      const value = this.machine.object(args[0]!); if (value?.kind !== "boxed-long") throw new Error("Long accessor requires a boxed long"); return value.value;
    }
    if (key === "java/util/zip/ZipFile.<init>(Ljava/lang/String;)V") {
      const receiver = this.machine.object(args[0]!); if (receiver?.kind !== "instance") throw new Error("ZipFile requires a Java object");
      if (!this.base || this.text(args[1]!) !== BASE_APK_PATH) this.machine.raise("java/io/FileNotFoundException", "Base APK path is unavailable");
      if (this.files.size >= 16) throw new Error("Java open ZIP file limit exceeded");
      const file: ZipState = { kind: "zip", closed: false, streams: new Set() }; this.states.set(receiver, file); this.files.add(file); return null;
    }
    if (key === "java/util/zip/ZipFile.getEntry(Ljava/lang/String;)Ljava/util/zip/ZipEntry;") {
      const file = this.state(args[0]!, "zip"); if (file.closed) this.machine.raise("java/io/IOException", "ZIP file is closed");
      const name = this.text(args[1]!), size = this.base!.entrySize(name);
      return size === undefined ? null : this.instance("java/util/zip/ZipEntry", { kind: "entry", file, name, size });
    }
    if (key === "java/util/zip/ZipEntry.getSize()J") return BigInt(this.state(args[0]!, "entry").size);
    if (key === "java/util/zip/ZipFile.getInputStream(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;") {
      const file = this.state(args[0]!, "zip"), entry = this.state(args[1]!, "entry");
      if (file.closed || entry.file !== file) this.machine.raise("java/io/IOException", "ZIP entry belongs to a closed or different file");
      if (file.streams.size >= 16) throw new Error("Java open ZIP stream limit exceeded");
      const stream: StreamState = { kind: "stream", file, name: entry.name, size: entry.size, closed: false, position: 0 };
      file.streams.add(stream); return this.instance("java/io/InputStream", stream);
    }
    if (key === "java/io/InputStream.read([BII)I") {
      const stream = this.state(args[0]!, "stream"), target = this.machine.object(args[1]!);
      if (target?.kind !== "byte-array") throw new Error("InputStream destination must be a byte array");
      const offset = this.machine.integer(args[2]!), length = this.machine.integer(args[3]!);
      if (offset < 0 || length < 0 || offset > target.bytes.length || length > target.bytes.length - offset) this.machine.raise("java/lang/IndexOutOfBoundsException", "Stream destination is outside bounds");
      if (stream.closed || stream.file.closed) this.machine.raise("java/io/IOException", "Input stream is closed");
      if (!length) return 0;
      if (!stream.bytes) {
        let value: JavaDatum;
        try { value = yield { kind: "wait", ready: this.base!.bytes(stream.name, 16 * 1024 * 1024).then(bytes => ({ kind: "byte-array" as const, bytes })) }; }
        catch (error) { this.machine.raise("java/io/IOException", String(error instanceof Error ? error.message : error).slice(0, 800)); }
        this.machine.assertActive();
        const loaded = this.machine.object(value);
        if (loaded?.kind !== "byte-array" || loaded.bytes.length !== stream.size) throw new Error("ZIP stream returned invalid bytes");
        stream.bytes = loaded.bytes;
      }
      const count = Math.min(length, stream.bytes.length - stream.position);
      if (!count) return -1;
      target.bytes.set(stream.bytes.subarray(stream.position, stream.position + count), offset); stream.position += count;
      return count;
    }
    if (key === "java/io/InputStream.close()V") { this.closeStream(this.state(args[0]!, "stream")); return null; }
    if (key === "java/util/zip/ZipFile.close()V") { this.closeFile(this.state(args[0]!, "zip")); return null; }
    if (method.name === "<init>" && classes.has(method.className) && (method.className.endsWith("Exception") || method.className === "java/lang/Throwable") &&
        ["()V", "(Ljava/lang/String;)V", "(Ljava/lang/String;Ljava/lang/Throwable;)V"].includes(method.descriptor)) {
      const receiver = this.machine.object(args[0]!); if (receiver?.kind !== "instance") throw new Error("Java exception constructor requires an instance");
      receiver.fields.set("detailMessage", args[1] ?? null); receiver.fields.set("cause", args[2] ?? null); return null;
    }
    if (method.name === "getMessage" && method.descriptor === "()Ljava/lang/String;" && classes.has(method.className) && (method.className.endsWith("Exception") || method.className === "java/lang/Throwable")) {
      const receiver = this.machine.object(args[0]!); if (receiver?.kind !== "instance") throw new Error("Java exception accessor requires an instance"); return receiver.fields.get("detailMessage") ?? null;
    }
    throw new Error(`Unsupported Java call ${key}`);
  }

  dispose(): void { for (const file of this.files) this.closeFile(file); this.states = new WeakMap(); }
}
