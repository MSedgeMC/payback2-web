import { BlobReader, ZipReader, configure } from "@zip.js/zip.js/lib/zip-core-native.js";
import type { Entry, FileEntry } from "@zip.js/zip.js";
import { SUPPORTED_GAME } from "./baseline.ts";

const MAX_PACKAGE_BYTES = 256 * 1024 * 1024;
const MAX_DIRECTORY_BYTES = 4 * 1024 * 1024;
const MAX_ENTRIES = 4096;
const MAX_EXPANDED_BYTES = 512 * 1024 * 1024;
configure({ useWebWorkers: false, maxWorkers: 1, chunkSize: 64 * 1024 });

export function validateEntryName(name: string): void {
  const path = name.endsWith("/") ? name.slice(0, -1) : name;
  if (!path || path.length > 512 || /[\\\x00-\x1f:]/.test(path) || path.startsWith("/") ||
      path.split("/").some(part => !part || part === "." || part === "..")) {
    throw new Error("Unsafe ZIP entry name");
  }
}

async function inspectDirectoryBounds(blob: Blob): Promise<number> {
  if (blob.size < 22 || blob.size > MAX_PACKAGE_BYTES) throw new Error("ZIP input must be between 22 bytes and 256 MiB");
  const offset = Math.max(0, blob.size - 65_557);
  const tail = new Uint8Array(await blob.slice(offset).arrayBuffer());
  const view = new DataView(tail.buffer);
  for (let index = tail.byteLength - 22; index >= 0; index--) {
    if (view.getUint32(index, true) !== 0x06054b50 || index + 22 + view.getUint16(index + 20, true) !== tail.byteLength) continue;
    const count = view.getUint16(index + 10, true), diskCount = view.getUint16(index + 8, true);
    const size = view.getUint32(index + 12, true), start = view.getUint32(index + 16, true);
    if (view.getUint16(index + 4, true) || view.getUint16(index + 6, true) || diskCount !== count || count === 0xffff || start === 0xffffffff) {
      throw new Error("Split-disk and ZIP64 packages are unsupported");
    }
    if (count > MAX_ENTRIES || size > MAX_DIRECTORY_BYTES || start + size > offset + index) {
      throw new Error("ZIP central directory exceeds bounds or limits");
    }
    return count;
  }
  throw new Error("ZIP end-of-directory record is missing or malformed");
}

export class BoundedZip {
  readonly entries: readonly Entry[];
  private readonly reader: ZipReader<Blob>;
  private closed = false;

  private constructor(reader: ZipReader<Blob>, entries: Entry[]) { this.reader = reader; this.entries = entries; }

  static async open(blob: Blob): Promise<BoundedZip> {
    const expectedCount = await inspectDirectoryBounds(blob);
    const reader = new ZipReader(new BlobReader(blob), { useWebWorkers: false, checkSignature: true });
    try {
      const entries = await reader.getEntries();
      if (entries.length !== expectedCount) throw new Error("ZIP entry count disagrees with its directory");
      const names = new Set<string>();
      let total = 0;
      for (const entry of entries) {
        validateEntryName(entry.filename);
        if (names.has(entry.filename)) throw new Error("Duplicate ZIP entry name");
        names.add(entry.filename);
        if (entry.encrypted || entry.symlink || ![0, 8].includes(entry.compressionMethod)) throw new Error("Encrypted, linked, or unsupported ZIP entry");
        if (!Number.isSafeInteger(entry.uncompressedSize) || !Number.isSafeInteger(entry.compressedSize) ||
            entry.uncompressedSize < 0 || entry.compressedSize < 0 || entry.compressedSize > blob.size || entry.uncompressedSize > MAX_PACKAGE_BYTES) {
          throw new Error("Invalid or oversized ZIP entry");
        }
        total += entry.uncompressedSize;
        if (total > MAX_EXPANDED_BYTES) throw new Error("ZIP expanded-size budget exceeded");
      }
      return new BoundedZip(reader, entries);
    } catch (error) { await reader.close(); throw error; }
  }

  private file(name: string, maxBytes: number): FileEntry {
    if (this.closed) throw new Error("ZIP reader is closed");
    const entry = this.entries.find(entry => entry.filename === name);
    if (!entry || entry.directory) throw new Error(`Required ZIP entry ${name} is missing`);
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || entry.uncompressedSize > maxBytes) throw new Error("Selected ZIP entry exceeds its expanded-size limit");
    return entry;
  }

  async bytes(name: string, maxBytes: number): Promise<Uint8Array<ArrayBuffer>> {
    const entry = this.file(name, maxBytes);
    const output = new Uint8Array(entry.uncompressedSize);
    let written = 0;
    await entry.getData(new WritableStream<Uint8Array>({
      write(chunk) {
        if (chunk.byteLength > output.byteLength - written) throw new Error("ZIP entry expanded beyond its declared size");
        output.set(chunk, written); written += chunk.byteLength;
      },
    }), { checkSignature: true, useWebWorkers: false });
    if (written !== entry.uncompressedSize) throw new Error("ZIP entry expanded-size mismatch");
    return output;
  }

  async blob(name: string, maxBytes: number): Promise<Blob> {
    const entry = this.file(name, maxBytes);
    const chunks: Blob[] = [];
    let written = 0;
    await entry.getData(new WritableStream<Uint8Array<ArrayBuffer>>({
      write(chunk) {
        if (chunk.byteLength > entry.uncompressedSize - written) throw new Error("ZIP entry expanded beyond its declared size");
        written += chunk.byteLength; chunks.push(new Blob([chunk]));
      },
    }), { checkSignature: true, useWebWorkers: false });
    if (written !== entry.uncompressedSize) throw new Error("ZIP entry expanded-size mismatch");
    return new Blob(chunks);
  }

  async close(): Promise<void> { if (!this.closed) { this.closed = true; await this.reader.close(); } }
}

export async function readPackageEngine(file: File): Promise<Uint8Array<ArrayBuffer>> {
  const name = file.name.toLowerCase();
  if (name.endsWith(".so")) {
    if (file.size !== SUPPORTED_GAME.engineBytes) throw new Error("Unsupported engine size");
    return new Uint8Array(await file.arrayBuffer());
  }
  if (!name.endsWith(".apk") && !name.endsWith(".apkm")) throw new Error("Select an APKM, ARM64 split APK, or libpayback2.so");
  let apk: Blob = file;
  if (name.endsWith(".apkm")) {
    const packageZip = await BoundedZip.open(file);
    try {
      const metadata = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await packageZip.bytes("info.json", 64 * 1024)));
      if (metadata.pname !== SUPPORTED_GAME.package || metadata.release_version !== SUPPORTED_GAME.version || Number(metadata.versioncode) !== SUPPORTED_GAME.versionCode) {
        throw new Error("Unsupported APKM package or version");
      }
      apk = await packageZip.blob("split_config.arm64_v8a.apk", 64 * 1024 * 1024);
    } finally { await packageZip.close(); }
  }
  const splitZip = await BoundedZip.open(apk);
  try { return await splitZip.bytes("lib/arm64-v8a/libpayback2.so", SUPPORTED_GAME.engineBytes); }
  finally { await splitZip.close(); }
}
