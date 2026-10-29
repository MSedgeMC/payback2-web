import { deflateRawSync } from "node:zlib";

export function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? 0xedb88320 ^ crc >>> 1 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function syntheticZip(entries: { name: string; bytes: Uint8Array; deflate?: boolean }[]): Blob {
  const encoder = new TextEncoder();
  const local: Uint8Array<ArrayBuffer>[] = [], central: Uint8Array<ArrayBuffer>[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = encoder.encode(entry.name);
    const compressed = entry.deflate ? deflateRawSync(entry.bytes) : entry.bytes;
    const header = new Uint8Array(30 + name.byteLength + compressed.byteLength), view = new DataView(header.buffer);
    const method = entry.deflate ? 8 : 0, crc = crc32(entry.bytes);
    view.setUint32(0, 0x04034b50, true); view.setUint16(4, 20, true); view.setUint16(8, method, true);
    view.setUint32(14, crc, true); view.setUint32(18, compressed.byteLength, true); view.setUint32(22, entry.bytes.byteLength, true);
    view.setUint16(26, name.byteLength, true); header.set(name, 30); header.set(compressed, 30 + name.byteLength);
    const directory = new Uint8Array(46 + name.byteLength), record = new DataView(directory.buffer);
    record.setUint32(0, 0x02014b50, true); record.setUint16(4, 20, true); record.setUint16(6, 20, true);
    record.setUint16(10, method, true); record.setUint32(16, crc, true); record.setUint32(20, compressed.byteLength, true);
    record.setUint32(24, entry.bytes.byteLength, true); record.setUint16(28, name.byteLength, true); record.setUint32(42, offset, true);
    directory.set(name, 46); local.push(header); central.push(directory); offset += header.byteLength;
  }
  const end = new Uint8Array(22), view = new DataView(end.buffer);
  view.setUint32(0, 0x06054b50, true); view.setUint16(8, entries.length, true); view.setUint16(10, entries.length, true);
  view.setUint32(12, central.reduce((size, bytes) => size + bytes.byteLength, 0), true); view.setUint32(16, offset, true);
  return new Blob([...local, ...central, end]);
}
