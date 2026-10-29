export function syntheticDex(): Uint8Array {
  const bytes = new Uint8Array(512), view = new DataView(bytes.buffer);
  const u32 = (offset: number, value: number): void => view.setUint32(offset, value, true);
  const strings = ["Lexample/Runner;", "[B", "Ljava/lang/Object;", "execute", "instance"];
  bytes.set(new TextEncoder().encode("dex\n035\0")); u32(32, bytes.length); u32(36, 112); u32(40, 0x12345678);
  const tables = [[5, 112], [3, 132], [1, 144], [0, 0], [2, 156], [1, 172]];
  tables.forEach(([count, offset], index) => { u32(56 + index * 8, count!); u32(60 + index * 8, offset!); });
  let cursor = 256;
  strings.forEach((value, index) => {
    u32(112 + index * 4, cursor); bytes[cursor++] = value.length;
    const encoded = new TextEncoder().encode(value + "\0"); bytes.set(encoded, cursor); cursor += encoded.length;
  });
  [0, 1, 2].forEach((value, index) => u32(132 + index * 4, value));
  u32(148, 2); u32(152, 208); u32(208, 1); view.setUint16(212, 1, true);
  u32(160, 3); u32(168, 4); u32(172, 0); u32(196, 216);
  // No fields; one static native method and one instance native method.
  bytes.set([0, 0, 1, 1, 0, 0x89, 2, 0, 1, 0x81, 2, 0], 216);
  return bytes;
}
