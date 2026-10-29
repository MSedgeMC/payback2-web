export const MAX_MODIFIED_UTF8_BYTES = 64 * 1024;

export function decodeModifiedUtf8(bytes: Uint8Array): string {
  if (bytes.length > MAX_MODIFIED_UTF8_BYTES) throw new RangeError("Java string exceeds its byte limit");
  let index = 0, value = "";
  const continuation = (): number => {
    const byte = bytes[index++];
    if (byte === undefined || (byte & 0xc0) !== 0x80) throw new Error("Invalid modified UTF-8 continuation");
    return byte & 63;
  };
  while (index < bytes.length) {
    const byte = bytes[index++]!;
    let unit: number;
    if (byte > 0 && byte < 128) unit = byte;
    else if (byte >= 0xc0 && byte < 0xe0) {
      unit = ((byte & 31) << 6) | continuation();
      if (unit > 0 && unit < 128) throw new Error("Overlong modified UTF-8 character");
    } else if (byte >= 0xe0 && byte < 0xf0) {
      unit = ((byte & 15) << 12) | (continuation() << 6) | continuation();
      if (unit < 2048) throw new Error("Overlong modified UTF-8 character");
    } else throw new Error("Invalid modified UTF-8 character");
    // Java encodes NUL and UTF-16 surrogates separately from ordinary UTF-8.
    value += String.fromCharCode(unit);
  }
  return value;
}
