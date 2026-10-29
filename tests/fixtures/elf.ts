// A self-authored ET_DYN fixture: two load segments, one import, and RELA.
export function syntheticElf(): Uint8Array {
  const bytes = new Uint8Array(0x1300);
  const view = new DataView(bytes.buffer);
  const u16 = (offset: number, value: number): void => view.setUint16(offset, value, true);
  const u32 = (offset: number, value: number): void => view.setUint32(offset, value, true);
  const u64 = (offset: number, value: bigint): void => view.setBigUint64(offset, value, true);
  u32(0, 0x464c457f); bytes[4] = 2; bytes[5] = 1; bytes[6] = 1;
  u16(16, 3); u16(18, 183); u32(20, 1); u64(32, 64n);
  u16(52, 64); u16(54, 56); u16(56, 3);
  function segment(index: number, type: number, flags: number, offset: number, address: bigint, fileSize: number, memorySize: bigint): void {
    const start = 64 + index * 56;
    u32(start, type); u32(start + 4, flags); u64(start + 8, BigInt(offset));
    u64(start + 16, address); u64(start + 32, BigInt(fileSize)); u64(start + 40, memorySize); u64(start + 48, 1n);
  }
  segment(0, 1, 5, 0, 0n, 0x400, 0x1000n);
  segment(1, 1, 6, 0x1000, 0x2000n, 0x300, 0x1000n);
  const entries: [bigint, bigint][] = [
    [1n, 1n], [5n, 0x2280n], [10n, 32n], [6n, 0x2200n], [11n, 24n],
    [4n, 0x22c0n], [7n, 0x2180n], [8n, 48n], [9n, 24n],
    [12n, 0x300n], [25n, 0x22a0n], [27n, 8n], [0n, 0n],
  ];
  segment(2, 2, 6, 0x1000, 0x2000n, entries.length * 16, BigInt(entries.length * 16));
  entries.forEach(([tag, value], index) => { u64(0x1000 + index * 16, tag); u64(0x1008 + index * 16, value); });
  bytes.set(new TextEncoder().encode("\0libsample.so\0host_sample\0local\0"), 0x1280);
  // Symbol 1: function import; symbol 2: locally defined code.
  u32(0x1218, 14); bytes[0x121c] = 0x12;
  u32(0x1230, 26); bytes[0x1234] = 0x12; u16(0x1236, 1); u64(0x1238, 0x300n); u64(0x1240, 4n);
  // SysV hash: one bucket and three symbol-chain entries.
  u32(0x12c0, 1); u32(0x12c4, 3); u32(0x12c8, 1);
  // One imported pointer and one relocated initialization pointer.
  u64(0x1180, 0x22b0n); u64(0x1188, (1n << 32n) | 1025n); u64(0x1190, 8n);
  u64(0x1198, 0x22a0n); u64(0x11a0, 1027n); u64(0x11a8, 0x300n);
  u32(0x300, 0xd65f03c0); // ret
  return bytes;
}
