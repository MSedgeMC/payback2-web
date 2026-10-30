import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseElf } from "../src/runtime/elf.ts";
import { decode } from "../src/runtime/translate/arm64.ts";

// Reports how much of a library's executable text the translator covers, treating `udf`
// padding and embedded data words as non-code so the percentage reflects real instructions.
const paths = process.argv.slice(2);
if (!paths.length) throw new Error("Pass one or more ELF paths");

/** `udf #imm16` is padding or a trap placeholder rather than executable code. */
function isUdf(word: number): boolean { return ((word & 0xffff0000) >>> 0) === 0; }

for (const path of paths) {
  const file = await readFile(resolve(path));
  const bytes = new Uint8Array(file.buffer, file.byteOffset, file.byteLength);
  const image = parseElf(bytes);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const report: { segment: string; words: number; code: number; supported: number; percent: number; unsupported: number[] }[] = [];
  for (const segment of image.segments) {
    if (segment.type !== 1 || (segment.flags & 1) === 0) continue;
    const start = Number(segment.address), end = start + segment.fileSize;
    let code = 0, supported = 0, words = 0;
    const unsupported: number[] = [];
    for (let address = start; address + 4 <= end; address += 4) {
      words++;
      const word = view.getUint32(address, true);
      try { decode(address, word); supported++; code++; }
      catch { if (!isUdf(word)) { code++; unsupported.push(address); } }
    }
    report.push({ segment: `0x${start.toString(16)}+0x${segment.fileSize.toString(16)}`, words, code, supported,
      percent: Math.round(supported / Math.max(code, 1) * 1000) / 10, unsupported });
  }
  const code = report.reduce((total, entry) => total + entry.code, 0);
  const supported = report.reduce((total, entry) => total + entry.supported, 0);
  console.log(JSON.stringify({ path, code, supported, percent: Math.round(supported / Math.max(code, 1) * 1000) / 10,
    segments: report.map(({ unsupported, ...rest }) => rest), unsupportedAddresses: report.flatMap(entry => entry.unsupported) }));
}
