
import { readFileSync } from "node:fs";
import { decode } from "/root/.t3/projects/payback2-web/src/runtime/translate/arm64.ts";
const bytes = new Uint8Array(readFileSync(".local/dependencies/libpairipcore.so"));
const view = new DataView(bytes.buffer);
const bad = [];
for (let address = 0; address + 4 <= 0x79000; address += 4) {
  try { decode(address, view.getUint32(address, true)); } catch { bad.push(address); }
}
console.log(JSON.stringify(bad));
