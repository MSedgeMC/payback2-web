import { translate } from "../src/runtime/translate/translate.ts";

// Translates each instruction prefix in turn and reports the first prefix that fails to
// compile, which localises emitter stack bugs without reading WASM bytes by hand.
const words = process.argv.slice(2).map(value => Number(value));
if (!words.length) throw new Error("Pass instruction words as hex, e.g. 0x91000421");
const bytes = new Uint8Array(words.length * 4);
const view = new DataView(bytes.buffer);
words.forEach((word, index) => view.setUint32(index * 4, word >>> 0, true));
for (let count = 1; count <= words.length; count++) {
  const end = count * 4;
  const label = words.slice(0, count).map(word => `0x${(word >>> 0).toString(16)}`).join(" ");
  try {
    const result = translate(bytes, 0, end);

    if (result.unsupported.length) console.log(`prefix ${count}: unsupported at ${result.unsupported.map(site => "0x" + site.address.toString(16)).join(",")}`);
    else console.log(`prefix ${count}: ok  [${label}]`);
  } catch (error) {
    console.log(`prefix ${count}: FAIL [${label}] -> ${(error as Error).message}`);
    break;
  }
}
