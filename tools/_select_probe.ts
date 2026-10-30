import { Code, I64, OP, buildModule } from "../src/runtime/translate/wasm.ts";
// Empirically confirm WASM select ordering: push valueA, valueB, condition.
for (const condition of [1, 0]) {
  const body = new Code();
  body.i32(0);
  body.i64(11n); body.i64(22n); body.i32(condition); body.raw(OP.select);
  body.store("i64", 0);
  const bytes = buildModule(body, [{ count: 0, type: I64 }], 1);
  const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer));
  (instance.exports.run as () => void)();
  console.log(`values (11, 22) cond=${condition} =>`, new DataView((instance.exports.memory as WebAssembly.Memory).buffer).getBigUint64(0, true));
}
