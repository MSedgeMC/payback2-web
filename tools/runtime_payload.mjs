import ts from "typescript";

export function wasmPayloads(source) {
  const file = ts.createSourceFile("runtime.js", source, ts.ScriptTarget.ES2022, false, ts.ScriptKind.JS);
  if (file.parseDiagnostics.length) throw new Error("Invalid JavaScript in public runtime output");
  const results = [];
  function visit(node) {
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && node.text.length > 4096) {
      let bytes;
      const dataUrl = /^data:application\/(?:octet-stream|wasm);base64,(.*)$/.exec(node.text);
      if (dataUrl) {
        const encoded = dataUrl[1];
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4) throw new Error("Invalid WASM base64 payload");
        bytes = new Uint8Array(Buffer.from(encoded, "base64"));
        if (Buffer.from(bytes).toString("base64") !== encoded) throw new Error("Noncanonical WASM base64 payload");
      } else {
        // Packed SINGLE_FILE releases decode each Unicode code unit with (~c >> 8) & c.
        bytes = new Uint8Array(node.text.length);
        for (let index = 0; index < bytes.length; index++) {
          const code = node.text.charCodeAt(index); bytes[index] = (~code >> 8) & code;
        }
      }
      if (bytes[0] === 0 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d) results.push(bytes);
      else throw new Error("Unapproved large string payload in public JavaScript");
    }
    ts.forEachChild(node, visit);
  }
  visit(file);
  return results;
}
