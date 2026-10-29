import ts from "typescript";

export function wasmPayloads(source) {
  const file = ts.createSourceFile("runtime.js", source, ts.ScriptTarget.ES2022, false, ts.ScriptKind.JS);
  if (file.parseDiagnostics.length) throw new Error("Invalid JavaScript in public runtime output");
  const results = [];
  function visit(node) {
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && node.text.length > 4096) {
      // Emscripten SINGLE_FILE packs bytes into a Unicode string and decodes
      // each code unit with (~c >> 8) & c. Inspect the exact decoded bytes.
      const bytes = new Uint8Array(node.text.length);
      for (let index = 0; index < bytes.length; index++) {
        const code = node.text.charCodeAt(index); bytes[index] = (~code >> 8) & code;
      }
      if (bytes[0] === 0 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d) results.push(bytes);
      else throw new Error("Unapproved large string payload in public JavaScript");
    }
    ts.forEachChild(node, visit);
  }
  visit(file);
  return results;
}
