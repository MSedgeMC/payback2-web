export function parseJavaMethod(descriptor: string): { parameters: string[]; result: string } {
  if (descriptor.length > 256 || descriptor[0] !== "(") throw new Error("Invalid Java method descriptor");
  let cursor = 1;
  const readType = (allowVoid: boolean): string => {
    const start = cursor;
    while (descriptor[cursor] === "[") cursor++;
    const array = cursor !== start, tag = descriptor[cursor++];
    if (tag === "L") {
      const end = descriptor.indexOf(";", cursor), name = descriptor.slice(cursor, end);
      if (end < cursor || !/^[A-Za-z_$][\w$]*(?:\/[A-Za-z_$][\w$]*)*$/.test(name)) throw new Error("Invalid Java object descriptor");
      cursor = end + 1;
    } else if (!tag || !"ZBCSIJFD".includes(tag) && !(allowVoid && !array && tag === "V")) throw new Error("Invalid Java type descriptor");
    return descriptor.slice(start, cursor);
  };
  const parameters: string[] = [];
  while (cursor < descriptor.length && descriptor[cursor] !== ")") parameters.push(readType(false));
  if (descriptor[cursor++] !== ")") throw new Error("Unterminated Java method descriptor");
  const result = readType(true);
  if (cursor !== descriptor.length) throw new Error("Trailing Java method descriptor data");
  return { parameters, result };
}

export function javaTypeWords(type: string): number { return type === "J" || type === "D" ? 2 : 1; }
