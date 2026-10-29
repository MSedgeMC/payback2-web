import type { DexMethodReference } from "./dex.ts";

export type JavaDatum = JavaValue | number | bigint | null;
export type JavaValue = { kind: "class"; name: string } | { kind: "string"; value: string }
  | { kind: "object-array"; elements: (JavaValue | null)[]; elementClass?: string }
  | { kind: "boxed-long"; value: bigint } | { kind: "byte-array"; bytes: Uint8Array }
  | { kind: "instance"; className: string; fields: Map<string, JavaDatum> };
export type JavaRequest = { kind: "native"; method: DexMethodReference; isStatic: boolean; args: JavaDatum[] }
  | { kind: "wait"; ready: Promise<JavaDatum> };
export type JavaExecution = Generator<JavaRequest, JavaDatum, JavaDatum>;

export function javaClassName(value: JavaValue): string {
  if (value.kind === "class") return "java/lang/Class";
  if (value.kind === "string") return "java/lang/String";
  if (value.kind === "boxed-long") return "java/lang/Long";
  if (value.kind === "byte-array") return "[B";
  if (value.kind === "object-array") return `[L${value.elementClass ?? "java/lang/Object"};`;
  return value.className;
}

export class JavaThrown extends Error {
  readonly value: JavaValue;
  constructor(value: JavaValue) { super(`Java exception: ${javaClassName(value)}`); this.value = value; }
}
