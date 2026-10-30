import type { RuntimeAdapter } from "./adapter.ts";
import { readDouble, readDoublePair, writeDouble } from "./aarch64-fp.ts";

// libm compatibility. AArch64 passes doubles in d0/d1 and returns in d0.
// Functions marked exact are fully specified by IEEE-754, so the JavaScript result is
// identical to bionic's. The transcendental entries delegate to the host JavaScript
// math library; their results follow that implementation and may differ in the last bit.
export type LibmHandler = (cpu: RuntimeAdapter) => void;

const unary = (apply: (value: number) => number): LibmHandler => cpu => writeDouble(cpu, 0, apply(readDouble(cpu, 0)));
const binary = (apply: (left: number, right: number) => number): LibmHandler =>
  cpu => { const [left, right] = readDoublePair(cpu); writeDouble(cpu, 0, apply(left, right)); };

/** C `round`: halfway cases round away from zero. */
const roundHalfAwayFromZero = (value: number): number => value < 0 ? -Math.round(-value) : Math.round(value);

// C fmin/fmax return the non-NaN operand when exactly one argument is NaN.
const minimum = (left: number, right: number): number =>
  Number.isNaN(left) ? right : Number.isNaN(right) ? left : Math.min(left, right);
const maximum = (left: number, right: number): number =>
  Number.isNaN(left) ? right : Number.isNaN(right) ? left : Math.max(left, right);

/** copysign reads the raw sign bit so signed zero and NaN signs are preserved. */
const copySign = (cpu: RuntimeAdapter): void => {
  const [magnitude, sign] = readDoublePair(cpu);
  const view = new DataView(new ArrayBuffer(16));
  view.setFloat64(0, magnitude, true); view.setFloat64(8, sign, true);
  view.setUint32(4, (view.getUint32(4, true) & 0x7fffffff) | (view.getUint32(12, true) & 0x80000000), true);
  writeDouble(cpu, 0, view.getFloat64(0, true));
};

const handlers: Record<string, LibmHandler> = {
  // Exact: IEEE-754 and C99 specify these results completely.
  fabs: unary(Math.abs), sqrt: unary(Math.sqrt), floor: unary(Math.floor), ceil: unary(Math.ceil),
  trunc: unary(Math.trunc), fmod: binary((left, right) => left % right),
  fmin: binary(minimum), fmax: binary(maximum), copysign: copySign,
  fdim: binary((left, right) => Number.isNaN(left) || Number.isNaN(right) ? NaN : left > right ? left - right : 0),
  round: unary(roundHalfAwayFromZero),
  // Host transcendental implementations; documented as approximately bionic.
  sin: unary(Math.sin), cos: unary(Math.cos), tan: unary(Math.tan),
  asin: unary(Math.asin), acos: unary(Math.acos), atan: unary(Math.atan),
  sinh: unary(Math.sinh), cosh: unary(Math.cosh), tanh: unary(Math.tanh),
  asinh: unary(Math.asinh), acosh: unary(Math.acosh), atanh: unary(Math.atanh),
  exp: unary(Math.exp), expm1: unary(Math.expm1), log: unary(Math.log), log1p: unary(Math.log1p),
  log2: unary(Math.log2), log10: unary(Math.log10), cbrt: unary(Math.cbrt),
  pow: binary(Math.pow), atan2: binary(Math.atan2),
};

export function libmHandler(name: string): LibmHandler | undefined { return handlers[name]; }
export const libmNames = Object.keys(handlers);
