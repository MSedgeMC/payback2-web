// Synthetic instructions only, encoded from the A64 instruction format.
export function words(...instructions: number[]): Uint8Array {
  const bytes = new Uint8Array(instructions.length * 4);
  const view = new DataView(bytes.buffer);
  instructions.forEach((instruction, index) => view.setUint32(index * 4, instruction, true));
  return bytes;
}

export const integerArithmetic = words(
  0xd28006e0, // mov x0, #0x37
  0xd2800441, // mov x1, #0x22
  0x8b010002, // add x2, x0, x1
  0xd65f03c0, // ret
);

export const integerLoop = words(
  0x91000421, // add x1, x1, #1
  0xf1000400, // subs x0, x0, #1
  0x54ffffc1, // b.ne -8
  0xd65f03c0,
);

export const memoryLoop = words(
  0xf9400022, // ldr x2, [x1]
  0x91000442, // add x2, x2, #1
  0xf9000022, // str x2, [x1]
  0xf1000400, // subs x0, x0, #1
  0x54ffff81, // b.ne -16
  0xd65f03c0,
);

export const vectorAdd = words(
  0x4ea18402, // add v2.4s, v0.4s, v1.4s
  0xd65f03c0,
);

export const vectorLoop = words(
  0x4ea18400, // add v0.4s, v0.4s, v1.4s
  0xf1000400,
  0x54ffffc1,
  0xd65f03c0,
);

export const hostCallLoop = words(
  0xd4000021, // svc #1
  0x91000421,
  0xf1000400,
  0x54ffffa1, // b.ne -12
  0xd65f03c0,
);
