export const SUPPORTED_GAME = {
  package: "net.apex_designs.payback2",
  version: "2.106.16",
  versionCode: 178,
  architecture: "arm64-v8a",
  engineBytes: 38_570_288,
  engineSha256: "bbb04c533f4f004d80b1460c18f6207be746d3c30fb828818b8bfc6efd23f5c7",
  pairipBytes: 525_424,
  pairipSha256: "e2caf73f534e90cd08405a5db1d11dc484b5d681ac2e0654421ea4816e2ea724",
} as const;

async function verifyLibrary(bytes: Uint8Array, expectedBytes: number, expectedHash: string, name: string): Promise<void> {
  if (bytes.byteLength !== expectedBytes) throw new Error(`Unsupported ${name} size; select the ARM64 files from Payback 2 2.106.16`);
  const digest = await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>);
  const hex = [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, "0")).join("");
  if (hex !== expectedHash) throw new Error(`Unsupported ${name} hash; this build supports Payback 2 2.106.16 (ARM64) only`);
}

export function verifyEngine(bytes: Uint8Array): Promise<void> {
  return verifyLibrary(bytes, SUPPORTED_GAME.engineBytes, SUPPORTED_GAME.engineSha256, "engine");
}

export function verifyPairip(bytes: Uint8Array): Promise<void> {
  return verifyLibrary(bytes, SUPPORTED_GAME.pairipBytes, SUPPORTED_GAME.pairipSha256, "PairIP dependency");
}
