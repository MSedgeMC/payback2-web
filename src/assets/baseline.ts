export const SUPPORTED_GAME = {
  package: "net.apex_designs.payback2",
  version: "2.106.16",
  versionCode: 178,
  architecture: "arm64-v8a",
  engineBytes: 38_570_288,
  engineSha256: "bbb04c533f4f004d80b1460c18f6207be746d3c30fb828818b8bfc6efd23f5c7",
} as const;

export async function verifyEngine(bytes: Uint8Array): Promise<void> {
  if (bytes.byteLength !== SUPPORTED_GAME.engineBytes) throw new Error("Unsupported engine size; select the ARM64 engine from Payback 2 2.106.16");
  const digest = await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>);
  const hex = [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, "0")).join("");
  if (hex !== SUPPORTED_GAME.engineSha256) throw new Error("Unsupported engine hash; this build supports Payback 2 2.106.16 (ARM64) only");
}
