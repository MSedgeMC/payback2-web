export type EngineRequest = { kind: "check" } | { kind: "import"; file: File };
export type EngineResponse =
  | { kind: "status"; text: string }
  | { kind: "checked"; runtime: string; wasmMemoryBytes: number }
  | { kind: "initialized"; status: string; diagnostic: string }
  | { kind: "error"; message: string };
