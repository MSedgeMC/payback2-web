import { readPackageEngine } from "../assets/importer.ts";
import { verifyEngine } from "../assets/baseline.ts";
import { parseElf } from "../runtime/elf.ts";
import { probeInitialization } from "../runtime/initialize.ts";
import { createRuntime } from "../runtime/unicorn.ts";
import { checkRuntime } from "../runtime/self-test.ts";
import type { RuntimeAdapter } from "../runtime/adapter.ts";
import type { EngineRequest, EngineResponse } from "./messages.ts";

const scope = self as unknown as { postMessage(message: EngineResponse): void; onmessage: ((event: MessageEvent<EngineRequest>) => void) | null };
let busy = false;
scope.onmessage = async (event): Promise<void> => {
  if (busy) { scope.postMessage({ kind: "error", message: "An engine operation is already running" }); return; }
  busy = true;
  let cpu: RuntimeAdapter | undefined;
  try {
    if (event.data.kind === "check") {
      cpu = await createRuntime();
      const result = checkRuntime(cpu);
      scope.postMessage({ kind: "checked", runtime: result.name, wasmMemoryBytes: result.wasmMemoryBytes });
    } else if (event.data.kind === "import" && event.data.file instanceof File) {
      scope.postMessage({ kind: "status", text: "Reading local package and checking engine identity…" });
      const bytes = await readPackageEngine(event.data.file);
      await verifyEngine(bytes);
      const image = parseElf(bytes);
      scope.postMessage({ kind: "status", text: "Running bounded engine initialization…" });
      cpu = await createRuntime();
      const result = probeInitialization(cpu, image);
      const status = result.blockedSymbol ? `Initialization stopped at unimplemented native call: ${result.blockedSymbol}` : `Initialization diagnostic: ${result.status}`;
      const serialize = (_key: string, value: unknown): unknown => typeof value === "bigint" ? `0x${value.toString(16)}` : value;
      scope.postMessage({ kind: "initialized", status, diagnostic: JSON.stringify(result, serialize, 2) });
    } else throw new Error("Invalid engine worker request");
  } catch (error) { scope.postMessage({ kind: "error", message: String(error instanceof Error ? error.message : error).slice(0, 800) }); }
  finally { cpu?.close(); busy = false; }
};
