import "./styles.css";
import type { EngineRequest, EngineResponse } from "./workers/messages.ts";

const game = document.querySelector<HTMLInputElement>("#game")!;
const check = document.querySelector<HTMLButtonElement>("#check")!;
const stop = document.querySelector<HTMLButtonElement>("#stop")!;
const status = document.querySelector<HTMLParagraphElement>("#status")!;
const details = document.querySelector<HTMLPreElement>("#details")!;
let worker: Worker | undefined;
let deadline: ReturnType<typeof setTimeout> | undefined;

function release(): void {
  clearTimeout(deadline); deadline = undefined;
  worker?.terminate(); worker = undefined;
  check.disabled = false; game.disabled = false; stop.disabled = true;
}

function start(request: EngineRequest): void {
  release(); details.textContent = "";
  check.disabled = true; game.disabled = true; stop.disabled = false;
  status.textContent = request.kind === "check" ? "Checking ARM64 execution in a worker…" : "Opening local game files…";
  try { worker = new Worker(new URL("./workers/engine.worker.ts", import.meta.url), { type: "module" }); }
  catch (error) { status.textContent = `Worker startup failed: ${String(error)}`; release(); return; }
  worker.onmessage = (event: MessageEvent<EngineResponse>): void => {
    const response = event.data;
    if (response.kind === "status") { status.textContent = response.text; return; }
    if (response.kind === "checked") {
      status.textContent = "ARM64 execution check passed. Gameplay is still under development.";
      details.textContent = `${response.runtime}\nWASM memory: ${(response.wasmMemoryBytes / 1024 / 1024).toFixed(1)} MiB`;
    } else if (response.kind === "initialized") {
      status.textContent = response.status; details.textContent = response.diagnostic;
    } else if (response.kind === "error") status.textContent = response.message;
    release();
  };
  worker.onerror = (event): void => { status.textContent = `Engine worker failed: ${event.message}`; release(); };
  deadline = setTimeout(() => { release(); status.textContent = "Operation stopped after its 30-second deadline"; }, 30_000);
  worker.postMessage(request);
}

check.addEventListener("click", () => start({ kind: "check" }));
game.addEventListener("change", () => {
  const file = game.files?.[0]; game.value = "";
  if (file) start({ kind: "import", file });
});
stop.addEventListener("click", () => { release(); status.textContent = "Stopped"; });
document.addEventListener("visibilitychange", () => {
  if (document.hidden && worker) { release(); status.textContent = "Paused while this tab is hidden. Select your files to restart."; }
});
window.addEventListener("pagehide", release);
