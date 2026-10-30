# Performance measurements

Local VPS measurements under `tools/resource_guard.py`. Not browser, game-frame,
or device numbers.

## Execution core throughput

`node tools/benchmark_runtime.ts`, Unicorn 2.x AArch64 WASM build (TCI interpreter),
Node 22.23.4, 100,000-instruction slices:

| Mix | MIPS |
| --- | --- |
| integer and branch | 1.78 |
| load, store, integer and branch | 1.45 |
| SIMD and branch | 1.63 |
| native host call | 17.7 µs per call |

Measured through real startup (80M-instruction budget, 20,000-instruction slices):
~2.3 s wall time, 89.8 MiB WASM memory. Slice overhead is ~0.3 ms per `run()`
entry, so 500-instruction slices lose about half the time to it; startup uses
20,000-instruction slices to keep that near 2%.

## Ahead-of-time translation to WebAssembly

`src/runtime/translate/` decodes AArch64 and emits a WASM module whose basic blocks
are dispatched by an in-module `br_table` loop, so a hot loop pays no host boundary
crossing per instruction or per block. Measured with `node tools/benchmark_translate.ts`
(50,000,000 iterations, same fixtures as the interpreter table):

| Mix | Interpreted | Translated | Speedup |
| --- | --- | --- | --- |
| integer and branch | 1.78 MIPS | 1,950 MIPS | ~1,100x |
| load, store, integer and branch | 1.45 MIPS | 2,653 MIPS | ~1,800x |

This removes the interpreter as the blocking constraint: the translated core is fast
enough that a 3D frame becomes a question of how much work the game does, not of
instruction dispatch.

**This is an upper bound, not a frame-rate promise.** The fixtures are tight loops
with registers in WASM locals, no indirect branches, no host calls, no
floating-point or SIMD. Real engine code will be slower, and the translator
currently covers a small 64-bit integer subset (arithmetic, compare, branch,
load/store, move-wide, return). Everything else falls back with the address reported
in `TranslationResult.unsupported`.

## Consequence for gameplay

The interpreted path (1.5 MIPS) could never deliver a frame. The translated path
can, so the remaining work is coverage and integration rather than a different
execution strategy.

## Where the time actually goes

The largest single startup cost is the protected dependency's FNV-1a self-integrity
hash over its own 408 KB `.text` (about 2.9M guest instructions, ~6 s at the
interpreter's rate). That work is inherent to the dependency, not to our loader.

Raw measurements: `.local/engine-probe.json`, `.local/trace-execution.json`,
`.local/engine-routine-benchmark.json`.
