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

## Consequence for gameplay

1.5 MIPS is roughly three orders of magnitude short of a real-time 3D frame. The
interpreter cannot deliver playable frames; compatibility work continues first
because a frame must exist before it can be measured, but replacing the core is
a prerequisite for the gameplay milestone.

## Where the time actually goes

The largest single startup cost is the protected dependency's FNV-1a self-integrity
hash over its own 408 KB `.text` (about 2.9M guest instructions, ~6 s at the
interpreter's rate). That work is inherent to the dependency, not to our loader.

Raw measurements: `.local/engine-probe.json`, `.local/trace-execution.json`,
`.local/engine-routine-benchmark.json`.
