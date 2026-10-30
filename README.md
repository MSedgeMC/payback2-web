# Payback 2 Web

[![CI](https://github.com/MSedgeMC/payback2-web/actions/workflows/ci.yml/badge.svg)](https://github.com/MSedgeMC/payback2-web/actions/workflows/ci.yml)

An independent WebAssembly compatibility runtime for running Payback 2 in a
desktop browser. Users supply their own game files locally; those files remain
on their device.

**Status: experimental native startup. Gameplay is not available yet.**
The original native dependency completes initialization, registers its Java
native method, and returns JNI version 1.6. The main engine then enters its own
constructors and calls into the protected dependency's virtual machine, which
runs a self-integrity hash over its own code, reads its process map, and starts
native threads. Execution currently stops on an unsynchronised condition
variable wait (`pthread_cond_wait`). Engine initialization, rendering, gameplay
input, and audio remain unfinished.

Measured execution throughput is the project's largest open problem: the
AArch64 interpreter reaches roughly 1.5 million guest instructions per second,
about three orders of magnitude below what a real-time 3D frame requires. See
`docs/PERFORMANCE.md`.

The browser interface reports loading and compatibility diagnostics. It does
not yet provide a playable scene.

## Current capabilities

- ARM64 execution in WebAssembly inside a dedicated worker with bounded execution.
- Validated ELF64 loading, BSS initialization, AArch64 RELA relocations, and native dependency linking.
- Local APKM and ARM64 split APK import with verification against the supported engine, dependency, and startup bytecode.
- JNI class and method lookup, native registration, typed references, strings, arrays, byte regions, constructors, and the instance call family.
- Direct guest kernel syscalls (clock, identity, descriptors, process map, entropy) with unimplemented numbers reported by name.
- A read-only guest file system over the user's package, and cooperative native threads.
- Explicit diagnostics for unsupported inputs, memory access, and native or Java calls.
- Unit and Chromium integration checks using synthetic fixtures; game data is excluded from CI.

The supported baseline is **Payback 2 2.106.16, version code 178, ARM64**.
Other versions and architectures are rejected.

## Development

Use Node.js **22.23.4** and the committed npm lockfile.

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
npm run dev
```

The production build is a static application in `dist/`. Serve it over HTTPS
or localhost. It requires a current desktop browser with WebAssembly, BigInt,
workers, and native decompression streams. No server receives game files.

The build uses a verified ARM64-only runtime release compiled with
Emscripten **4.0.23**. Preparation downloads the runtime and its build metadata
once, verifies their hashes, and reuses the local cache. Heavy runtime compilation
is separate from ordinary application builds. Execution code is bundled with
the static application.

## License

Project source is licensed under **GPL-2.0-only**. Dependency notices are in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Payback 2 binaries, assets, and saves
are excluded and retain their original ownership.
