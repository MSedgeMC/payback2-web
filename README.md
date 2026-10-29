# Payback 2 Web

[![CI](https://github.com/MSedgeMC/payback2-web/actions/workflows/ci.yml/badge.svg)](https://github.com/MSedgeMC/payback2-web/actions/workflows/ci.yml)

An independent browser/WebAssembly compatibility runtime for Payback 2.
Game files are supplied locally by the user and remain on their device.

**Status: early compatibility bring-up. Gameplay is not available yet.**
The original engine executes its first initialization routine through ARM64
emulation, then stops at the unimplemented `ExecuteProgram` call in its PairIP
dependency. Rendering, game input, and audio remain to be implemented.
The current browser interface provides compatibility and initialization diagnostics.

## Current capabilities

- ARM64 execution in WebAssembly inside a dedicated, bounded worker.
- Validated ELF64 loading, explicit BSS initialization, and supported AArch64 RELA relocations.
- Local APKM, ARM64 split APK, and engine-file import with baseline hash verification.
- Visible failures for unsupported inputs, memory access, and native calls.
- Synthetic unit and Chromium integration checks; no proprietary game data in CI.

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

The execution runtime is pinned and hash-verified. Heavy runtime compilation
is separate from ordinary application builds; the current build reuses an
immutable ARM64-only WASM package.

## License

Project source is licensed under **GPL-2.0-only**. Dependency notices are in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Payback 2 binaries, assets, and saves
are excluded and retain their original ownership.
