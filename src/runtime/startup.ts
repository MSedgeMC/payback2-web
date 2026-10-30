import type { RuntimeAdapter } from "./adapter.ts";
import type { ElfImage } from "./elf.ts";
import type { DexFile } from "./dex.ts";
import type { BoundedZip } from "../assets/importer.ts";
import { NativeSession } from "./initialize.ts";
import type { ExecutionLimits, InitializationProbe, NativeCallProbe, SliceObserver } from "./initialize.ts";
import { JniEnvironment, isSupportedJniVersion } from "./jni.ts";

export type GameStartupProbe = {
  stage: "dependency-constructors" | "dependency-jni" | "engine-constructors";
  result: InitializationProbe | NativeCallProbe;
  dependencyInitializers?: InitializationProbe;
  dependencyJni?: NativeCallProbe;
};

export async function probeGameStartup(cpu: RuntimeAdapter, engine: ElfImage, pairip?: ElfImage,
                                      java?: { dex: DexFile; base?: BoundedZip }, limits?: ExecutionLimits,
                                      observe?: SliceObserver): Promise<GameStartupProbe> {
  if (!pairip) {
    const session = new NativeSession(cpu);
    try {
      const loaded = session.load("libpayback2.so", engine, 0x10000000n);
      return { stage: "engine-constructors", result: await session.initializeAsync(loaded, limits, observe) };
    } finally { session.dispose(); }
  }
  const session = new NativeSession(cpu);
  let jni: JniEnvironment | undefined;
  try {
    jni = new JniEnvironment(cpu, session.imports);
    if (java) jni.attachBytecode(java.dex, java.base, name => session.isLibraryInitialized(name));
    const core = session.load("libpairipcore.so", pairip, 0x20000000n);
    const dependencyInitializers = await session.initializeAsync(core, limits);
    if (dependencyInitializers.status !== "initializers-returned") {
      return { stage: "dependency-constructors", result: dependencyInitializers };
    }
    const dependencyJni = await session.callAsync(core.lookupExport("JNI_OnLoad"), [jni.vmAddress, 0n]);
    if (dependencyJni.status !== "returned") return { stage: "dependency-jni", result: dependencyJni, dependencyInitializers };
    const version = Number(BigInt.asIntN(32, dependencyJni.registers.x0));
    if (!isSupportedJniVersion(version)) throw new Error(`Dependency JNI_OnLoad returned an unsupported version: ${version}`);
    const loaded = session.load("libpayback2.so", engine, 0x10000000n);
    return { stage: "engine-constructors", result: await session.initializeAsync(loaded, limits, observe), dependencyInitializers, dependencyJni };
  } finally { jni?.dispose(); session.dispose(); }
}
