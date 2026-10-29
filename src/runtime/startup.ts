import type { RuntimeAdapter } from "./adapter.ts";
import type { ElfImage } from "./elf.ts";
import { NativeSession, probeInitialization } from "./initialize.ts";
import type { InitializationProbe, NativeCallProbe } from "./initialize.ts";
import { JniEnvironment, isSupportedJniVersion } from "./jni.ts";

export type GameStartupProbe = {
  stage: "dependency-constructors" | "dependency-jni" | "engine-constructors";
  result: InitializationProbe | NativeCallProbe;
  dependencyInitializers?: InitializationProbe;
  dependencyJni?: NativeCallProbe;
};

export function probeGameStartup(cpu: RuntimeAdapter, engine: ElfImage, pairip?: ElfImage): GameStartupProbe {
  if (!pairip) return { stage: "engine-constructors", result: probeInitialization(cpu, engine) };
  const session = new NativeSession(cpu);
  let jni: JniEnvironment | undefined;
  try {
    jni = new JniEnvironment(cpu, session.imports);
    const core = session.load("libpairipcore.so", pairip, 0x20000000n);
    const dependencyInitializers = session.initialize(core);
    if (dependencyInitializers.status !== "initializers-returned") {
      return { stage: "dependency-constructors", result: dependencyInitializers };
    }
    const dependencyJni = session.call(core.lookupExport("JNI_OnLoad"), [jni.vmAddress, 0n]);
    if (dependencyJni.status !== "returned") return { stage: "dependency-jni", result: dependencyJni, dependencyInitializers };
    const version = Number(BigInt.asIntN(32, dependencyJni.registers.x0));
    if (!isSupportedJniVersion(version)) throw new Error(`Dependency JNI_OnLoad returned an unsupported version: ${version}`);
    const loaded = session.load("libpayback2.so", engine, 0x10000000n);
    return { stage: "engine-constructors", result: session.initialize(loaded), dependencyInitializers, dependencyJni };
  } finally { jni?.dispose(); session.dispose(); }
}
