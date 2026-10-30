import type { RuntimeAdapter } from "./adapter.ts";
import type { NativeDispatch } from "./symbols.ts";
import { readGuestBytes, writeGuestBytes } from "./guest-memory.ts";

// arm64 Linux syscall numbers, verified against asm-generic/unistd.h (the arm64 table).
// Native imports reach the host through SVC traps; a direct `svc #0` is guest code issuing
// a raw kernel call, which happens in the protected dependency rather than in libc.
export const SYS = {
  gettimeofday: 169, clock_gettime: 113, clock_getres: 114, getpid: 172, gettid: 178, set_tid_address: 96,
} as const;

// Only numbers that this module can name; unknown numbers stay visible as their index.
const names: Record<number, string> = {
  19: "eventfd2", 20: "epoll_create1", 29: "ioctl", 56: "openat", 57: "close", 63: "read", 64: "write",
  93: "exit", 94: "exit_group", 96: "set_tid_address", 98: "futex", 101: "nanosleep", 113: "clock_gettime",
  114: "clock_getres", 115: "clock_nanosleep", 124: "sched_yield", 131: "tgkill", 135: "rt_sigprocmask",
  160: "uname", 167: "prctl", 169: "gettimeofday", 172: "getpid", 173: "getppid", 174: "getuid", 178: "gettid",
  214: "brk", 215: "munmap", 216: "mremap", 222: "mmap", 226: "mprotect", 233: "madvise", 260: "wait4",
  278: "getrandom", 48: "faccessat", 79: "newfstatat", 80: "fstat", 61: "getdents64",
};

const SVC_ZERO = 0xd4000001;
const CLOCK_REALTIME = 0, CLOCK_REALTIME_COARSE = 5, CLOCK_REALTIME_ALARM = 8;
const EINVAL = 22;

type Timespec = { seconds: number; nanoseconds: number };

function monotonicTimespec(): Timespec {
  const value = performance.now(), seconds = Math.floor(value / 1000);
  return { seconds, nanoseconds: Math.round((value - seconds * 1000) * 1e6) };
}

function realtimeTimespec(): Timespec {
  const value = Date.now(), seconds = Math.floor(value / 1000);
  return { seconds, nanoseconds: (value - seconds * 1000) * 1e6 };
}

export function syscallName(number: number): string { return names[number] ?? `syscall_${number}`; }

/**
 * Dispatches guest `svc #0` calls. Returns false when the interrupt was not a raw
 * syscall or when the number has no compatibility implementation, so the caller can
 * report a bounded diagnostic instead of inventing success.
 */
export class GuestSyscalls {
  private readonly cpu: RuntimeAdapter;
  private blocked: string | undefined;
  private disposed = false;

  constructor(cpu: RuntimeAdapter) { this.cpu = cpu; }

  /** Name of the last raw syscall that had no implementation, for diagnostics. */
  get unsupportedSyscall(): string | undefined { return this.blocked; }

  handle(pc: bigint): NativeDispatch {
    if (this.disposed) throw new Error("Guest syscalls are disposed");
    this.blocked = undefined;
    if (pc < 4n || !this.isRawSyscall(pc - 4n)) return false;
    const number = Number(BigInt.asUintN(32, this.cpu.readRegister("x8")));
    if (!this.dispatch(number)) { this.blocked = syscallName(number); return false; }
    this.cpu.writeRegister("pc", this.cpu.readRegister("x30"));
    return true;
  }

  private isRawSyscall(address: bigint): boolean {
    try {
      const bytes = readGuestBytes(this.cpu, address, 4);
      return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true) === SVC_ZERO;
    } catch { return false; }
  }

  private dispatch(number: number): boolean {
    if (number === SYS.clock_gettime) return this.clockGetTime();
    if (number === SYS.clock_getres) return this.clockGetRes();
    if (number === SYS.gettimeofday) return this.getTimeOfDay();
    // Each isolated worker hosts one guest process with one thread.
    if (number === SYS.getpid || number === SYS.gettid || number === SYS.set_tid_address) {
      this.cpu.writeRegister("x0", number === SYS.set_tid_address ? 0n : 1n);
      return true;
    }
    return false;
  }

  private clockGetTime(): boolean {
    const clock = Number(BigInt.asIntN(32, this.cpu.readRegister("x0")));
    const target = this.cpu.readRegister("x1");
    const value = this.clockValue(clock);
    if (!value) { this.cpu.writeRegister("x0", BigInt(-EINVAL)); return true; }
    this.writeTimespec(target, value);
    this.cpu.writeRegister("x0", 0n);
    return true;
  }

  private clockGetRes(): boolean {
    const clock = Number(BigInt.asIntN(32, this.cpu.readRegister("x0")));
    const target = this.cpu.readRegister("x1");
    if (!this.clockValue(clock)) { this.cpu.writeRegister("x0", BigInt(-EINVAL)); return true; }
    // The browser clock is millisecond-quantised; report that resolution honestly.
    this.writeTimespec(target, { seconds: 0, nanoseconds: 1e6 });
    this.cpu.writeRegister("x0", 0n);
    return true;
  }

  private getTimeOfDay(): boolean {
    const target = this.cpu.readRegister("x0");
    // struct timeval { time_t tv_sec; suseconds_t tv_usec; } with a 64-bit time_t.
    if (target !== 0n) this.writeTimespec(target, realtimeTimespec(), true);
    this.cpu.writeRegister("x0", 0n);
    return true;
  }

  private clockValue(clock: number): Timespec | undefined {
    if (clock === CLOCK_REALTIME || clock === CLOCK_REALTIME_COARSE || clock === CLOCK_REALTIME_ALARM) return realtimeTimespec();
    // shortcut: process and thread CPU time report wall time until guest CPU accounting exists.
    if (clock >= 1 && clock <= 7) return monotonicTimespec();
    return undefined;
  }

  /** Writes a 64-bit timespec, or a 64-bit timeval when `microseconds` is set. */
  private writeTimespec(address: bigint, value: Timespec, microseconds = false): void {
    if (address === 0n) throw new RangeError("Guest clock pointer is null");
    const bytes = new Uint8Array(16), view = new DataView(bytes.buffer);
    view.setBigInt64(0, BigInt(value.seconds), true);
    view.setBigInt64(8, BigInt(microseconds ? Math.floor(value.nanoseconds / 1000) : value.nanoseconds), true);
    writeGuestBytes(this.cpu, address, bytes);
  }

  dispose(): void { this.disposed = true; this.blocked = undefined; }
}
