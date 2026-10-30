import type { RuntimeAdapter } from "./adapter.ts";
import type { NativeDispatch } from "./symbols.ts";
import { readCString, readGuestBytes, writeGuestBytes } from "./guest-memory.ts";

// arm64 Linux syscall numbers, verified against asm-generic/unistd.h (the arm64 table).
// Native imports reach the host through SVC traps; a direct `svc #0` is guest code issuing
// a raw kernel call, which happens in the protected dependency rather than in libc.
export const SYS = {
  gettimeofday: 169, clock_gettime: 113, clock_getres: 114, getpid: 172, gettid: 178, set_tid_address: 96,
  openat: 56, close: 57, read: 63, lseek: 62, faccessat: 48, newfstatat: 79, readlinkat: 78,
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
const EBADF = 9, EFAULT = 14, EINVAL = 22, ENOENT = 2;

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
  /** Environment facts the guest was told about, kept visible rather than silent. */
  private readonly noticeList: string[] = [];
  /** Open descriptors over synthetic in-process files; the browser guest has no kernel file tree. */
  private readonly descriptors = new Map<number, { path: string; bytes: Uint8Array; position: number }>();
  private nextDescriptor = 3;
  private disposed = false;

  constructor(cpu: RuntimeAdapter) { this.cpu = cpu; }

  /** Name of the last raw syscall that had no implementation, for diagnostics. */
  get unsupportedSyscall(): string | undefined { return this.blocked; }

  /** Bounded record of refusals the guest received as normal error codes. */
  get notices(): readonly string[] { return this.noticeList; }

  private notice(message: string): void {
    if (this.noticeList.length < 16 && !this.noticeList.includes(message)) this.noticeList.push(message);
  }

  handle(pc: bigint): NativeDispatch {
    if (this.disposed) throw new Error("Guest syscalls are disposed");
    this.blocked = undefined;
    if (pc < 4n || !this.isRawSyscall(pc - 4n)) return false;
    const number = Number(BigInt.asUintN(32, this.cpu.readRegister("x8")));
    if (!this.dispatch(number)) { this.blocked = `${syscallName(number)}${this.pathArgument(number)}`; return false; }
    this.cpu.writeRegister("pc", this.cpu.readRegister("x30"));
    return true;
  }

  /** Path-based syscalls report the requested path, so a refusal names the guest's target. */
  private pathArgument(number: number): string {
    if (![SYS.openat, SYS.faccessat, SYS.newfstatat, SYS.readlinkat].includes(number as never)) return "";
    try { return `(${new TextDecoder().decode(readCString(this.cpu, this.cpu.readRegister("x1"), 256))})`; } catch { return ""; }
  }

  private isRawSyscall(address: bigint): boolean {
    try {
      const bytes = readGuestBytes(this.cpu, address, 4);
      return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true) === SVC_ZERO;
    } catch { return false; }
  }

  private dispatch(number: number): boolean {
    if (number === SYS.openat) return this.openAt();
    if (number === SYS.close) return this.close();
    if (number === SYS.read) return this.read();
    if (number === SYS.lseek) return this.seek();
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

  /**
   * Resolves a guest path. `/proc/self/maps` is rendered from this runtime's own region
   * table, so the guest sees a truthful description of its address space rather than an
   * invented one. Any other path has no backing store and reports ENOENT.
   */
  private virtualFile(path: string): Uint8Array | undefined {
    if (path !== "/proc/self/maps" && path !== "/proc/self/smaps") return undefined;
    const lines = this.cpu.regions.map(region => {
      const permissions = `${region.permissions & 1 ? "r" : "-"}${region.permissions & 2 ? "w" : "-"}${region.permissions & 4 ? "x" : "-"}p`;
      const start = region.address.toString(16).padStart(8, "0"), end = (region.address + region.size).toString(16).padStart(8, "0");
      return `${start}-${end} ${permissions} 00000000 00:00 0 `;
    });
    return new TextEncoder().encode(lines.length ? `${lines.join("\n")}\n` : "");
  }

  private openAt(): boolean {
    let path = "";
    try { path = new TextDecoder().decode(readCString(this.cpu, this.cpu.readRegister("x1"), 256)); } catch { /* an unreadable path is still missing */ }
    const bytes = path ? this.virtualFile(path) : undefined;
    if (!bytes) {
      this.notice(`openat(${path || "<unreadable>"}) reported ENOENT`);
      this.cpu.writeRegister("x0", BigInt(-ENOENT));
      return true;
    }
    const descriptor = this.nextDescriptor++;
    this.descriptors.set(descriptor, { path, bytes, position: 0 });
    this.cpu.writeRegister("x0", BigInt(descriptor));
    return true;
  }

  private close(): boolean {
    const descriptor = Number(BigInt.asIntN(32, this.cpu.readRegister("x0")));
    if (!this.descriptors.delete(descriptor)) { this.cpu.writeRegister("x0", BigInt(-EBADF)); return true; }
    this.cpu.writeRegister("x0", 0n);
    return true;
  }

  private read(): boolean {
    const descriptor = Number(BigInt.asIntN(32, this.cpu.readRegister("x0"))), file = this.descriptors.get(descriptor);
    if (!file) { this.cpu.writeRegister("x0", BigInt(-EBADF)); return true; }
    const count = Number(BigInt.asUintN(64, this.cpu.readRegister("x2")));
    if (!Number.isSafeInteger(count) || count < 0) { this.cpu.writeRegister("x0", BigInt(-EINVAL)); return true; }
    const available = Math.min(count, file.bytes.length - file.position);
    const chunk = file.bytes.subarray(file.position, file.position + available);
    try { writeGuestBytes(this.cpu, this.cpu.readRegister("x1"), chunk); }
    catch { this.cpu.writeRegister("x0", BigInt(-EFAULT)); return true; }
    file.position += available;
    this.cpu.writeRegister("x0", BigInt(available));
    return true;
  }

  private seek(): boolean {
    const descriptor = Number(BigInt.asIntN(32, this.cpu.readRegister("x0"))), file = this.descriptors.get(descriptor);
    if (!file) { this.cpu.writeRegister("x0", BigInt(-EBADF)); return true; }
    const offset = BigInt.asIntN(64, this.cpu.readRegister("x1")), origin = Number(BigInt.asIntN(32, this.cpu.readRegister("x2")));
    const base = origin === 0 ? 0 : origin === 1 ? file.position : origin === 2 ? file.bytes.length : undefined;
    const position = base === undefined ? -1n : BigInt(base) + offset;
    if (position < 0n || position > BigInt(file.bytes.length)) { this.cpu.writeRegister("x0", BigInt(-EINVAL)); return true; }
    file.position = Number(position);
    this.cpu.writeRegister("x0", position);
    return true;
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

  dispose(): void { this.disposed = true; this.blocked = undefined; this.noticeList.length = 0; this.descriptors.clear(); }
}
