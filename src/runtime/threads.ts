import type { Register, RuntimeAdapter } from "./adapter.ts";
import { readGuestBytes, writeGuestBytes } from "./guest-memory.ts";

// The guest runs one core, so a native thread is scheduled cooperatively: a thread created by
// `pthread_create` runs while its parent is suspended inside that call, and the parent resumes
// when the child returns from its start routine. Blocking calls stay honest (the parent really
// is inside pthread_create) at the cost of concurrency. This is a documented limitation, not
// real parallelism.
const integerRegisters: readonly Register[] = ["sp", "pc", "nzcv", "fpcr", "fpsr", "tpidr_el0",
  ...Array.from({ length: 31 }, (_, index) => `x${index}` as Register)];

export type ThreadContext = { registers: Map<Register, bigint>; vectors: Uint8Array[] };
export type GuestThread = {
  id: number; parentId: number; handle: bigint; sentinel: bigint;
  stack: bigint; stackSize: bigint; tls: bigint;
  context?: ThreadContext; state: "running" | "waiting" | "finished"; waitKey?: bigint; waitMutex?: bigint; result: bigint;
};

const STACK_BYTES = 256n * 1024n, TLS_BYTES = 4096n, TLS_PREFIX_BYTES = 64;
const HANDLE_BASE = 0x75000000n, SENTINEL_BASE = 0x7ffe0000n;
const STACK_BASE = 0x76000000n, TLS_BASE = 0x77000000n;

export class GuestThreads {
  private readonly cpu: RuntimeAdapter;
  private readonly threads: GuestThread[] = [];
  private current: GuestThread | undefined;
  /** Saved context of the main thread while a child runs on its behalf. */
  private mainContext: ThreadContext | undefined;
  private disposed = false;

  constructor(cpu: RuntimeAdapter) { this.cpu = cpu; }

  /** Exit sentinel of the thread that is currently running, or undefined for the main thread. */
  get activeSentinel(): bigint | undefined { return this.current?.sentinel; }

  count(): number { return this.threads.length; }

  private save(): ThreadContext {
    const registers = new Map<Register, bigint>();
    for (const register of integerRegisters) registers.set(register, this.cpu.readRegister(register));
    return { registers, vectors: Array.from({ length: 32 }, (_, index) => this.cpu.readVector(index)) };
  }

  private restore(context: ThreadContext): void {
    for (const [register, value] of context.registers) this.cpu.writeRegister(register, value);
    context.vectors.forEach((vector, index) => this.cpu.writeVector(index, vector));
  }

  /**
   * Starts a thread and switches to it. The entry point and argument come from the caller's
   * registers, so the guest ABI is preserved; the child begins with a private stack and TLS.
   */
  create(startRoutine: bigint, argument: bigint, handleTarget: bigint): bigint {
    if (this.disposed) throw new Error("Guest threads are disposed");
    if (!this.cpu.regions.some(region => (region.permissions & 4) && startRoutine >= region.address && startRoutine < region.address + region.size)) {
      throw new RangeError("Thread entry point is outside executable guest memory");
    }
    if (this.threads.length >= 16) throw new RangeError("Guest thread limit exceeded");
    const id = this.threads.length, stack = STACK_BASE + BigInt(id) * 0x40000n, tls = TLS_BASE + BigInt(id) * 0x2000n;
    this.cpu.map(stack, STACK_BYTES, 3); this.cpu.map(tls, TLS_BYTES, 3);
    try {
      // Bionic reserves two slots before the thread pointer; mirror the same private prefix.
      try { writeGuestBytes(this.cpu, tls + 16n, readGuestBytes(this.cpu, this.cpu.readRegister("tpidr_el0") - 16n, TLS_PREFIX_BYTES)); }
      catch { /* an unmapped parent prefix simply stays zeroed */ }
      const thread: GuestThread = { id, parentId: -1, handle: HANDLE_BASE + BigInt(id) * 0x1000n,
        sentinel: SENTINEL_BASE + BigInt(id) * 8n, stack, stackSize: STACK_BYTES, tls: tls + 16n,
        state: "running", result: 0n };
      const parent = this.current;
      // The parent's registers are the snapshot the child starts from and the parent resumes at.
      const saved = this.save();
      if (parent) parent.context = saved; else this.mainContext = saved;
      thread.parentId = parent ? parent.id : -1;
      const child: ThreadContext = { registers: new Map(saved.registers), vectors: saved.vectors.slice() };
      child.registers.set("sp", stack + STACK_BYTES - 16n);
      child.registers.set("x30", thread.sentinel);
      child.registers.set("pc", startRoutine);
      child.registers.set("x0", argument);
      child.registers.set("x1", 0n); child.registers.set("x2", 0n); child.registers.set("x3", 0n);
      child.registers.set("tpidr_el0", thread.tls);
      thread.context = child;
      this.threads.push(thread);
      const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, thread.handle, true);
      writeGuestBytes(this.cpu, handleTarget, bytes);
      this.current = thread;
      this.restore(child);
      return thread.handle;
    } catch (error) {
      this.cpu.unmap(stack, STACK_BYTES); this.cpu.unmap(tls, TLS_BYTES); throw error;
    }
  }

  waitingCount(waitKey: bigint): number {
    return this.threads.filter(thread => thread.state === "waiting" && thread.waitKey === waitKey).length;
  }

  /** Suspends the running thread on a wait key and hands control back to its parent. */
  suspend(waitKey: bigint, mutex: bigint): void {
    const thread = this.current;
    if (!thread) throw new Error("Only a guest thread can wait on a condition variable");
    thread.state = "waiting"; thread.waitKey = waitKey; thread.waitMutex = mutex;
    thread.context = this.save();
    if (thread.parentId === -1) {
      if (!this.mainContext) throw new Error("Guest thread has no resumable parent");
      this.current = undefined; this.restore(this.mainContext); this.mainContext = undefined;
      return;
    }
    const parent = this.threads.find(candidate => candidate.id === thread.parentId);
    if (!parent?.context) throw new Error("Guest thread has no resumable parent");
    this.current = parent; this.restore(parent.context); parent.context = undefined;
  }

  /**
   * Resumes a thread waiting on a key, suspending the caller. Returns the mutex the woken
   * thread must reacquire, or undefined when nothing was waiting. `broadcast` still wakes a
   * single waiter: the rest keep waiting, which the caller reports rather than hides.
   */
  resume(waitKey: bigint, broadcast: boolean): bigint | undefined {
    void broadcast;
    const waiter = this.threads.find(thread => thread.state === "waiting" && thread.waitKey === waitKey);
    if (!waiter?.context) return undefined;
    const caller = this.current;
    if (caller) caller.context = this.save(); else this.mainContext = this.save();
    waiter.parentId = caller?.id ?? -1;
    waiter.state = "running";
    const mutex = waiter.waitMutex ?? 0n;
    waiter.waitKey = undefined; waiter.waitMutex = undefined;
    this.current = waiter;
    this.restore(waiter.context);
    waiter.context = undefined;
    return mutex;
  }

  /** Called when the running thread reaches its exit sentinel; restores its parent. */
  finish(result: bigint): void {
    const thread = this.current;
    if (!thread) throw new Error("No guest thread is running");
    thread.state = "finished"; thread.result = result;
    if (thread.parentId === -1) {
      if (!this.mainContext) throw new Error("Guest thread has no resumable parent");
      this.current = undefined; this.restore(this.mainContext); this.mainContext = undefined;
      return;
    }
    const parent = this.threads.find(candidate => candidate.id === thread.parentId);
    if (!parent?.context) throw new Error("Guest thread has no resumable parent");
    this.current = parent;
    this.restore(parent.context);
    parent.context = undefined;
  }

  /** Return value of a finished thread, or undefined while it is still running. */
  resultOf(handle: bigint): bigint | undefined {
    const thread = this.threads.find(candidate => candidate.handle === handle);
    return thread?.state === "finished" ? thread.result : undefined;
  }

  /** True when a thread pointer belongs to a live guest thread created here. */
  isThreadPointer(value: bigint): boolean {
    return this.threads.some(thread => thread.tls === value);
  }

  /** Validates a thread handle without dereferencing it. */
  has(handle: bigint): boolean { return this.threads.some(thread => thread.handle === handle); }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    for (const thread of this.threads) {
      this.cpu.unmap(thread.stack, thread.stackSize);
      this.cpu.unmap(thread.tls - 16n, TLS_BYTES);
    }
    this.threads.length = 0; this.current = undefined; this.mainContext = undefined;
  }
}
