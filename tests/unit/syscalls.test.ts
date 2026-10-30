import assert from "node:assert/strict";
import { test } from "node:test";
import { createRuntime } from "../../src/runtime/unicorn.ts";
import { GuestSyscalls, SYS } from "../../src/runtime/syscalls.ts";

const code = 0x30000n, data = 0x40000n;
// Guest registers hold raw 64-bit values, so a negative errno reads back two's-complement encoded.
const signed = (value: bigint): bigint => BigInt.asIntN(64, value);

test("guest syscalls write clock results and report one isolated process", async () => {
  const cpu = await createRuntime(), syscalls = new GuestSyscalls(cpu);
  try {
    cpu.map(code, 4096n, 5); cpu.map(data, 4096n, 3);
    cpu.copyIn(code, new Uint8Array([0x01, 0x00, 0x00, 0xd4]));
    const call = (number: number, args: bigint[] = [], pc = code + 4n) => {
      cpu.writeRegister("x8", BigInt(number)); cpu.writeRegister("x30", 0x7fff0000n);
      args.forEach((value, index) => cpu.writeRegister(`x${index}` as `x${number}`, value));
      const handled = syscalls.handle(pc);
      return { handled, result: cpu.readRegister("x0"), signed: signed(cpu.readRegister("x0")), pc: cpu.readRegister("pc") };
    };
    const realtime = call(SYS.clock_gettime, [0n, data]);
    assert.equal(realtime.handled, true); assert.equal(realtime.result, 0n); assert.equal(realtime.pc, 0x7fff0000n);
    const view = new DataView(cpu.copyOut(data, 16).buffer);
    const seconds = Number(view.getBigInt64(0, true)), nanoseconds = Number(view.getBigInt64(8, true));
    assert.ok(Math.abs(seconds - Math.floor(Date.now() / 1000)) < 5); assert.ok(nanoseconds >= 0 && nanoseconds < 1e9);
    const monotonic = call(SYS.clock_gettime, [1n, data + 32n]);
    assert.equal(monotonic.handled, true);
    const monotonicView = new DataView(cpu.copyOut(data + 32n, 16).buffer);
    assert.ok(Number(monotonicView.getBigInt64(8, true)) < 1e9);
    assert.equal(call(SYS.clock_getres, [1n, data + 64n]).result, 0n);
    assert.equal(new DataView(cpu.copyOut(data + 64n, 16).buffer).getBigInt64(8, true), 1_000_000n);
    assert.equal(call(SYS.clock_gettime, [42n, data]).signed, -22n);
    assert.equal(call(SYS.getpid).result, 1n); assert.equal(call(SYS.gettid).result, 1n);
    assert.equal(call(SYS.set_tid_address, [data + 96n]).result, 0n);
    const timeval = call(SYS.gettimeofday, [data + 128n]);
    assert.equal(timeval.result, 0n);
    const timevalView = new DataView(cpu.copyOut(data + 128n, 16).buffer);
    assert.ok(Math.abs(Number(timevalView.getBigInt64(0, true)) - Math.floor(Date.now() / 1000)) < 5);
    assert.equal(syscalls.unsupportedSyscall, undefined);
  } finally { syscalls.dispose(); cpu.unmap(code, 4096n); cpu.unmap(data, 4096n); assert.equal(cpu.regions.length, 0); cpu.close(); }
});

test("unsupported and non-syscall interrupts stay visible instead of fabricating success", async () => {
  const cpu = await createRuntime(), syscalls = new GuestSyscalls(cpu);
  try {
    cpu.map(code, 4096n, 5);
    cpu.copyIn(code, new Uint8Array([0x01, 0x00, 0x00, 0xd4]));
    cpu.writeRegister("x8", 222n);
    assert.equal(syscalls.handle(code + 4n), false); assert.equal(syscalls.unsupportedSyscall, "mmap");
    cpu.writeRegister("x8", 4242n);
    assert.equal(syscalls.handle(code + 4n), false); assert.equal(syscalls.unsupportedSyscall, "syscall_4242");
    // An interrupt that is not a raw syscall (here the `svc #1` diagnostic trap) is not claimed.
    cpu.copyIn(code + 100n, new Uint8Array([0x21, 0x00, 0x00, 0xd4]));
    cpu.writeRegister("x8", BigInt(SYS.getpid));
    assert.equal(syscalls.handle(code + 104n), false); assert.equal(syscalls.unsupportedSyscall, undefined);
    assert.equal(syscalls.handle(4n), false);
    syscalls.dispose(); assert.throws(() => syscalls.handle(code + 4n), /disposed/);
  } finally { cpu.unmap(code, 4096n); cpu.close(); }
});
