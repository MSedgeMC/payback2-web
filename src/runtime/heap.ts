import { MAX_GUEST_BYTES, PAGE_SIZE } from "./adapter.ts";
import type { RuntimeAdapter } from "./adapter.ts";

const base = 0x50000000n, limit = 64n * 1024n * 1024n, chunkSize = 64n * 1024n;
// shortcut: 64 MiB and 65,536 live allocations; increase only after measuring guest demand.
const allocationLimit = 65_536;
const zero = new Uint8Array(Number(chunkSize));
type Block = { address: bigint; size: bigint; mapping: bigint };

export class GuestHeap {
  private readonly cpu: RuntimeAdapter;
  private readonly freeBlocks: Block[] = [];
  private readonly allocations = new Map<bigint, Block>();
  private readonly mappings: { address: bigint; size: bigint }[] = [];
  private mappedBytes = 0n;
  private disposed = false;

  constructor(cpu: RuntimeAdapter) { this.cpu = cpu; }

  allocate(bytes: bigint, clear = false): bigint {
    if (this.disposed) throw new Error("Guest heap is disposed");
    if (bytes < 0n) throw new RangeError("Negative guest allocation size");
    if (bytes > limit || this.allocations.size >= allocationLimit) return 0n;
    const size = bytes === 0n ? 16n : (bytes + 15n) / 16n * 16n;
    let index = this.freeBlocks.findIndex(block => block.size >= size);
    if (index < 0) {
      const pages = (size + PAGE_SIZE - 1n) / PAGE_SIZE * PAGE_SIZE;
      const mappingSize = pages > chunkSize ? pages : chunkSize;
      if (this.mappedBytes + mappingSize > limit ||
          this.cpu.regions.reduce((total, region) => total + region.size, mappingSize) > BigInt(MAX_GUEST_BYTES)) return 0n;
      const address = base + this.mappedBytes;
      this.cpu.map(address, mappingSize, 3); this.mappings.push({ address, size: mappingSize });
      this.mappedBytes += mappingSize;
      this.freeBlocks.push({ address, size: mappingSize, mapping: address }); index = this.freeBlocks.length - 1;
    }
    const block = this.freeBlocks[index]!, address = block.address;
    this.allocations.set(address, { address, size, mapping: block.mapping });
    if (block.size === size) this.freeBlocks.splice(index, 1);
    else { block.address += size; block.size -= size; }
    if (clear) {
      for (let offset = 0n; offset < bytes; offset += chunkSize) {
        const count = Number(bytes - offset < chunkSize ? bytes - offset : chunkSize);
        this.cpu.copyIn(address + offset, zero.subarray(0, count));
      }
    }
    return address;
  }

  free(address: bigint): void {
    if (this.disposed) throw new Error("Guest heap is disposed");
    if (address === 0n) return;
    const block = this.allocations.get(address);
    if (!block) throw new RangeError("Free requires an active guest allocation");
    this.allocations.delete(address); this.freeBlocks.push(block);
    this.freeBlocks.sort((a, b) => a.address < b.address ? -1 : 1);
    for (let index = 1; index < this.freeBlocks.length;) {
      const previous = this.freeBlocks[index - 1]!, current = this.freeBlocks[index]!;
      if (previous.mapping === current.mapping && previous.address + previous.size === current.address) {
        previous.size += current.size; this.freeBlocks.splice(index, 1);
      } else index++;
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    for (const mapping of this.mappings.splice(0).reverse()) this.cpu.unmap(mapping.address, mapping.size);
    this.allocations.clear(); this.freeBlocks.length = 0;
  }
}
