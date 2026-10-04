/** Fixed-capacity ring buffer; index 0 is the NEWEST element. */
export class RingBuffer<T> {
  private buf: (T | undefined)[];
  private head = 0; // next write slot
  private count = 0;
  /** Total elements ever pushed (evictions included). */
  total = 0;
  evicted = 0;
  constructor(readonly capacity: number) {
    this.buf = new Array<T | undefined>(capacity);
  }
  get size() {
    return this.count;
  }
  push(items: readonly T[]): void {
    for (const it of items) {
      if (this.count === this.capacity) this.evicted++;
      this.buf[this.head] = it;
      this.head = (this.head + 1) % this.capacity;
      if (this.count < this.capacity) this.count++;
      this.total++;
    }
  }
  /** i = 0 → newest. */
  at(i: number): T | undefined {
    if (i < 0 || i >= this.count) return undefined;
    return this.buf[(this.head - 1 - i + this.capacity * 2) % this.capacity];
  }
  toArray(): T[] {
    const out: T[] = new Array(this.count);
    for (let i = 0; i < this.count; i++) out[i] = this.at(i) as T;
    return out;
  }
  clear() {
    this.buf = new Array<T | undefined>(this.capacity);
    this.head = 0;
    this.count = 0;
  }
}
