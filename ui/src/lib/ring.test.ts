import { describe, expect, it } from "vitest";
import { RingBuffer } from "./ring";

describe("RingBuffer", () => {
  it("returns newest first", () => {
    const r = new RingBuffer<number>(5);
    r.push([1, 2, 3]);
    expect(r.toArray()).toEqual([3, 2, 1]);
    expect(r.at(0)).toBe(3);
    expect(r.at(3)).toBeUndefined();
    expect(r.at(-1)).toBeUndefined();
  });
  it("evicts the oldest once full and counts evictions", () => {
    const r = new RingBuffer<number>(3);
    r.push([1, 2, 3, 4, 5]);
    expect(r.toArray()).toEqual([5, 4, 3]);
    expect(r.size).toBe(3);
    expect(r.total).toBe(5);
    expect(r.evicted).toBe(2);
  });
  it("keeps ordering across wrap-around in several batches", () => {
    const r = new RingBuffer<number>(4);
    for (let i = 0; i < 10; i += 3) r.push([i, i + 1, i + 2]);
    expect(r.toArray()).toEqual([11, 10, 9, 8]);
  });
  it("clear empties the buffer but keeps lifetime totals", () => {
    const r = new RingBuffer<string>(2);
    r.push(["a", "b", "c"]);
    r.clear();
    expect(r.size).toBe(0);
    expect(r.toArray()).toEqual([]);
    r.push(["z"]);
    expect(r.toArray()).toEqual(["z"]);
    expect(r.total).toBe(4);
  });
});
