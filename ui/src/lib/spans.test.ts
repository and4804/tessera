import { describe, expect, it } from "vitest";
import { base64ToBytes, buildSegments, clampSpans, decodeGlyphs, sliceText } from "./spans";

const enc = (s: string) => new TextEncoder().encode(s);

describe("decodeGlyphs", () => {
  it("round-trips ASCII byte offsets", () => {
    const g = decodeGlyphs(enc("abc"));
    expect(g.map((x) => [x.start, x.end, x.text])).toEqual([[0, 1, "a"], [1, 2, "b"], [2, 3, "c"]]);
  });
  it("keeps multi-byte characters as one glyph with a byte range", () => {
    const g = decodeGlyphs(enc("a€b😀"));
    expect(g.map((x) => [x.start, x.end, x.text])).toEqual([[0, 1, "a"], [1, 4, "€"], [4, 5, "b"], [5, 9, "😀"]]);
  });
  it("escapes invalid UTF-8 and control bytes instead of dropping them", () => {
    const g = decodeGlyphs(new Uint8Array([0x41, 0xff, 0xc3, 0x0a, 0xe2, 0x82]));
    expect(g.map((x) => x.text)).toEqual(["A", "\\xff", "\\xc3", "\\n", "\\xe2", "\\x82"]);
    expect(g.filter((x) => x.escaped)).toHaveLength(5);
    expect(g.at(-1)!.end).toBe(6); // every byte is accounted for
  });
  it("rejects overlong encodings and surrogates", () => {
    expect(decodeGlyphs(new Uint8Array([0xc0, 0x80])).every((x) => x.escaped)).toBe(true);
    expect(decodeGlyphs(new Uint8Array([0xed, 0xa0, 0x80])).every((x) => x.escaped)).toBe(true);
  });
  it("covers each byte exactly once", () => {
    const b = new Uint8Array(256).map((_, i) => i);
    const g = decodeGlyphs(b);
    let at = 0;
    for (const x of g) { expect(x.start).toBe(at); at = x.end; }
    expect(at).toBe(256);
  });
});

describe("buildSegments", () => {
  const raw = 'srcip=10.1.1.15 dstip=8.8.8.8 note="héllo"';
  const bytes = enc(raw);
  const find = (needle: string) => {
    const s = enc(raw.slice(0, raw.indexOf(needle))).length;
    return { start: s, end: s + enc(needle).length };
  };

  it("reassembles the exact text and every highlighted slice equals its value", () => {
    const items = [
      { id: "src", spans: [find("10.1.1.15")] },
      { id: "dst", spans: [find("8.8.8.8")] },
      { id: "note", spans: [find("héllo")] }
    ];
    const segs = buildSegments(bytes, items);
    expect(segs.map((s) => s.text).join("")).toBe(raw);
    const hl = Object.fromEntries(items.map((i) => [i.id, segs.filter((s) => s.ids.includes(i.id)).map((s) => s.text).join("")]));
    expect(hl).toEqual({ src: "10.1.1.15", dst: "8.8.8.8", note: "héllo" });
    for (const it of items) expect(sliceText(bytes, it.spans[0])).toBe(hl[it.id]);
  });
  it("handles overlapping spans, listing both ids on the overlap", () => {
    const segs = buildSegments(enc("abcdef"), [
      { id: "a", spans: [{ start: 0, end: 4 }] },
      { id: "b", spans: [{ start: 2, end: 6 }] }
    ]);
    expect(segs.map((s) => [s.text, s.ids.join("+")])).toEqual([["ab", "a"], ["cd", "a+b"], ["ef", "b"]]);
  });
  it("supports multiple spans per item and merges adjacent equal segments", () => {
    const segs = buildSegments(enc("x1y2z"), [{ id: "n", spans: [{ start: 1, end: 2 }, { start: 3, end: 4 }] }]);
    expect(segs.map((s) => [s.text, s.ids.length])).toEqual([["x", 0], ["1", 1], ["y", 0], ["2", 1], ["z", 0]]);
  });
  it("clamps out-of-range and drops empty spans without throwing", () => {
    expect(clampSpans([{ start: -5, end: 3 }, { start: 4, end: 4 }, { start: 8, end: 99 }], 10)).toEqual([
      { start: 0, end: 3 }, { start: 8, end: 10 }
    ]);
    expect(() => buildSegments(enc("abc"), [{ id: "z", spans: [{ start: 2, end: 50 }] }])).not.toThrow();
  });
  it("is byte-exact for invalid UTF-8", () => {
    const b = new Uint8Array([0x61, 0xff, 0x62]);
    const segs = buildSegments(b, [{ id: "bad", spans: [{ start: 1, end: 2 }] }]);
    expect(segs.find((s) => s.ids.includes("bad"))!.text).toBe("\\xff");
  });
  it("empty input yields no segments", () => {
    expect(buildSegments(new Uint8Array(), [])).toEqual([]);
  });
});

describe("base64ToBytes", () => {
  it("decodes", () => {
    expect([...base64ToBytes("aGk=")]).toEqual([104, 105]);
  });
});
