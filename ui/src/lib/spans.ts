/**
 * Raw-bytes renderer for Event Detail. Explain spans are BYTE offsets into the raw event
 * (§7.10). We decode UTF-8 into "glyphs" that remember their byte range, so highlighting
 * stays exact even with multi-byte characters, invalid UTF-8 (shown as \xNN) and control
 * bytes — nothing is ever lossy-decoded away.
 */
import type { Span } from "@/api/types";

export interface Glyph {
  start: number; // byte offset
  end: number;
  text: string; // what we display
  escaped: boolean; // invalid UTF-8 / control byte rendered as an escape
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

const hex2 = (n: number) => "\\x" + n.toString(16).padStart(2, "0");

export function decodeGlyphs(bytes: Uint8Array): Glyph[] {
  const out: Glyph[] = [];
  const n = bytes.length;
  let i = 0;
  while (i < n) {
    const b = bytes[i];
    if (b < 0x80) {
      if (b === 0x09) out.push({ start: i, end: i + 1, text: "\\t", escaped: true });
      else if (b === 0x0a) out.push({ start: i, end: i + 1, text: "\\n", escaped: true });
      else if (b === 0x0d) out.push({ start: i, end: i + 1, text: "\\r", escaped: true });
      else if (b < 0x20 || b === 0x7f) out.push({ start: i, end: i + 1, text: hex2(b), escaped: true });
      else out.push({ start: i, end: i + 1, text: String.fromCharCode(b), escaped: false });
      i++;
      continue;
    }
    let need = 0;
    let cp = 0;
    let min = 0;
    if (b >= 0xc2 && b <= 0xdf) { need = 1; cp = b & 0x1f; min = 0x80; }
    else if (b >= 0xe0 && b <= 0xef) { need = 2; cp = b & 0x0f; min = 0x800; }
    else if (b >= 0xf0 && b <= 0xf4) { need = 3; cp = b & 0x07; min = 0x10000; }
    let ok = need > 0 && i + need < n;
    if (ok) {
      for (let k = 1; k <= need; k++) {
        const c = bytes[i + k];
        if (c === undefined || (c & 0xc0) !== 0x80) { ok = false; break; }
        cp = (cp << 6) | (c & 0x3f);
      }
    }
    if (ok && (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))) ok = false;
    if (ok) {
      out.push({ start: i, end: i + need + 1, text: String.fromCodePoint(cp), escaped: false });
      i += need + 1;
    } else {
      out.push({ start: i, end: i + 1, text: hex2(b), escaped: true });
      i++;
    }
  }
  return out;
}

export function clampSpans(spans: Span[], len: number): Span[] {
  const r: Span[] = [];
  for (const s of spans) {
    const a = Math.max(0, Math.min(len, Math.floor(s.start)));
    const b = Math.max(0, Math.min(len, Math.floor(s.end)));
    if (b > a) r.push({ start: a, end: b });
  }
  return r;
}

/** Decoded text of a byte range (used by tests and tooltips to prove span == value). */
export function sliceText(bytes: Uint8Array, span: Span): string {
  return new TextDecoder("utf-8").decode(bytes.subarray(span.start, span.end));
}

export interface HighlightItem {
  id: string;
  spans: Span[];
}
export interface Segment {
  start: number;
  end: number;
  text: string;
  /** ids of every highlight covering this segment (document order of items). */
  ids: string[];
  escaped: boolean;
}

/**
 * Split raw bytes into render segments. Adjacent glyphs with the same coverage and
 * escape-ness are merged, so a 400-byte line with 12 fields renders ~25 nodes.
 */
export function buildSegments(bytes: Uint8Array, items: HighlightItem[]): Segment[] {
  const glyphs = decodeGlyphs(bytes);
  const len = bytes.length;
  // difference array over byte offsets -> active id sets per boundary interval
  const events: { at: number; id: string; open: boolean }[] = [];
  for (const it of items)
    for (const s of clampSpans(it.spans, len)) {
      events.push({ at: s.start, id: it.id, open: true });
      events.push({ at: s.end, id: it.id, open: false });
    }
  events.sort((a, b) => a.at - b.at);
  const order = new Map(items.map((it, i) => [it.id, i]));
  const counts = new Map<string, number>();
  const bounds: { at: number; ids: string[] }[] = [{ at: 0, ids: [] }];
  let ei = 0;
  while (ei < events.length) {
    const at = events[ei].at;
    while (ei < events.length && events[ei].at === at) {
      const e = events[ei++];
      counts.set(e.id, (counts.get(e.id) ?? 0) + (e.open ? 1 : -1));
    }
    const ids = [...counts.entries()].filter(([, c]) => c > 0).map(([id]) => id).sort((a, b) => order.get(a)! - order.get(b)!);
    if (at === 0) bounds[0] = { at, ids };
    else bounds.push({ at, ids });
  }
  const segs: Segment[] = [];
  let bi = 0;
  for (const g of glyphs) {
    while (bi + 1 < bounds.length && bounds[bi + 1].at <= g.start) bi++;
    const ids = bounds[bi].ids;
    const last = segs[segs.length - 1];
    if (last && last.escaped === g.escaped && last.ids.length === ids.length && last.ids.every((x, i) => x === ids[i])) {
      last.end = g.end;
      last.text += g.text;
    } else segs.push({ start: g.start, end: g.end, text: g.text, ids, escaped: g.escaped });
  }
  return segs;
}
