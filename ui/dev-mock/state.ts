/* DEV-ONLY mock state: event store, counters, incidents, query matching. */
import { createHash } from "node:crypto";
import type { Detection, EventRow, EventStatus, QueryField, SeriesPoint } from "../src/api/types";
import { LAKE_FIELDS } from "../src/lib/fields";
import { parseQuery, type QTerm } from "../src/lib/query-dsl";
import { BLOCK_SIZE, SEG_SIZE, SOURCES, R, int, makeEvent, pick, randomFlow, segName, totalMade, type Flow, type StoredEvent } from "./data";

export const CAP = 40_000;
export const events: StoredEvent[] = []; // oldest → newest
export const byId = new Map<string, StoredEvent>();
const pinned = new Set<string>(); // incident evidence stays resolvable after ring eviction
export const startedAt = Date.now();

export interface Counter { ingested: number; parsed: number; partial: number; unparsed: number; covSum: number; last: number; unmapped: Map<string, { n: number; first: number; ex: string }> }
export const counters = new Map<string, Counter>();
export const knownKeys = new Map<string, Set<string>>();
export const tamperRef: { v: { seg: string; block: number } | null } = { v: null };

const incidents: { key: string; title: string; entity: { kind: string; value: string }; ids: string[]; start: number; end: number; sources: Set<string>; summary: string; sev: number; score: number; feats: Detection["features"] }[] = [];

export function ingest(e: StoredEvent) {
  events.push(e);
  byId.set(e.row.event_id, e);
  if (events.length > CAP) { const old = events.splice(0, 2000); for (const o of old) if (!pinned.has(o.row.event_id)) byId.delete(o.row.event_id); }
  const sid = e.row.source_id;
  const c = counters.get(sid) ?? { ingested: 0, parsed: 0, partial: 0, unparsed: 0, covSum: 0, last: 0, unmapped: new Map() };
  c.ingested++; c[e.row.status]++; c.covSum += e.row.coverage; c.last = Math.max(c.last, e.row.time);
  for (const [k, v] of Object.entries(e.doc.unmapped ?? {})) {
    const u = c.unmapped.get(k) ?? { n: 0, first: e.row.time, ex: String(v) };
    u.n++; c.unmapped.set(k, u);
  }
  counters.set(sid, c);
}

/* ── seeding: ~45 min of history with three incidents ──────────────── */
export function seed(historyMs = 45 * 60_000) {
  const now = Date.now();
  const t0 = now - historyMs;
  const weights = SOURCES.flatMap((s) => Array(s.weight).fill(s.id) as string[]);
  const n = 9000;
  for (let i = 0; i < n; i++) {
    const t = t0 + (i / n) * historyMs + R() * 100;
    if (R() < 0.03) ingest(makeEvent("mikrotik.unseen", randomFlow("fortinet.fortigate"), t));
    else { const s = pick(weights); ingest(makeEvent(s, randomFlow(s), t)); }
  }
  const inject = (key: string, title: string, entity: { kind: string; value: string }, startAgo: number, plan: { src: string; n: number; flow: (i: number) => Flow }[], sev: number, score: number, summary: string, feats: Detection["features"]) => {
    const start = now - startAgo; const ids: string[] = []; const sources = new Set<string>(); let end = start;
    for (const p of plan) for (let i = 0; i < p.n; i++) {
      const t = start + i * 220 + R() * 90; end = Math.max(end, t);
      const ev = makeEvent(p.src, p.flow(i), t, { forceStatus: "parsed" });
      ingest(ev); ids.push(ev.row.event_id); pinned.add(ev.row.event_id); sources.add(p.src);
    }
    events.sort((a, b) => a.row.time - b.row.time);
    incidents.push({ key, title, entity, ids, start, end: end + 60_000, sources, summary, sev, score, feats });
  };
  const base = (): Flow => randomFlow("fortinet.fortigate");
  inject("scan", "Port scan across perimeter", { kind: "src_ip", value: "203.0.113.50" }, 30 * 60_000,
    [{ src: "fortinet.fortigate", n: 90, flow: (i) => ({ ...base(), srcIp: "203.0.113.50", dstIp: "10.1.1.15", dstPort: 20 + i * 11, deny: true, bytesIn: 0, bytesOut: 60, proto: "tcp" }) },
     { src: "cisco.asa", n: 70, flow: (i) => ({ ...base(), srcIp: "203.0.113.50", dstIp: "10.1.2.20", dstPort: 30 + i * 13, deny: true, proto: "tcp" }) }],
    4, 0.93, "One external host touched many distinct destination ports on two different firewalls inside a single 60-second window, nearly all denied.",
    [{ name: "uniq_dst_port", value: 160, baseline: 6, z: 9.8 }, { name: "deny_ratio", value: 0.98, baseline: 0.14, z: 7.1 }, { name: "conn_count", value: 160, baseline: 14, z: 6.2 }, { name: "uniq_sources", value: 2, baseline: 1, z: 1.4 }]);
  inject("brute", "SSH brute force", { kind: "src_ip", value: "198.51.100.77" }, 22 * 60_000,
    [{ src: "cisco.asa", n: 60, flow: () => ({ ...base(), srcIp: "198.51.100.77", dstIp: "10.1.1.20", dstPort: 22, deny: true, proto: "tcp" }) },
     { src: "pfsense.filterlog", n: 60, flow: () => ({ ...base(), srcIp: "198.51.100.77", dstIp: "10.1.3.20", dstPort: 22, deny: true, proto: "tcp" }) }],
    4, 0.88, "Repeated denied connections to TCP/22 from one address, seen by ASA and pfSense.",
    [{ name: "conn_count", value: 120, baseline: 11, z: 8.3 }, { name: "deny_ratio", value: 1, baseline: 0.13, z: 7.5 }, { name: "uniq_dst_port", value: 1, baseline: 5, z: -0.9 }]);
  inject("exfil", "Possible data exfiltration", { kind: "src_ip", value: "10.1.1.42" }, 15 * 60_000,
    [{ src: "squid.access", n: 25, flow: () => ({ ...base(), srcIp: "10.1.1.42", dstIp: "192.0.2.99", dstPort: 443, deny: false, bytesIn: int(4e6, 9e6), bytesOut: 2000, url: "http://192.0.2.99/upload" }) },
     { src: "fortinet.fortigate", n: 20, flow: () => ({ ...base(), srcIp: "10.1.1.42", dstIp: "192.0.2.99", dstPort: 443, deny: false, bytesOut: int(8e6, 2e7), bytesIn: 4000, proto: "tcp" }) }],
    5, 0.91, "An internal host sent an unusually large volume to a destination never previously contacted.",
    [{ name: "bytes_out_sum", value: 3.1e8, baseline: 1.9e6, z: 11.2 }, { name: "uniq_dst_ip", value: 1, baseline: 18, z: -2.1 }, { name: "conn_count", value: 45, baseline: 12, z: 3.4 }]);
  // one weak finding so the list is not all signal
  inject("noise", "Elevated denied traffic", { kind: "src_ip", value: "10.1.3.88" }, 38 * 60_000,
    [{ src: "pfsense.filterlog", n: 14, flow: () => ({ ...base(), srcIp: "10.1.3.88", deny: true }) }], 2, 0.62, "Deny ratio above this host's baseline for one window.",
    [{ name: "deny_ratio", value: 0.71, baseline: 0.15, z: 2.4 }]);
}

export function detections(): Detection[] {
  return incidents.map((i) => {
    const ev = i.ids.map((id) => byId.get(id)?.row).filter(Boolean) as EventRow[];
    const top = ev.slice(0, 40);
    const fid = createHash("sha1").update(i.key).digest("hex").slice(0, 12);
    return { finding_id: `fnd-${fid}`, event_id: top[0]?.event_id ?? "", time: i.start, title: i.title, severity_id: i.sev, score: i.score, entity: i.entity, window: { start: i.start, end: i.end }, summary: i.summary, features: i.feats, sources: [...i.sources], evidence_total: ev.length, evidence: top };
  }).sort((a, b) => b.score - a.score);
}

/* ── query matching (uses the UI's own parser for syntax, mock semantics) ── */
const ip4n = (s: string) => s.split(".").reduce((a, o) => a * 256 + Number(o), 0);
function ipMatch(v: string | null, q: string): boolean {
  if (!v) return false;
  if (q.includes("/") && !q.includes(":")) { const [a, p] = q.split("/"); const m = p === "0" ? 0 : (~0 << (32 - Number(p))) >>> 0; return v.includes(".") && ((ip4n(v) & m) >>> 0) === ((ip4n(a) & m) >>> 0); }
  if (q.endsWith("*")) return v.startsWith(q.slice(0, -1));
  return v === q;
}
const NUMF: Record<string, keyof EventRow> = { src_port: "src_port", dst_port: "dst_port", bytes_in: "bytes_in", bytes_out: "bytes_out", severity_id: "severity_id", class_uid: "class_uid", action_id: "action_id", activity_id: "activity_id", coverage: "coverage" };
const STRF: Record<string, keyof EventRow> = { proto_name: "proto_name", source_id: "source_id", status: "status", user_name: "user_name", url: "url", signature: "signature", device_host: "device_host", event_id: "event_id", raw_ref: "raw_ref", dns_query: "dns_query" };

function termMatch(t: QTerm, e: StoredEvent): boolean {
  if (t.kind === "text") return e.raw.toLowerCase().includes(t.value.toLowerCase());
  const f = t.field!; const row = e.row;
  const vals = t.value.split(",");
  let ok = false;
  if (f === "src_ip" || f === "dst_ip") ok = vals.some((v) => ipMatch(row[f], v));
  else if (f === "action") ok = vals.some((v) => (v === "denied" ? row.action_id === 2 : v === "allowed" ? row.action_id === 1 : false));
  else if (NUMF[f]) {
    const x = row[NUMF[f]] as number | null;
    ok = x != null && vals.some((v) => {
      const rg = /^(-?[\d.]+)\.\.(-?[\d.]+)$/.exec(v);
      if (rg) return x >= +rg[1] && x <= +rg[2];
      const n = Number(v);
      return t.op === ">" ? x > n : t.op === ">=" ? x >= n : t.op === "<" ? x < n : t.op === "<=" ? x <= n : x === n;
    });
  } else if (STRF[f]) {
    const x = String(row[STRF[f]] ?? "").toLowerCase();
    ok = vals.some((v) => { const w = v.toLowerCase(); return w.includes("*") ? new RegExp("^" + w.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$").test(x) : x === w; });
  } else ok = false;
  return t.negated ? !ok : ok;
}

export function compile(q: string | undefined): { terms: QTerm[]; error: string | null } {
  if (!q?.trim()) return { terms: [], error: null };
  const r = parseQuery(q, LAKE_FIELDS as QueryField[]);
  const err = r.issues.find((i) => i.level === "error");
  return { terms: r.terms, error: err ? err.message : null };
}
export const matches = (terms: QTerm[], e: StoredEvent) => terms.every((t) => termMatch(t, e));

/* ── derived views ─────────────────────────────────────────────────── */
export function epsSeries(sourceId: string | null, buckets = 60, binMs = 5000): SeriesPoint[] {
  const now = Date.now(); const start = now - buckets * binMs; const out = new Array(buckets).fill(0);
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    if (e.row.time < start) break;
    if (e.row.time > now) continue;
    if (sourceId && e.row.source_id !== sourceId) continue;
    out[Math.min(buckets - 1, Math.floor((e.row.time - start) / binMs))]++;
  }
  return out.map((n, i) => ({ t: start + i * binMs, v: n / (binMs / 1000) }));
}

export function segments() {
  const n = totalMade();
  const count = Math.ceil(n / SEG_SIZE);
  return Array.from({ length: count }, (_, s) => {
    const inSeg = Math.min(SEG_SIZE, n - s * SEG_SIZE);
    const sealed = s < count - 1;
    return { segment: segName(s), inSeg, blocks: Math.ceil(inSeg / BLOCK_SIZE), sealed };
  });
}
export { BLOCK_SIZE, SEG_SIZE };
export type { EventStatus };
