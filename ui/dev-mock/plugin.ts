/* DEV-ONLY: Vite plugin that serves a fake ULPF API. See dev-mock/README.md. Never imported by src/. */
import { cpus, totalmem, platform, release } from "node:os";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Plugin } from "vite";
import { WebSocketServer, type WebSocket } from "ws";
import type { EventRow, EventStatus, StreamRequest, TailRow } from "../src/api/types";
import { LAKE_FIELDS } from "../src/lib/fields";
import { MIKROTIK_RE, SOURCES, int, makeEvent, mikrotikLine, nodeId, pick, published, R, randomFlow } from "./data";
import {
  BLOCK_SIZE, byId, compile, counters, detections, epsSeries, events, ingest, matches, seed, segments, startedAt, tamperRef
} from "./state";

const verified = new Map<string, { ok: boolean; block?: number; frame?: number }>();

function send(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.setHeader("x-ulpf-mock", "1");
  res.end(JSON.stringify(body));
}
const err = (res: ServerResponse, status: number, code: string, message: string) => send(res, status, { error: { code, message } });
async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

function filterFrom(u: URL) {
  const from = Number(u.searchParams.get("from") ?? 0) || 0;
  const to = Number(u.searchParams.get("to") ?? 0) || Date.now() + 60_000;
  const cls = u.searchParams.get("class");
  const source = u.searchParams.get("source");
  const status = u.searchParams.get("status");
  const c = compile(u.searchParams.get("q") ?? undefined);
  return {
    error: c.error,
    test: (e: (typeof events)[number]) =>
      e.row.time >= from && e.row.time <= to && (!cls || e.row.class_uid === Number(cls)) && (!source || e.row.source_id === source) && (!status || e.row.status === status) && matches(c.terms, e),
    from, to
  };
}

function template(raw: string) {
  return raw.replace(/\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b/g, "<MAC>").replace(/\d+(\.\d+){3}/g, "<IP>").replace(/\b\d+\b/g, "<NUM>");
}

/* ── onboarding mock ───────────────────────────────────────────────── */
const DRAFT_PATTERN = String(MIKROTIK_RE.source).replace(/\(\?<(\w+)>/g, "(?P<$1>");
const MAP_LINES = `      activity_id: {const: 6}
      src_endpoint.ip: {from: src_ip, pipe: [ip]}
      src_endpoint.port: {from: src_port, pipe: [int, port]}
      src_endpoint.mac: {from: src_mac, pipe: [mac]}
      src_endpoint.interface_name: in_if
      dst_endpoint.ip: {from: dst_ip, pipe: [ip]}
      dst_endpoint.port: {from: dst_port, pipe: [int, port]}
      dst_endpoint.interface_name: out_if
      connection_info.protocol_name: {from: proto, pipe: [lower]}
      connection_info.tcp_flags: flags
      firewall_rule.name: chain
      traffic.bytes_out: {from: len, pipe: [int]}`;
const draftYaml = (vendor: string, product: string) => `# Draft generated from your samples — edit freely, preview updates live.
pack: 1
id: mikrotik.routeros_firewall
version: 0.1.0
verified: false
meta: {vendor: ${vendor || "MikroTik"}, product: ${product || "RouterOS"}, category: firewall}
match:
  priority: 40
  all:
    - starts_with: "firewall,"
framing: none
extract:
  kind: regex
  options:
    pattern: '${DRAFT_PATTERN}'
select:
  - otherwise: network_activity
classes:
  network_activity:
    set:
${MAP_LINES}
tests: []
`;

function analyze(samples: string[], vendor?: string, product?: string) {
  const hits = samples.filter((l) => MIKROTIK_RE.test(l)).length;
  const isMt = hits / Math.max(1, samples.length) >= 0.5;
  const yaml = isMt ? draftYaml(vendor ?? "", product ?? "") : `pack: 1\nid: custom.generic\nversion: 0.1.0\nverified: false\nmeta: {vendor: ${vendor || "Unknown"}, product: ${product || "Unknown"}, category: other}\nmatch:\n  priority: 10\n  all:\n    - contains: ""\nextract:\n  kind: regex\n  options:\n    pattern: '^(?P<message>.*)$'\nselect:\n  - otherwise: base_event\nclasses:\n  base_event:\n    set:\n      message: message\ntests: []\n`;
  const prev = preview(yaml, samples);
  const tmpl = new Map<string, { n: number; ex: string }>();
  for (const l of samples) { const t = template(l); const c = tmpl.get(t) ?? { n: 0, ex: l }; c.n++; tmpl.set(t, c); }
  const fields = isMt
    ? Object.keys(MIKROTIK_RE.exec(samples.find((l) => MIKROTIK_RE.test(l))!)!.groups!).map((name) => {
        const ex = String(MIKROTIK_RE.exec(samples.find((l) => MIKROTIK_RE.test(l) && MIKROTIK_RE.exec(l)!.groups![name])!)?.groups?.[name] ?? "");
        const type = /ip$/.test(name) ? "ip" : /port$/.test(name) ? "port" : name === "len" ? "int" : name === "src_mac" ? "mac" : "enum/text";
        return { name, type, example: ex, ocsf_path: MAP_LINES.split("\n").map((s) => s.trim()).find((s) => new RegExp(`from: ${name}\\b|: ${name}$`).test(s))?.split(":")[0] ?? null, confidence: type === "enum/text" ? 0.6 : 0.95 };
      })
    : [{ name: "message", type: "text", example: samples[0]?.slice(0, 60) ?? "", ocsf_path: "message", confidence: 0.3 }];
  return {
    analysis_id: sha(samples.join("\n")).slice(0, 12), format: isMt ? "text (drain3 template)" : "text", format_confidence: isMt ? hits / samples.length : 0.4,
    class_name: isMt ? "Network Activity" : "Base Event", class_uid: isMt ? 4001 : 0, pack_id: isMt ? "mikrotik.routeros_firewall" : "custom.generic",
    draft_pack_yaml: yaml,
    templates: [...tmpl.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 6).map(([t, v], i) => ({ template_id: `t${i}`, template: t, count: v.n, share: v.n / samples.length, example_raw: v.ex })),
    fields, coverage: prev.coverage, est_minutes: isMt ? 1.6 : null,
    warnings: samples.length < 20 ? [`only ${samples.length} sample lines; 20+ recommended`] : []
  };
}

function preview(yaml: string, samples: string[]) {
  const lint: { level: "error" | "warning"; message: string; line?: number }[] = [];
  const lines = yaml.split("\n");
  if (!/^id:\s*\S+/m.test(yaml)) lint.push({ level: "error", message: "missing required key: id", line: 1 });
  if (/\t/.test(yaml)) lint.push({ level: "error", message: "tabs are not allowed in YAML", line: lines.findIndex((l) => l.includes("\t")) + 1 });
  const pl = lines.findIndex((l) => /^\s+pattern:/.test(l));
  let re: RegExp | null = null;
  if (pl < 0) lint.push({ level: "error", message: "extract.options.pattern is required for kind: regex", line: 1 });
  else {
    const m = /pattern:\s*'(.*)'\s*$/.exec(lines[pl]);
    try { re = new RegExp((m?.[1] ?? "").replace(/\(\?P</g, "(?<")); if (!m) throw new Error("pattern must be a single-quoted string"); }
    catch (e) { lint.push({ level: "error", message: `invalid regex: ${(e as Error).message}`, line: pl + 1 }); re = null; }
    if (re && /\([^)]*[+*]\)[+*]/.test(re.source)) lint.push({ level: "error", message: "ReDoS-prone nested quantifier", line: pl + 1 });
  }
  const maps: { path: string; field: string }[] = [];
  lines.forEach((l) => { const m = /^\s{6}([\w.]+):\s*(?:\{from:\s*(\w+)|(\w+)\s*$)/.exec(l); if (m && (m[2] || m[3])) maps.push({ path: m[1], field: m[2] ?? m[3] }); });
  if (re && maps.length === 0) lint.push({ level: "warning", message: "no mappings under classes.*.set — every field will land in unmapped", line: 1 });
  if (/^tests:\s*\[\]/m.test(yaml)) lint.push({ level: "warning", message: "tests[] is empty; golden vectors are generated from samples on publish", line: lines.findIndex((l) => /^tests:/.test(l)) + 1 });
  const groups = re ? [...re.source.matchAll(/\(\?<(\w+)>/g)].map((m) => m[1]) : [];
  const hasErr = lint.some((i) => i.level === "error");
  const rows: { line_no: number; status: EventStatus; coverage: number; class_uid: number | null; raw: string; mapped: Record<string, unknown>; unmapped: Record<string, unknown> }[] = [];
  const mapField = new Map(maps.map((m) => [m.field, m.path]));
  let matched = 0; const um = new Map<string, number>(); let covSum = 0;
  samples.forEach((raw, i) => {
    const g = !hasErr && re ? re.exec(raw)?.groups : undefined;
    if (!g) { rows.push({ line_no: i + 1, status: "unparsed", coverage: 0, class_uid: null, raw, mapped: {}, unmapped: {} }); return; }
    matched++;
    const mapped: Record<string, unknown> = {}, unm: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(g)) { if (v == null) continue; const p = mapField.get(k); if (p) mapped[p] = v; else { unm[k] = v; um.set(k, (um.get(k) ?? 0) + 1); } }
    const n = Object.keys(mapped).length, tot = n + Object.keys(unm).length;
    const cov = tot ? n / tot : 0; covSum += cov;
    rows.push({ line_no: i + 1, status: mapped["src_endpoint.ip"] && mapped["dst_endpoint.ip"] ? "parsed" : "partial", coverage: cov, class_uid: 4001, raw, mapped, unmapped: unm });
  });
  const mappedGroups = groups.filter((g) => mapField.has(g)).length;
  return {
    ok: !hasErr, lint, tests: { passed: 0, failed: 0 }, rows,
    coverage: { lines_total: samples.length, lines_matched: matched, lines_matched_pct: samples.length ? matched / samples.length : 0, fields_mapped_pct: groups.length ? mappedGroups / groups.length : 0, mean_event_coverage: matched ? covSum / matched : 0, unmapped: [...um.entries()].map(([field, count]) => ({ field, count })) }
  };
}

/* ── router ────────────────────────────────────────────────────────── */
async function handle(req: IncomingMessage, res: ServerResponse, path: string, u: URL) {
  const m = req.method ?? "GET";
  const s = path.split("/").filter(Boolean);

  if (path === "/health") return send(res, 200, { status: "ok", version: "dev-mock", node_id: nodeId, ocsf_version: "1.3.0", time: Date.now() });
  if (path === "/events/fields") return send(res, 200, { fields: LAKE_FIELDS });
  if (path === "/events/values") {
    const f = u.searchParams.get("field") ?? ""; const p = (u.searchParams.get("prefix") ?? "").toLowerCase();
    const key = ({ source_id: "source_id", device_host: "device_host", user_name: "user_name", proto_name: "proto_name", signature: "signature", src_ip: "src_ip", dst_ip: "dst_ip" } as Record<string, keyof EventRow>)[f];
    const set = new Set<string>();
    if (key) for (let i = events.length - 1; i >= 0 && i > events.length - 4000 && set.size < 12; i--) { const v = events[i].row[key]; if (v != null && String(v).toLowerCase().startsWith(p)) set.add(String(v)); }
    return send(res, 200, { values: [...set] });
  }
  if (path === "/events/histogram") {
    const f = filterFrom(u); if (f.error) return err(res, 400, "BAD_QUERY", f.error);
    const nb = Math.max(10, Math.min(200, Number(u.searchParams.get("buckets") ?? 60)));
    const from = f.from || (events[0]?.row.time ?? Date.now() - 3.6e6); const to = f.to;
    const interval = Math.max(1000, Math.ceil((to - from) / nb / 1000) * 1000);
    const t0 = Math.floor(from / interval) * interval;
    const n = Math.max(1, Math.ceil((to - t0) / interval));
    const buckets = Array.from({ length: n }, (_, i) => ({ t: t0 + i * interval, parsed: 0, partial: 0, unparsed: 0 }));
    for (let i = events.length - 1; i >= 0; i--) { const e = events[i]; if (e.row.time < t0) { if (i < events.length - 20000) break; continue; } if (f.test(e)) { const b = buckets[Math.min(n - 1, Math.floor((e.row.time - t0) / interval))]; if (b) b[e.row.status]++; } }
    return send(res, 200, { from: t0, to, interval_ms: interval, buckets });
  }
  if (path === "/events" && m === "GET") {
    const f = filterFrom(u); if (f.error) return err(res, 400, "BAD_QUERY", f.error);
    const limit = Math.min(500, Number(u.searchParams.get("limit") ?? 100));
    const cur = u.searchParams.get("cursor");
    let i = cur ? Number(cur) - 1 : events.length - 1;
    const items: EventRow[] = []; let last = i;
    const t = Date.now();
    for (; i >= 0 && items.length < limit; i--) { last = i; if (f.test(events[i])) items.push(events[i].row); }
    let more = false; for (let j = i; j >= 0; j--) if (f.test(events[j])) { more = true; break; }
    return send(res, 200, { items, next_cursor: more ? String(last) : null, took_ms: Date.now() - t, total_estimate: null });
  }
  if (s[0] === "events" && s[1]) {
    const e = byId.get(decodeURIComponent(s[1]));
    if (!e) return err(res, 404, "NOT_FOUND", "No such event (the mock only retains the most recent events)");
    if (!s[2]) return send(res, 200, e.doc);
    if (s[2] === "raw") {
      const bytes = Buffer.from(e.raw, "utf8");
      const bad = tamperRef.v && tamperRef.v.seg === e.seg && tamperRef.v.block === e.block;
      const out = Buffer.from(bytes); if (bad) out[Math.min(5, out.length - 1)] ^= 0x01;
      const actual = sha(out);
      return send(res, 200, { event_id: e.row.event_id, raw_ref: e.row.raw_ref, segment: e.seg, block: e.block, idx: e.idx, size: out.length, data_b64: out.toString("base64"), sha256_expected: e.doc.ulpf.raw_sha256, sha256_actual: actual, verified: !bad, error: bad ? { code: "IntegrityError", message: `block ${e.block} of ${e.seg} failed its hash check` } : null });
    }
    if (s[2] === "explain") return e.explain ? send(res, 200, e.explain) : err(res, 404, "NO_PACK", "Unparsed events have no pack to explain");
  }
  if (path === "/sources") {
    const items = [...SOURCES.map((x) => x.id), ...(counters.has("mikrotik.routeros_firewall") ? ["mikrotik.routeros_firewall"] : [])].filter((id) => counters.has(id)).map((id) => sourceSummary(id));
    return send(res, 200, { items });
  }
  if (s[0] === "sources" && s[1] && s[2] === "health") {
    const id = decodeURIComponent(s[1]); if (!counters.has(id)) return err(res, 404, "NOT_FOUND", "unknown source");
    const c = counters.get(id)!; const sum = sourceSummary(id);
    const series = (fn: (evs: typeof events) => number) => { const now = Date.now(); const bin = 120_000; return Array.from({ length: 20 }, (_, i) => { const a = now - (20 - i) * bin; const evs = events.filter((e) => e.row.source_id === id && e.row.time >= a && e.row.time < a + bin); return { t: a, v: evs.length ? fn(evs) : 0 }; }); };
    const peers = new Map<string, { n: number; last: number }>();
    for (let i = events.length - 1; i >= 0 && i > events.length - 6000; i--) { const e = events[i]; if (e.row.source_id !== id) continue; const ip = e.doc.ulpf.peer_ip; const p = peers.get(ip) ?? { n: 0, last: e.row.time }; p.n++; peers.set(ip, p); }
    return send(res, 200, { ...sum, coverage_series: series((e) => e.reduce((a, x) => a + x.row.coverage, 0) / e.length), parse_rate_series: series((e) => e.filter((x) => x.row.status === "parsed").length / e.length),
      unmapped_all: [...c.unmapped.entries()].sort((a, b) => b[1].n - a[1].n).map(([field, v]) => ({ field, count: v.n, example: v.ex })), peers: [...peers.entries()].map(([ip, v]) => ({ ip, events: v.n, last_seen: v.last })) });
  }
  if (path === "/ledger") {
    const now = Date.now();
    const per = [...counters.entries()].map(([source, c]) => {
      let inflight = 0; for (let i = events.length - 1; i >= 0 && events[i].row.time > now - 400; i--) if (events[i].row.source_id === source) inflight++;
      return { source, ingested: c.ingested, vaulted: c.ingested, normalized_parsed: c.parsed, normalized_partial: c.partial, unparsed: c.unparsed, sunk: c.ingested - inflight, dropped: 0, in_flight: inflight };
    });
    const sum = (k: keyof (typeof per)[number]) => per.reduce((a, r) => a + (r[k] as number), 0);
    const totals = { ingested: sum("ingested"), vaulted: sum("vaulted"), normalized_parsed: sum("normalized_parsed"), normalized_partial: sum("normalized_partial"), unparsed: sum("unparsed"), sunk: sum("sunk"), dropped: 0, in_flight: sum("in_flight") };
    return send(res, 200, { as_of: now, totals, conserved: true, per_source: per.sort((a, b) => b.ingested - a.ingested), dropped_by_reason: {}, sunk_by_sink: { parquet: totals.sunk } });
  }
  if (path === "/vault/segments") {
    const segs = segments();
    return send(res, 200, { items: segs.map((g) => {
      const v = verified.get(g.segment);
      const first = events.find((e) => e.seg === g.segment)?.row.time ?? startedAt;
      return { segment: g.segment, node_id: nodeId, created_ms: first, sealed_ms: g.sealed ? first + 60_000 : null, n_events: g.inSeg, n_blocks: g.blocks, size_bytes: g.inSeg * 61, chain_head: sha(g.segment + g.inSeg),
        chain_status: v ? (v.ok ? "ok" : "broken") : g.sealed ? "ok" : "open", signature_ok: g.sealed ? (v ? v.ok : true) : null, last_verified_ms: g.sealed ? (v ? Date.now() : startedAt) : null,
        error: v && !v.ok ? { block: v.block, frame: v.frame ?? null, message: "block hash mismatch" } : null };
    }) });
  }
  if (path === "/vault/verify" && m === "POST") {
    res.statusCode = 200; res.setHeader("content-type", "application/x-ndjson"); res.setHeader("x-ulpf-mock", "1"); res.flushHeaders();
    const segs = segments(); const t0 = Date.now(); let frames = 0; let first: { segment: string; block: number; frame: number | null } | null = null;
    const w = (o: unknown) => res.write(JSON.stringify(o) + "\n");
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    for (const g of segs) {
      const bad = tamperRef.v && tamperRef.v.seg === g.segment;
      for (let k = 1; k <= 4; k++) { w({ type: "progress", segment: g.segment, done: Math.round((g.inSeg * k) / 4), total: g.inSeg }); await sleep(90); }
      const blk = bad ? tamperRef.v!.block : 0; const checked = bad ? (blk + 1) * BLOCK_SIZE : g.inSeg; frames += checked;
      const r = bad ? { ok: false, block: blk, frame: 5 } : { ok: true };
      verified.set(g.segment, r);
      w({ type: "segment_result", segment: g.segment, ok: !bad, blocks_checked: bad ? blk + 1 : g.blocks, frames_checked: checked, error: bad ? { block: blk, frame: 5, message: "sha256 mismatch in frame" } : null });
      if (bad && !first) first = { segment: g.segment, block: blk, frame: 5 };
    }
    w({ type: "done", ok: !first, segments_checked: segs.length, frames_checked: frames, duration_ms: Date.now() - t0, first_failure: first });
    return void res.end();
  }
  if (path === "/__mock/tamper" && m === "POST") { const segs = segments(); tamperRef.v = { seg: segs[Math.min(1, segs.length - 1)].segment, block: 2 }; verified.clear(); return send(res, 200, { tampered: tamperRef.v }); }
  if (path === "/__mock/untamper" && m === "POST") { tamperRef.v = null; verified.clear(); return send(res, 200, { tampered: null }); }
  if (path === "/analytics/detections") return send(res, 200, { items: detections(), baseline: { windows_scored: Math.floor((Date.now() - startedAt) / 60000) + 45, false_positives: null } });
  if (path === "/benchmark") {
    const real = new URL("../../bench/results.json", import.meta.url);
    try { if (existsSync(real)) return send(res, 200, JSON.parse(readFileSync(real, "utf8"))); } catch { /* fall through to synthetic */ }
    const c = cpus(); const per = int(6500, 9500);
    const scaling = [1, 2, 4].filter((n) => n <= Math.max(4, c.length)).map((n) => ({ workers: n, eps: Math.round(per * n * (1 - 0.06 * Math.log2(n))) }));
    const top = scaling[scaling.length - 1];
    return send(res, 200, { generated_at: startedAt, hardware: { cpu: c[0]?.model ?? "unknown", cores: c.length, ram_gb: Math.round(totalmem() / 2 ** 30), os: `${platform()} ${release()}`, label: "SYNTHETIC — dev mock, not a measurement" }, config: { mix: "fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10", duration_s: 60, events: top.eps * 60, workers_list: scaling.map((x) => x.workers) },
      sustained: { eps: top.eps, per_worker_eps: Math.round(top.eps / top.workers), projected_daily_events: top.eps * 86400 }, scaling, latency_ms: { p50: 180, p95: 640, p99: 1250, max: 2900 }, resources: { cpu_pct: 340, rss_mb: 520 }, vault: { compression_ratio: 7.4 }, lake: { bytes_per_event: 96 }, ledger: { ingested: top.eps * 60, lost: 0, conserved: true }, accuracy: { precision: 0.997, recall: 0.995 }, parse_rate: 0.992 });
  }
  if (path === "/onboard/clusters") {
    const g = new Map<string, { n: number; ex: string; samples: Set<string>; first: number; last: number }>();
    for (const e of events) if (e.row.status === "unparsed") { const t = template(e.raw); const c = g.get(t) ?? { n: 0, ex: e.raw, samples: new Set(), first: e.row.time, last: 0 }; c.n++; c.last = e.row.time; if (c.samples.size < 30) c.samples.add(e.raw); g.set(t, c); }
    const total = [...g.values()].reduce((a, c) => a + c.n, 0) || 1;
    return send(res, 200, { items: [...g.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 8).map(([t, c], i) => ({ template_id: `t-${i}`, template: t, count: c.n, share: c.n / total, example_raw: c.ex, samples: [...c.samples], first_seen: c.first, last_seen: c.last })) });
  }
  if (path === "/onboard/analyze" && m === "POST") { const b = JSON.parse(await readBody(req)) as { samples: string[]; vendor?: string; product?: string }; await new Promise((r) => setTimeout(r, 700)); return send(res, 200, analyze(b.samples, b.vendor, b.product)); }
  if (path === "/onboard/preview" && m === "POST") { const b = JSON.parse(await readBody(req)) as { pack_yaml: string; samples: string[] }; return send(res, 200, preview(b.pack_yaml, b.samples)); }
  if (path === "/onboard/publish" && m === "POST") {
    const b = JSON.parse(await readBody(req)) as { pack_yaml: string }; const id = /^id:\s*(\S+)/m.exec(b.pack_yaml)?.[1] ?? "custom.pack";
    if (id.startsWith("mikrotik")) published.add("mikrotik.routeros_firewall");
    return send(res, 200, { published: true, pack_id: id, version: "0.1.0", path: `packs/custom/${id}.yaml`, reloaded: true });
  }
  if (s[0] === "export") {
    const f = filterFrom(u); if (f.error) return err(res, 400, "BAD_QUERY", f.error);
    if (s[1] === "arrow") return err(res, 501, "NOT_IMPLEMENTED", "The dev mock does not produce Arrow IPC");
    const rows: EventRow[] = []; for (let i = events.length - 1; i >= 0 && rows.length < 50000; i--) if (f.test(events[i])) rows.push(events[i].row);
    res.setHeader("x-ulpf-mock", "1");
    if (s[1] === "json") { res.setHeader("content-type", "application/json"); res.setHeader("content-disposition", "attachment; filename=ulpf-export.json"); return void res.end(JSON.stringify(rows)); }
    const cols = Object.keys(rows[0] ?? { event_id: 1 });
    res.setHeader("content-type", "text/csv"); res.setHeader("content-disposition", "attachment; filename=ulpf-export.csv");
    return void res.end([cols.join(","), ...rows.map((r) => cols.map((c) => JSON.stringify((r as unknown as Record<string, unknown>)[c] ?? "")).join(","))].join("\n"));
  }
  return err(res, 404, "NOT_FOUND", `no mock route for ${m} ${path}`);
}

function sourceSummary(id: string) {
  const c = counters.get(id)!; const meta = SOURCES.find((x) => x.id === id) ?? { vendor: "MikroTik", product: "RouterOS", category: "firewall", version: "0.1.0" };
  const series = epsSeries(id); const eps = (series[series.length - 2].v + series[series.length - 3].v) / 2;
  const reasons = [...c.unmapped.entries()].filter(([, v]) => v.first > startedAt + 1000).map(([k, v]) => `new unmapped field "${k}" first seen ${new Date(v.first).toISOString().slice(11, 19)}Z (${v.n} events)`);
  return { source_id: id, vendor: meta.vendor, product: meta.product, category: meta.category, pack_version: meta.version, verified: false, eps, eps_series: series, parse_rate: c.parsed / c.ingested, mean_coverage: c.covSum / c.ingested, last_seen: c.last, total_events: c.ingested,
    status_counts: { parsed: c.parsed, partial: c.partial, unparsed: c.unparsed }, top_unmapped: [...c.unmapped.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 6).map(([field, v]) => ({ field, count: v.n })), drift: { flag: reasons.length > 0, reasons } };
}

export function ulpfDevMock(): Plugin {
  return {
    name: "ulpf-dev-mock",
    apply: "serve",
    configureServer(server) {
      seed();
      console.warn("\n  [ulpf dev-mock] serving FAKE data on /api/v1 — development only\n");
      server.middlewares.use("/api/v1", (req, res, next) => {
        const u = new URL(req.url ?? "/", "http://mock.local");
        handle(req, res, u.pathname, u).catch((e) => { console.error(e); if (!res.headersSent) err(res, 500, "MOCK_ERROR", String(e)); else res.end(); });
        void next;
      });

      // live generation + WebSocket tail
      const wss = new WebSocketServer({ noServer: true });
      const clients = new Map<WebSocket, { f: StreamRequest; q: ReturnType<typeof compile> }>();
      server.httpServer?.on("upgrade", (req, socket, head) => {
        if (!req.url?.startsWith("/api/v1/stream")) return;
        wss.handleUpgrade(req, socket, head, (ws) => {
          clients.set(ws, { f: { op: "filter", q: "", sources: [], statuses: [] }, q: compile("") });
          ws.send(JSON.stringify({ type: "hello", server_time: Date.now(), buffer: 0 }));
          ws.on("message", (d) => { try { const f = JSON.parse(String(d)) as StreamRequest; if (f.op === "filter") clients.set(ws, { f, q: compile(f.q) }); } catch { /* ignore */ } });
          ws.on("close", () => clients.delete(ws));
        });
      });
      const weights = SOURCES.flatMap((s) => Array(s.weight).fill(s.id) as string[]);
      let rate = 260;
      const timer = setInterval(() => {
        rate = Math.max(120, Math.min(520, rate + (R() - 0.5) * 40));
        const n = Math.round(rate / 10);
        const batch = [];
        for (let i = 0; i < n; i++) {
          const t = Date.now() - int(0, 90);
          const sid = R() < 0.025 ? "mikrotik.unseen" : pick(weights);
          const ev = makeEvent(sid, randomFlow(sid === "mikrotik.unseen" ? "fortinet.fortigate" : sid), t, { live: true });
          ingest(ev); batch.push(ev);
        }
        for (const [ws, c] of clients) {
          if (ws.readyState !== ws.OPEN) continue;
          const out: TailRow[] = batch.filter((e) => (!c.f.statuses.length || c.f.statuses.includes(e.row.status)) && (!c.f.sources.length || c.f.sources.includes(e.row.source_id)) && matches(c.q.terms, e)).map((e) => ({ ...e.row, message: e.raw.slice(0, 140) }));
          if (out.length) ws.send(JSON.stringify({ type: "batch", events: out }));
        }
      }, 100);
      server.httpServer?.on("close", () => { clearInterval(timer); wss.close(); });
      void MIKROTIK_RE; void mikrotikLine;
    }
  };
}
