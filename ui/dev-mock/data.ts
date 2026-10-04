/* DEV-ONLY mock data synthesizer. Not part of the production bundle. */
import { createHash, randomBytes } from "node:crypto";
import type { EventRow, EventStatus, ExplainField, ExplainResponse, ExplainUnmapped, OcsfEvent, Span } from "../src/api/types";

export function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
export const R = rng(Date.now() & 0xffffffff);
const pick = <T,>(a: readonly T[]): T => a[Math.floor(R() * a.length)];
const int = (lo: number, hi: number) => lo + Math.floor(R() * (hi - lo + 1));
const p2 = (n: number) => String(n).padStart(2, "0");
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export interface Meta { id: string; vendor: string; product: string; category: string; version: string; device: string; weight: number }
export const SOURCES: Meta[] = [
  { id: "fortinet.fortigate", vendor: "Fortinet", product: "FortiGate", category: "firewall", version: "1.0.0", device: "FGT-HQ", weight: 30 },
  { id: "cisco.asa", vendor: "Cisco", product: "ASA", category: "firewall", version: "1.0.0", device: "ASA-EDGE", weight: 20 },
  { id: "suricata.eve", vendor: "OISF", product: "Suricata EVE", category: "ids", version: "1.0.0", device: "ids-01", weight: 14 },
  { id: "cef.generic_firewall", vendor: "CEF", product: "Generic firewall", category: "firewall", version: "1.0.0", device: "cef-fw", weight: 8 },
  { id: "pfsense.filterlog", vendor: "Netgate", product: "pfSense", category: "firewall", version: "1.0.0", device: "pfSense", weight: 16 },
  { id: "squid.access", vendor: "Squid", product: "Squid proxy", category: "proxy", version: "1.0.0", device: "proxy-01", weight: 10 }
];

/* ── raw builder with byte-exact spans ─────────────────────────────── */
interface Fld { key: string; val: string; path?: string; typed?: unknown; expr?: string; extra?: { key: string; start: number; end: number }[] }
class B {
  s = "";
  fields: { f: Fld; spans: Span[] }[] = [];
  lit(t: string) { this.s += t; return this; }
  fld(f: Fld, text = f.val) {
    const start = Buffer.byteLength(this.s);
    this.s += text;
    this.fields.push({ f, spans: [{ start, end: start + Buffer.byteLength(text) }] });
    return this;
  }
}
const kv = (b: B, k: string, f: Fld, quote = false) => { b.lit(` ${k}=`); if (quote) b.lit('"'); b.fld(f); if (quote) b.lit('"'); };

function setPath(o: Record<string, unknown>, path: string, v: unknown) {
  const parts = path.split(".");
  let cur = o;
  for (let i = 0; i < parts.length - 1; i++) cur = (cur[parts[i]] ??= {}) as Record<string, unknown>;
  cur[parts[parts.length - 1]] = v;
}

export interface Flow {
  srcIp: string; srcPort: number; dstIp: string; dstPort: number; proto: "tcp" | "udp" | "icmp";
  deny: boolean; bytesIn: number; bytesOut: number; pktsIn: number; pktsOut: number; durS: number;
  user?: string; url?: string; sig?: string; sigSev?: number;
}
const PROTO_NUM = { tcp: 6, udp: 17, icmp: 1 } as const;
const MONTH = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const d = (t: number) => new Date(t);
const dateStr = (t: number) => `${d(t).getUTCFullYear()}-${p2(d(t).getUTCMonth() + 1)}-${p2(d(t).getUTCDate())}`;
const timeStr = (t: number) => `${p2(d(t).getUTCHours())}:${p2(d(t).getUTCMinutes())}:${p2(d(t).getUTCSeconds())}`;
const sysTs = (t: number) => `${MONTH[d(t).getUTCMonth()]} ${String(d(t).getUTCDate()).padStart(2, " ")} ${timeStr(t)}`;

interface Rendered { b: B; cls: number; activity: number; sev: number; extraDoc?: (doc: Record<string, unknown>) => void }

const PATHS_COMMON = (f: Flow) => ({ action_id: f.deny ? 2 : 1 });

function renderFortigate(f: Flow, t: number, live: boolean): Rendered {
  const b = new B();
  b.lit("<189>");
  b.lit("date=").fld({ key: "date", val: dateStr(t), path: "metadata.original_time", typed: `${dateStr(t)} ${timeStr(t)}`, expr: 'concat(date, " ", time)', extra: [] });
  b.lit(" time=").fld({ key: "time", val: timeStr(t) });
  kv(b, "devname", { key: "devname", val: "FGT-HQ", path: "device.hostname", expr: "devname" }, true);
  kv(b, "logid", { key: "logid", val: "0000000013" }, true);
  kv(b, "type", { key: "type", val: "traffic" }, true);
  kv(b, "level", { key: "level", val: "notice", path: "severity_id", typed: 1, expr: "level | lookup{notice:1,warning:2,…}" }, true);
  kv(b, "vd", { key: "vd", val: "root" }, true);
  kv(b, "srcip", { key: "srcip", val: f.srcIp, path: "src_endpoint.ip", expr: "srcip | ip" });
  kv(b, "srcport", { key: "srcport", val: String(f.srcPort), path: "src_endpoint.port", typed: f.srcPort, expr: "srcport | int | port" });
  kv(b, "srcintf", { key: "srcintf", val: "lan", path: "src_endpoint.interface_name", expr: "srcintf" }, true);
  kv(b, "dstip", { key: "dstip", val: f.dstIp, path: "dst_endpoint.ip", expr: "dstip | ip" });
  kv(b, "dstport", { key: "dstport", val: String(f.dstPort), path: "dst_endpoint.port", typed: f.dstPort, expr: "dstport | int | port" });
  kv(b, "dstintf", { key: "dstintf", val: "wan1", path: "dst_endpoint.interface_name", expr: "dstintf" }, true);
  kv(b, "proto", { key: "proto", val: String(PROTO_NUM[f.proto]), path: "connection_info.protocol_num", typed: PROTO_NUM[f.proto], expr: "proto | int" });
  kv(b, "action", { key: "action", val: f.deny ? "deny" : "accept", path: "action_id", typed: f.deny ? 2 : 1, expr: "action | lookup{accept:1, deny:2}" }, true);
  kv(b, "policyid", { key: "policyid", val: String(int(1, 40)) });
  kv(b, "service", { key: "service", val: f.dstPort === 22 ? "SSH" : f.dstPort === 443 ? "HTTPS" : "PING" }, true);
  kv(b, "duration", { key: "duration", val: String(f.durS), path: "duration", typed: f.durS * 1000, expr: "duration | int | mul(1000)" });
  kv(b, "sentbyte", { key: "sentbyte", val: String(f.bytesOut), path: "traffic.bytes_out", typed: f.bytesOut, expr: "sentbyte | int" });
  kv(b, "rcvdbyte", { key: "rcvdbyte", val: String(f.bytesIn), path: "traffic.bytes_in", typed: f.bytesIn, expr: "rcvdbyte | int" });
  if (live) kv(b, "srccountry", { key: "srccountry", val: "Reserved" }, true); // new field => schema drift demo
  return { b, cls: 4001, activity: 6, sev: 1 };
}

function renderAsa(f: Flow, t: number): Rendered {
  const b = new B();
  const id = f.deny ? "106023" : "302013";
  b.lit(`<${f.deny ? 164 : 166}>${sysTs(t)} `).fld({ key: "syslog.host", val: "ASA-EDGE", path: "device.hostname", expr: "syslog.host" }).lit(` : %ASA-${f.deny ? 4 : 6}-`).fld({ key: "msgid", val: id }).lit(": ");
  if (f.deny) {
    b.lit("Deny ").fld({ key: "proto", val: f.proto, path: "connection_info.protocol_name", expr: "proto | lower" }).lit(" src outside:")
      .fld({ key: "sip", val: f.srcIp, path: "src_endpoint.ip", expr: "sip | ip" }).lit("/").fld({ key: "sport", val: String(f.srcPort), path: "src_endpoint.port", typed: f.srcPort, expr: "sport | int | port" })
      .lit(" dst inside:").fld({ key: "dip", val: f.dstIp, path: "dst_endpoint.ip", expr: "dip | ip" }).lit("/").fld({ key: "dport", val: String(f.dstPort), path: "dst_endpoint.port", typed: f.dstPort, expr: "dport | int | port" })
      .lit(' by access-group "').fld({ key: "acl", val: "OUTSIDE_IN" }).lit('"');
  } else {
    b.lit("Built inbound ").fld({ key: "proto", val: f.proto.toUpperCase(), path: "connection_info.protocol_name", typed: f.proto, expr: "proto | lower" }).lit(" connection ").fld({ key: "connid", val: String(int(100000, 999999)) }).lit(" for outside:")
      .fld({ key: "sip", val: f.srcIp, path: "src_endpoint.ip", expr: "sip | ip" }).lit("/").fld({ key: "sport", val: String(f.srcPort), path: "src_endpoint.port", typed: f.srcPort, expr: "sport | int | port" })
      .lit(` (${f.srcIp}/${f.srcPort}) to inside:`).fld({ key: "dip", val: f.dstIp, path: "dst_endpoint.ip", expr: "dip | ip" }).lit("/").fld({ key: "dport", val: String(f.dstPort), path: "dst_endpoint.port", typed: f.dstPort, expr: "dport | int | port" })
      .lit(` (${f.dstIp}/${f.dstPort})`);
  }
  return { b, cls: 4001, activity: 6, sev: f.deny ? 2 : 1 };
}

function renderSuricata(f: Flow, t: number): Rendered {
  const b = new B();
  const ts = new Date(t).toISOString().replace("Z", "+0000");
  b.lit('{"timestamp":"').fld({ key: "timestamp", val: ts, path: "metadata.original_time", typed: ts, expr: "timestamp" }).lit('","event_type":"alert","src_ip":"')
    .fld({ key: "src_ip", val: f.srcIp, path: "src_endpoint.ip", expr: "src_ip | ip" }).lit('","src_port":').fld({ key: "src_port", val: String(f.srcPort), path: "src_endpoint.port", typed: f.srcPort, expr: "src_port | int | port" })
    .lit(',"dest_ip":"').fld({ key: "dest_ip", val: f.dstIp, path: "dst_endpoint.ip", expr: "dest_ip | ip" }).lit('","dest_port":').fld({ key: "dest_port", val: String(f.dstPort), path: "dst_endpoint.port", typed: f.dstPort, expr: "dest_port | int | port" })
    .lit(',"proto":"').fld({ key: "proto", val: f.proto.toUpperCase(), path: "connection_info.protocol_name", typed: f.proto, expr: "proto | lower" })
    .lit('","alert":{"signature":"').fld({ key: "alert.signature", val: f.sig ?? "ET SCAN Potential SSH Scan", path: "finding_info.title", expr: "alert.signature" })
    .lit('","signature_id":').fld({ key: "alert.signature_id", val: String(int(2000000, 2900000)), path: "finding_info.uid", expr: "alert.signature_id | str" })
    .lit(',"severity":').fld({ key: "alert.severity", val: String(f.sigSev ?? 2) }).lit('},"flow_id":').fld({ key: "flow_id", val: String(int(1e9, 9e9)) }).lit("}");
  return { b, cls: 2004, activity: 1, sev: f.sigSev ? f.sigSev + 1 : 3 };
}

function renderCef(f: Flow, t: number): Rendered {
  const b = new B();
  b.lit("CEF:0|Acme|Firewall|1.0|100|").fld({ key: "cef.name", val: f.deny ? "Traffic denied" : "Traffic allowed", path: "message", expr: "cef.name" }).lit("|").fld({ key: "cef.severity", val: f.deny ? "5" : "3", path: "severity_id", typed: f.deny ? 3 : 1, expr: "cef.severity | int" }).lit("|");
  b.lit("rt=").fld({ key: "rt", val: String(t), path: "time", typed: t, expr: "rt | epoch_ms" });
  b.lit(" src=").fld({ key: "src", val: f.srcIp, path: "src_endpoint.ip", expr: "src | ip" }).lit(" spt=").fld({ key: "spt", val: String(f.srcPort), path: "src_endpoint.port", typed: f.srcPort, expr: "spt | int | port" });
  b.lit(" dst=").fld({ key: "dst", val: f.dstIp, path: "dst_endpoint.ip", expr: "dst | ip" }).lit(" dpt=").fld({ key: "dpt", val: String(f.dstPort), path: "dst_endpoint.port", typed: f.dstPort, expr: "dpt | int | port" });
  b.lit(" proto=").fld({ key: "proto", val: f.proto.toUpperCase(), path: "connection_info.protocol_name", typed: f.proto, expr: "proto | lower" });
  b.lit(" act=").fld({ key: "act", val: f.deny ? "deny" : "allow", path: "action_id", typed: f.deny ? 2 : 1, expr: "act | lookup{allow:1, deny:2}" });
  b.lit(" cnt=").fld({ key: "cnt", val: String(int(1, 5)) });
  return { b, cls: 4001, activity: 6, sev: 1 };
}

function renderPf(f: Flow, t: number): Rendered {
  const b = new B();
  b.lit(`<134>${sysTs(t)} `).fld({ key: "syslog.host", val: "pfSense", path: "device.hostname", expr: "syslog.host" }).lit(` filterlog[${int(100, 9999)}]: `);
  b.fld({ key: "rule", val: String(int(1, 99)) }).lit(",,,").fld({ key: "tracker", val: String(int(1e9, 2e9)) }).lit(",").fld({ key: "iface", val: "igb0", path: "src_endpoint.interface_name", expr: "iface" }).lit(",match,")
    .fld({ key: "action", val: f.deny ? "block" : "pass", path: "action_id", typed: f.deny ? 2 : 1, expr: "action | lookup{pass:1, block:2}" }).lit(",in,4,0x0,,64,").fld({ key: "id", val: String(int(1, 65000)) }).lit(",0,none,")
    .fld({ key: "protonum", val: String(PROTO_NUM[f.proto]), path: "connection_info.protocol_num", typed: PROTO_NUM[f.proto], expr: "protonum | int" }).lit(",").fld({ key: "protoname", val: f.proto, path: "connection_info.protocol_name", expr: "protoname" }).lit(",")
    .fld({ key: "length", val: String(f.bytesOut) }).lit(",").fld({ key: "src", val: f.srcIp, path: "src_endpoint.ip", expr: "src | ip" }).lit(",").fld({ key: "dst", val: f.dstIp, path: "dst_endpoint.ip", expr: "dst | ip" }).lit(",")
    .fld({ key: "sport", val: String(f.srcPort), path: "src_endpoint.port", typed: f.srcPort, expr: "sport | int | port" }).lit(",").fld({ key: "dport", val: String(f.dstPort), path: "dst_endpoint.port", typed: f.dstPort, expr: "dport | int | port" }).lit(",0,S");
  return { b, cls: 4001, activity: 6, sev: 1 };
}

function renderSquid(f: Flow, t: number): Rendered {
  const b = new B();
  const status = f.deny ? 403 : 200;
  b.fld({ key: "ts", val: (t / 1000).toFixed(3), path: "time", typed: t, expr: "ts | epoch_s" }).lit("    ").fld({ key: "elapsed", val: String(int(5, 900)) }).lit(" ")
    .fld({ key: "client", val: f.srcIp, path: "src_endpoint.ip", expr: "client | ip" }).lit(" ").fld({ key: "result", val: f.deny ? "TCP_DENIED" : "TCP_MISS" }).lit("/").fld({ key: "status", val: String(status), path: "http_response.code", typed: status, expr: "status | int" }).lit(" ")
    .fld({ key: "bytes", val: String(f.bytesIn), path: "traffic.bytes_in", typed: f.bytesIn, expr: "bytes | int" }).lit(" ").fld({ key: "method", val: "GET", path: "http_request.http_method", expr: "method" }).lit(" ")
    .fld({ key: "url", val: f.url ?? `http://${f.dstIp}/index.html`, path: "http_request.url.text", expr: "url" }).lit(" ").fld({ key: "user", val: f.user ?? "-", path: "actor.user.name", expr: "user" }).lit(" HIER_DIRECT/")
    .fld({ key: "peer", val: f.dstIp, path: "dst_endpoint.ip", expr: "peer | ip" }).lit(" ").fld({ key: "mime", val: "text/html" });
  return { b, cls: 4002, activity: 6, sev: 1 };
}

/* ── MikroTik: the "unseen" source (unparsed until onboarded) ──────── */
const MAC = () => Array.from({ length: 6 }, () => int(0, 255).toString(16).padStart(2, "0")).join(":");
export function mikrotikLine(): { line: string; f: Flow } {
  const proto = pick(["TCP", "UDP", "ICMP"] as const);
  const f: Flow = { srcIp: pick(["192.168.88.254", "192.168.88.10", "203.0.113.50", "192.168.88.77"]), srcPort: int(1024, 65000), dstIp: pick(["8.8.8.8", "192.168.88.1", "1.1.1.1", "192.0.2.99"]), dstPort: pick([443, 53, 80, 22]), proto: proto.toLowerCase() as Flow["proto"], deny: false, bytesIn: 0, bytesOut: int(40, 1500), pktsIn: 1, pktsOut: 1, durS: 0 };
  const chain = pick(["forward", "input"]);
  const ports = proto === "ICMP" ? "" : `:${f.srcPort}`;
  const portsD = proto === "ICMP" ? "" : `:${f.dstPort}`;
  const flags = proto === "TCP" ? ` (${pick(["SYN", "ACK", "FIN,ACK", "SYN,ACK"])})` : proto === "ICMP" ? " (type 8, code 0)" : "";
  const line = `firewall,info ${chain}: in:${pick(["bridge", "ether1"])} out:${pick(["ether1", "(unknown 0)"])}, src-mac ${MAC()}, proto ${proto}${flags}, ${f.srcIp}${ports}->${f.dstIp}${portsD}, len ${f.bytesOut}`;
  return { line, f };
}
export const MIKROTIK_RE = /^firewall,(?<topic>\w+) (?<chain>\w+): in:(?<in_if>\S+) out:(?<out_if>.+?), src-mac (?<src_mac>[0-9a-f:]{17}), proto (?<proto>\w+)(?: \((?<flags>[^)]*)\))?, (?<src_ip>[\d.]+)(?::(?<src_port>\d+))?->(?<dst_ip>[\d.]+)(?::(?<dst_port>\d+))?, len (?<len>\d+)$/;

/* ── event assembly ────────────────────────────────────────────────── */
export interface StoredEvent {
  row: EventRow;
  doc: OcsfEvent;
  raw: string;
  explain: ExplainResponse | null;
  seg: string; block: number; idx: number;
}

let seq = 0;
const segSize = 5000;
const blockSize = 500;
export const nodeId = "n1";
export const segName = (n: number) => `${nodeId}-${String(n).padStart(6, "0")}`;
export const published = new Set<string>();

export function eventId(t: number) {
  const hex = t.toString(16).padStart(12, "0");
  const r = randomBytes(10).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8)}-7${r.slice(0, 3)}-${r.slice(3, 7)}-${r.slice(7, 19)}:0`;
}

export function randomFlow(sourceId: string): Flow {
  const internal = () => `10.1.${int(1, 4)}.${int(2, 250)}`;
  const external = () => pick([`142.250.${int(60, 90)}.${int(2, 250)}`, `151.101.${int(0, 255)}.${int(2, 250)}`, `93.184.216.${int(2, 250)}`, `52.${int(1, 120)}.${int(0, 255)}.${int(2, 250)}`]);
  const proto = pick(["tcp", "tcp", "tcp", "udp", "icmp"] as const);
  const dstPort = proto === "icmp" ? 0 : pick([443, 443, 443, 80, 53, 22, 3389, 8080, 123]);
  const deny = R() < 0.14;
  const out = int(60, 4000);
  return {
    srcIp: sourceId === "cisco.asa" || sourceId === "suricata.eve" ? external() : internal(), srcPort: int(1024, 65000),
    dstIp: sourceId === "cisco.asa" || sourceId === "suricata.eve" ? internal() : external(), dstPort, proto, deny,
    bytesOut: out, bytesIn: deny ? 0 : int(100, 90000), pktsOut: Math.ceil(out / 700), pktsIn: deny ? 0 : int(1, 80), durS: deny ? 0 : int(0, 120),
    user: R() < 0.5 ? pick(["alice", "bob", "carol", "-"]) : "-", url: `http://${pick(["example.com", "updates.vendor.net", "cdn.static.io"])}/${pick(["index.html", "a.js", "img.png", "api/v1/ping"])}`,
    sig: pick(["ET SCAN Potential SSH Scan", "ET POLICY Suspicious inbound to MSSQL", "ET MALWARE Possible C2 beacon", "GPL ICMP_INFO PING"]), sigSev: int(1, 3)
  };
}

const RENDER: Record<string, (f: Flow, t: number, live: boolean) => Rendered> = {
  "fortinet.fortigate": renderFortigate, "cisco.asa": renderAsa, "suricata.eve": renderSuricata,
  "cef.generic_firewall": renderCef, "pfsense.filterlog": renderPf, "squid.access": renderSquid
};
const FORMAT: Record<string, ExplainResponse["format"]> = {
  "fortinet.fortigate": "kv", "cisco.asa": "regex", "suricata.eve": "json", "cef.generic_firewall": "cef", "pfsense.filterlog": "csv", "squid.access": "regex"
};

export function makeEvent(sourceId: string, f: Flow, t: number, opts: { live?: boolean; forceStatus?: EventStatus } = {}): StoredEvent {
  const n = seq++;
  const segN = Math.floor(n / segSize);
  const block = Math.floor((n % segSize) / blockSize);
  const idx = (n % segSize) % blockSize;
  const id = eventId(t);
  let status: EventStatus = opts.forceStatus ?? (R() < 0.025 ? "partial" : "parsed");
  let raw: string;
  let doc: Record<string, unknown> = {};
  let explain: ExplainResponse | null = null;
  let source = sourceId;
  let coverage = 0.9 + R() * 0.1;

  if (sourceId === "mikrotik.unseen" && !published.has("mikrotik.routeros_firewall")) {
    const m = mikrotikLine();
    raw = m.line;
    status = "unparsed";
    source = "unknown";
    coverage = 0;
    doc = { class_uid: 0, category_uid: 0, activity_id: 0, type_uid: 0, time: t, message: raw };
  } else if (sourceId === "mikrotik.unseen") {
    const m = mikrotikLine();
    raw = m.line;
    source = "mikrotik.routeros_firewall";
    const g = MIKROTIK_RE.exec(raw)!.groups!;
    doc = { class_uid: 4001, category_uid: 4, activity_id: 6, type_uid: 400106, time: t, src_endpoint: { ip: g.src_ip, port: g.src_port ? +g.src_port : undefined, interface_name: g.in_if }, dst_endpoint: { ip: g.dst_ip, port: g.dst_port ? +g.dst_port : undefined, interface_name: g.out_if }, connection_info: { protocol_name: g.proto.toLowerCase() }, traffic: { bytes_out: +g.len }, unmapped: { chain: g.chain, src_mac: g.src_mac, topic: g.topic, ...(g.flags ? { flags: g.flags } : {}) } };
    coverage = 0.86;
  } else {
    const r = RENDER[sourceId](f, t, !!opts.live);
    raw = r.b.s;
    const mapped: ExplainField[] = [];
    const unmapped: ExplainUnmapped[] = [];
    const um: Record<string, unknown> = {};
    doc = { class_uid: r.cls, category_uid: Math.floor(r.cls / 1000), activity_id: r.activity, type_uid: r.cls * 100 + r.activity, time: t, severity_id: r.sev, ...PATHS_COMMON(f) };
    if (r.cls === 2004) { delete doc.action_id; }
    const seen = new Set<string>();
    for (const { f: fl, spans } of r.b.fields) {
      if (fl.path) {
        if (seen.has(fl.path)) continue;
        seen.add(fl.path);
        const value = fl.typed ?? fl.val;
        setPath(doc, fl.path, value);
        mapped.push({ ocsf_path: fl.path, value, source_fields: [fl.key], spans, expr: fl.expr ?? fl.key, pack_rule: `${sourceId}#classes.${r.cls === 2004 ? "detection_finding" : r.cls === 4002 ? "http_activity" : "network_activity"}.set` });
      } else {
        um[fl.key] = fl.val;
        unmapped.push({ field: fl.key, value: fl.val, spans });
      }
    }
    doc.unmapped = um;
    coverage = mapped.length / Math.max(1, mapped.length + unmapped.length);
    if (status === "partial") coverage *= 0.7;
    explain = { event_id: id, source_id: sourceId, pack_id: sourceId, pack_version: "1.0.0", format: FORMAT[sourceId], raw_len: Buffer.byteLength(raw), spans_exact: FORMAT[sourceId] !== "json", fields: mapped, unmapped };
  }
  const meta = SOURCES.find((s) => s.id === source);
  const ref = `${segName(segN)}/${block}/${idx}`;
  const doc2 = doc as Record<string, unknown>;
  const prevOrig = (doc2.metadata as { original_time?: string } | undefined)?.original_time;
  doc2.metadata = { version: "1.3.0", uid: id, original_time: prevOrig ?? dateStr(t) + " " + timeStr(t), product: { name: meta?.product ?? "unknown", vendor_name: meta?.vendor ?? "unknown" } };
  if (!doc2.unmapped) doc2.unmapped = {};
  const lin = { event_id: id, raw_ref: ref, raw_sha256: sha(raw), recv_time: t + int(1, 40), collector_id: nodeId, transport: sourceId === "squid.access" ? "file" : "udp", peer_ip: `10.0.0.${int(1, 9)}`, source_id: source, pack_version: meta?.version ?? "0.0.0", schema: "ocsf-1.3.0", status, coverage: +coverage.toFixed(3), time_quality: "source_tz" as const, ...(status === "unparsed" ? { template_id: "t-" + sha(raw.replace(/[\d.:a-f]+/g, "*")).slice(0, 8) } : {}) };
  doc2.ulpf = lin;
  const full = doc2 as unknown as OcsfEvent;
  const se = full.src_endpoint, de = full.dst_endpoint;
  const rec = doc2 as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  const row: EventRow = {
    event_id: id, raw_ref: ref, time: t, recv_time: lin.recv_time, class_uid: full.class_uid, activity_id: full.activity_id ?? null, severity_id: full.severity_id ?? null,
    action_id: full.action_id ?? null, status, source_id: source, src_ip: se?.ip ?? null, src_port: se?.port ?? null, dst_ip: de?.ip ?? null, dst_port: de?.port ?? null,
    proto_name: full.connection_info?.protocol_name ?? null, bytes_in: full.traffic?.bytes_in ?? null, bytes_out: full.traffic?.bytes_out ?? null,
    user_name: rec.actor?.user?.name ?? null, url: rec.http_request?.url?.text ?? null, dns_query: null,
    signature: rec.finding_info?.title ?? null, device_host: rec.device?.hostname ?? null, coverage: lin.coverage
  };
  if (explain) explain.event_id = id;
  return { row, doc: full, raw, explain, seg: segName(segN), block, idx };
}

export function resetSeq() { seq = 0; }
export const SEG_SIZE = segSize;
export const BLOCK_SIZE = blockSize;
export const totalMade = () => seq;
export { pick, int };
