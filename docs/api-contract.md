# UI ⇄ API contract (`/api/v1`)

This is exactly what `ui/` expects. The authoritative TypeScript is `ui/src/api/types.ts`; the HTTP calls are in
`ui/src/api/client.ts`. If the backend needs to differ, change **both** in the same commit (R2).

Rules the UI relies on:

* **R9** — every number shown comes from these responses. The UI has no demo data; an unreachable API shows an
  explicit "can't reach the API" state, never fabricated rows.
* All times are **epoch milliseconds (UTC)**. The UI renders UTC.
* All JSON. Errors are `HTTP 4xx/5xx` with `{"error": {"code": "STRING", "message": "human text"}}`
  (FastAPI's default `{"detail": "..."}` is also tolerated). `400` on `/events*` with `code: "BAD_QUERY"` is shown inline as
  "the server rejected this query". `502/503/504` and network failures are treated as **API down**.
* Auth: optional static bearer. UI sends `Authorization: Bearer <localStorage.ulpf_token>` when set. Because browsers
  cannot set headers on WebSocket / `<a download>`, **`?access_token=<token>` must also be accepted** on `WS /stream` and
  `GET /export/*`.
* Dev-mock responses carry `X-ULPF-Mock: 1`; the real API must **not** send it.
* The built UI is served by the API process itself (`ui/dist`, static files + SPA fallback to `index.html`); any unknown path under
  `/api/` is a JSON `404 NOT_FOUND`, never the SPA. `POST /ingest/raw` (HTTP ingest) lives outside `/api/v1`.
* Events are identified by `event_id` (`"<raw_id>:<n>"`), URL-encoded in paths (`:` is legal but encode anyway).

Endpoints marked **(ext)** are not listed in IMPLEMENTATION_GUIDE §7.13; they are small additions the UI needs.
Add them to §7.13 when the API lands.

---

## Shared shapes

```ts
type EventStatus = "parsed" | "partial" | "unparsed";

// Thin row projection of the lake schema (§7.9). Used by /events, WS /stream, detections evidence.
interface EventRow {
  event_id: string; raw_ref: string;          // "n1-000042/17/233"
  time: number; recv_time: number;            // epoch ms
  class_uid: number;                          // 4001, 4002, 4003, 3002, 2004, 0
  activity_id: number | null; severity_id: number | null; action_id: number | null; // OCSF ints; action_id 1=allowed 2=denied
  status: EventStatus; source_id: string;     // e.g. "fortinet.fortigate"; "unknown" is fine for unparsed
  src_ip: string | null; src_port: number | null; dst_ip: string | null; dst_port: number | null;
  proto_name: string | null; bytes_in: number | null; bytes_out: number | null;
  user_name: string | null; url: string | null; dns_query: string | null;
  signature: string | null; device_host: string | null;
  coverage: number;                           // 0..1
}
interface TailRow extends EventRow { message?: string }   // optional lossy-safe raw preview (<=140 chars)
```

Full event document (`GET /events/{id}`) is the §6.2 OCSF shape verbatim, including `unmapped{}` and the `ulpf{}` lineage
object (`event_id, raw_ref, raw_sha256, recv_time, collector_id, transport, peer_ip, source_id, pack_version, schema,
status, coverage, time_quality`, optional `template_id`, `truncated`, `ignored`).

**Synthetic events** (analytics findings, `ulpf.source_id = "ulpf.analytics"`) carry `ulpf.synthetic: true` and have **no
`raw_ref` / `raw_sha256`** (they have no wire bytes; the document's `evidences[]` cite the raw lines by `raw_ref`). For them
`GET /events/{id}/raw` is `404 {code:"NO_RAW"}` and `/explain` is `404 {code:"NO_PACK"}`. The UI hides Verify and shows the
evidence list instead.

---

## Health (ext)

`GET /health` → `{ "status": "ok"|"degraded", "version": str, "node_id": str, "ocsf_version": str, "time": ms }`
Polled every 5 s for the connection indicator.

## Events

### `GET /events`
Query: `from, to` (ms), `class` (uid), `source` (source_id), `status`, `q` (field DSL, see below), `limit` (≤500), `cursor`.
→ `{ "items": EventRow[], "next_cursor": string|null, "took_ms": number, "total_estimate"?: number|null }`
Newest first. `next_cursor: null` ends pagination. Invalid `q` → `400 BAD_QUERY` with a precise message.

**Query DSL the UI validates client-side** (server stays authoritative; whitelist + parameterised SQL):
`term := ['-'] ( field ':' [op] value | text )`, terms are AND-ed, whitespace separated. `op` ∈ `>= <= > <` (numeric/time fields only).
`value` may be quoted (`"a b"`, `\"` escape), a comma list (`22,2222` = OR), or a numeric range `1000..5000`.
IP fields accept CIDR (`10.0.0.0/8`) and trailing wildcards (`10.1.*`). String fields accept `*` wildcards.
`text` (bare/quoted) matches the raw message. `action:denied|allowed` is an alias over `action_id`.
Field names: the lake columns of §7.9 (`src_ip dst_ip src_port dst_port proto_name proto_num action action_id activity_id
severity_id class_uid status source_id bytes_in bytes_out packets_in packets_out duration_ms user_name url http_method
http_status dns_query signature device_host coverage event_id raw_ref`).

### `GET /events/fields` (ext, optional)
→ `{ "fields": { name: str, type: "string"|"ip"|"int"|"float"|"time"|"enum", description?: str, enum?: str[], suggest?: bool }[] }`
`suggest: true` means `GET /events/values` can hint that field (the UI only asks for those; when the flag is absent it assumes
`type === "string"`). Replaces the UI's built-in copy of the lake schema when present (404 is fine; the UI falls back).

### `GET /events/values?field=&prefix=&limit=` (ext, optional)
→ `{ "values": string[] }` — autocomplete hints for fields flagged `suggest` in `/events/fields` (e.g. `device_host`, `source_id`).
`400 BAD_QUERY` for any other field; 404 for the whole endpoint is tolerated.

### `GET /events/histogram` (ext)
Same filters as `/events` plus `buckets` (target count, 10–200).
→ `{ "from": ms, "to": ms, "interval_ms": number, "buckets": { "t": ms, "parsed": n, "partial": n, "unparsed": n }[] }`
Buckets are contiguous, `t` = bucket start. The UI draws them stacked and lets the user drag a window to zoom.

### `GET /events/{event_id}` → OCSF document (§6.2). `404` if unknown.

### `GET /events/{event_id}/raw`
```ts
{ event_id, raw_ref, segment: str, block: int, idx: int, size: int,
  data_b64: string,                 // EXACT raw bytes, base64
  sha256_expected: string,          // hex, recorded at ingest
  sha256_actual: string,            // hex, recomputed from the vault bytes just now
  verified: boolean,                // expected === actual
  error?: { code: "IntegrityError"|string, message: string } | null }
```
The block is **always re-read from the vault file** (never from the reader's block cache), so "Verify" reflects what is on disk now.
On tamper return **HTTP 200** with `verified:false` + `error` (and the offending bytes in `data_b64` if readable) so the UI can show them
beside the failure. An HTTP error whose `error.code === "IntegrityError"` is also handled.

### `GET /events/{event_id}/explain` (§7.10)
```ts
{ event_id, source_id, pack_id, pack_version,
  format: "kv"|"regex"|"csv"|"cef"|"leef"|"json"|"xml"|"tsv"|"text",
  raw_len: int,
  spans_exact: boolean,             // false => json/xml display-only highlighting
  fields:   { ocsf_path: string, value: any, source_fields: string[], spans: {start,end}[], expr: string, pack_rule: string }[],
  unmapped: { field: string, value: any, spans: {start,end}[] }[],
  ignored?: { field: string, reason: string, spans?: {start,end}[] }[] }
```
**Span offsets are BYTE offsets into the raw bytes, `start` inclusive, `end` exclusive**, indexing the same bytes `/raw` returns.
`ocsf_path` is the dotted path into the event document (`src_endpoint.ip`), which is how the UI links tree rows ⇄ bytes.
Unparsed events: `404 {code:"NO_PACK"}` (the UI shows raw bytes without spans).

## Live stream — `WS /stream`
Client → server (sent on open and whenever filters change):
`{ "op": "filter", "q": string, "sources": string[], "statuses": EventStatus[] }` (empty arrays/strings = no filter).
Server → client:
```ts
{ "type": "hello", "server_time": ms, "buffer": int }
{ "type": "batch", "events": TailRow[], "dropped"?: int }   // dropped = rows skipped for this connection by backpressure
{ "type": "error", "message": string }
```
Batch every ~50–250 ms; the UI keeps the newest 5,000 rows in a ring buffer and computes eps from arrivals.

## Sources

### `GET /sources` → `{ "items": SourceSummary[] }`
```ts
SourceSummary { source_id, vendor, product, category, pack_version, verified: boolean,
  eps: number,                                  // current events/sec
  eps_series: { t: ms, v: number }[],           // >= 2 points, oldest first (e.g. 60 x 5 s)
  parse_rate: number,                           // 0..1 parsed / total
  mean_coverage: number,                        // 0..1
  last_seen: ms | null, total_events: int,
  status_counts: { parsed: int, partial: int, unparsed: int },
  top_unmapped: { field: string, count: int }[],
  drift: { flag: boolean, reasons: string[] } } // reasons are human sentences
```
### `GET /sources/{source_id}/health` → `SourceSummary &`
`{ coverage_series: {t,v}[], parse_rate_series: {t,v}[], unmapped_all: { field, count, example? }[], peers: { ip, events, last_seen }[] }`
(`coverage_series`/`parse_rate_series` values are 0..1.)

## Integrity & ledger

### `GET /ledger`
```ts
LedgerCounts { ingested, vaulted, normalized_parsed, normalized_partial, unparsed, sunk, dropped, in_flight }  // all ints
{ as_of: ms, totals: LedgerCounts, per_source: ({ source: string } & LedgerCounts)[],
  conserved: boolean, dropped_by_reason: { [reason: string]: int }, sunk_by_sink: { [sink: string]: int } }
```
Invariant the UI re-checks per row: `ingested == sunk + dropped + in_flight`. `conserved` is the server's verdict
(ingested = vaulted = normalized+unparsed = sunk; dropped == 0 unless explicitly configured). If the two disagree the UI says so.

### `GET /vault/segments` (ext) → `{ "items": VaultSegment[] }`
```ts
VaultSegment { segment, node_id, created_ms, sealed_ms: ms|null, n_events, n_blocks, size_bytes, chain_head: hex,
  chain_status: "ok"|"open"|"unverified"|"broken", signature_ok: boolean|null, last_verified_ms: ms|null,
  error?: { block: int, frame: int|null, message: string } | null }
```
### `POST /vault/verify`  body `{ "all": true } | { "segment": "n1-000042" }`
Response `application/x-ndjson`, flushed per line:
```
{"type":"progress","segment":S,"done":n,"total":n}
{"type":"segment_result","segment":S,"ok":bool,"blocks_checked":n,"frames_checked":n,"error":{"block":n,"frame":n|null,"message":str}|null}
{"type":"done","ok":bool,"segments_checked":n,"frames_checked":n,"duration_ms":n,"first_failure":{"segment":S,"block":n,"frame":n|null}|null}
```

## Detections — `GET /analytics/detections`
```ts
{ items: { finding_id, event_id /* the Detection Finding (2004) event */, time: ms, title, severity_id: 0..6, score: 0..1,
    entity: { kind: "src_ip"|…, value: string }, window: { start: ms, end: ms }, summary: string,
    features: { name, value, baseline, z }[], sources: string[],
    evidence_total: int, evidence: EventRow[] /* top-N contributing events, full rows */ }[],
  baseline?: { windows_scored: int, false_positives: int|null } | null }
```
The UI links `entity.kind:entity.value` into the Explorer and each evidence row into Event Detail.

## Onboarding Studio

### `GET /onboard/clusters` (ext) → `{ "items": TemplateCluster[] }`
```ts
TemplateCluster { template_id, template: string, count: int, share: 0..1 /* of all unparsed */, example_raw: string,
                  samples?: string[] /* a few raw lines, loaded into the Studio on "Onboard" */, peer_ips?: string[], first_seen?: ms, last_seen?: ms }
```
### `POST /onboard/analyze`  body `{ samples: string[], vendor?: string, product?: string }`
```ts
{ analysis_id, format: string, format_confidence: 0..1, class_name: string, class_uid: int, pack_id: string,
  draft_pack_yaml: string, templates: TemplateCluster[],
  fields: { name, type, example, ocsf_path: string|null, confidence: 0..1 }[],
  coverage: Coverage, est_minutes: number|null, warnings: string[] }
Coverage { lines_total, lines_matched, lines_matched_pct: 0..1, fields_mapped_pct: 0..1, mean_event_coverage: 0..1,
           unmapped: { field, count }[] }
```
### `POST /onboard/preview`  body `{ pack_yaml: string, samples: string[] }` (called ~650 ms after each edit)
```ts
{ ok: boolean, lint: { level: "error"|"warning", message, line?: int|null }[],
  tests: { passed: int, failed: int, failures?: { name, message }[] }, coverage: Coverage,
  rows: { line_no: int /*1-based index into samples*/, status: EventStatus, coverage: 0..1, class_uid: int|null,
          raw: string, mapped: { [ocsf_path]: any }, unmapped: { [field]: any } }[] }
```
`ok:false` or any `error` lint disables Publish. `line` is 1-based in `pack_yaml` and drives Monaco markers.
### `POST /onboard/publish`  body `{ pack_yaml: string }` → `{ published: boolean, pack_id, version, path, reloaded: boolean }`

## Benchmark — `GET /benchmark` (ext)
Serves `bench/results.json` as-is; `404` when no run exists (the UI shows "run `ulpf bench`").
```ts
{ generated_at: ms,
  hardware: { cpu: string, cores: int, ram_gb: number, os: string, python?: string, storage?: string, label?: string },
  config: { mix?: string, duration_s: number, events?: int, workers_list?: int[] },
  sustained: { eps: number, per_worker_eps?: number, projected_daily_events?: number },
  scaling: { workers: int, eps: number }[],                  // >= 2 points draws the scaling chart (+ ideal-linear line from the first point)
  latency_ms: { p50: number, p95?: number, p99: number, max?: number },   // ingest -> queryable
  resources?: { cpu_pct?: number, rss_mb?: number }, vault?: { compression_ratio?: number }, lake?: { bytes_per_event?: number },
  ledger?: { ingested: int, lost: int, conserved: boolean }, accuracy?: { precision: 0..1, recall: 0..1 }, parse_rate?: 0..1,
  targets?: { eps?: number, eps_stretch?: number, latency_p99_ms?: number } }   // optional reference lines; never defaulted by the UI
```
Every optional section is simply omitted from the page when absent.

## Export — `GET /export/{csv|json|arrow}`
Same filters as `/events` (no `limit`/`cursor`); returns a file (`Content-Disposition: attachment`). Arrow may be `501`.

## Metrics — `GET /metrics`
Prometheus text; not used by the UI.
