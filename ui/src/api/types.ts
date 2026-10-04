/**
 * Typed shapes for the ULPF API (/api/v1). Single source of truth for the UI; the
 * human-readable twin is docs/api-contract.md. Event shapes follow IMPLEMENTATION_GUIDE §6.2.
 */

export type EventStatus = "parsed" | "partial" | "unparsed";
export type TimeQuality = "source_tz" | "assumed_tz" | "recv_time";

/** §6.2 `ulpf` lineage extension object. */
export interface UlpfLineage {
  event_id: string;
  /** Absent on synthetic events (analytics findings): they have no raw bytes of their own, only `evidences`. */
  raw_ref?: string;
  raw_sha256?: string;
  synthetic?: boolean;
  recv_time: number;
  collector_id: string;
  transport: string;
  peer_ip: string;
  source_id: string;
  pack_version: string;
  schema: string;
  status: EventStatus;
  coverage: number;
  time_quality: TimeQuality;
  template_id?: string;
  truncated?: boolean;
  ignored?: Record<string, number | string>;
}

export interface Endpoint {
  ip?: string;
  port?: number;
  interface_name?: string;
  [k: string]: unknown;
}

/** §6.2 normalized OCSF event (full document, GET /events/{id}). Open-ended on purpose. */
export interface OcsfEvent {
  class_uid: number;
  category_uid: number;
  activity_id: number;
  type_uid: number;
  time: number;
  severity_id?: number;
  action_id?: number;
  disposition_id?: number;
  src_endpoint?: Endpoint;
  dst_endpoint?: Endpoint;
  connection_info?: { protocol_num?: number; protocol_name?: string };
  traffic?: { bytes_out?: number; bytes_in?: number; packets_out?: number; packets_in?: number };
  duration?: number;
  device?: { hostname?: string };
  metadata: {
    version: string;
    uid: string;
    original_time?: string;
    product?: { name?: string; vendor_name?: string };
  };
  unmapped?: Record<string, unknown>;
  ulpf: UlpfLineage;
  [k: string]: unknown;
}

/** Thin row projection of the lake schema (§7.9) used by lists, live tail, evidence. */
export interface EventRow {
  event_id: string;
  raw_ref: string;
  time: number; // epoch ms
  recv_time: number; // epoch ms
  class_uid: number;
  activity_id: number | null;
  severity_id: number | null;
  action_id: number | null;
  status: EventStatus;
  source_id: string;
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
  proto_name: string | null;
  bytes_in: number | null;
  bytes_out: number | null;
  user_name: string | null;
  url: string | null;
  dns_query: string | null;
  signature: string | null;
  device_host: string | null;
  coverage: number; // 0..1
}

/** Live tail rows additionally carry a short, lossy-safe raw preview. */
export interface TailRow extends EventRow {
  message?: string;
}

export type FieldType = "string" | "ip" | "int" | "float" | "time" | "enum";

export interface QueryField {
  name: string;
  type: FieldType;
  description?: string;
  enum?: string[];
  /** true when GET /events/values can hint this field; when the server omits it the UI assumes `type === "string"`. */
  suggest?: boolean;
}

export interface EventsPage {
  items: EventRow[];
  next_cursor: string | null;
  took_ms: number;
  /** Approximate total matching rows (optional). */
  total_estimate?: number | null;
}

export interface EventsFilter {
  from?: number;
  to?: number;
  class?: number | null;
  source?: string | null;
  status?: EventStatus | null;
  q?: string;
}

export interface HistogramBucket {
  t: number; // bucket start, epoch ms
  parsed: number;
  partial: number;
  unparsed: number;
}
export interface Histogram {
  from: number;
  to: number;
  interval_ms: number;
  buckets: HistogramBucket[];
}

export interface RawResponse {
  event_id: string;
  raw_ref: string;
  segment: string;
  block: number;
  idx: number;
  size: number;
  /** Base64 of the EXACT raw bytes. */
  data_b64: string;
  sha256_expected: string;
  sha256_actual: string;
  verified: boolean;
  error?: { code: "IntegrityError" | string; message: string } | null;
}

export interface Span {
  start: number; // byte offset, inclusive
  end: number; // byte offset, exclusive
}

export interface ExplainField {
  ocsf_path: string;
  value: unknown;
  source_fields: string[];
  spans: Span[];
  expr: string;
  pack_rule: string;
}
export interface ExplainUnmapped {
  field: string;
  value: unknown;
  spans: Span[];
}
export interface ExplainResponse {
  event_id: string;
  source_id: string;
  pack_id: string;
  pack_version: string;
  format: "kv" | "regex" | "csv" | "cef" | "leef" | "json" | "xml" | "tsv" | "text";
  raw_len: number;
  /** false when spans are display-only approximations (json/xml pretty-print). */
  spans_exact: boolean;
  fields: ExplainField[];
  unmapped: ExplainUnmapped[];
  ignored?: { field: string; reason: string; spans?: Span[] }[];
}

export interface HealthResponse {
  status: "ok" | "degraded";
  version: string;
  node_id: string;
  ocsf_version: string;
  time: number;
}

export interface SeriesPoint {
  t: number;
  v: number;
}

export interface SourceSummary {
  source_id: string;
  vendor: string;
  product: string;
  category: string;
  pack_version: string;
  verified: boolean;
  eps: number;
  eps_series: SeriesPoint[];
  parse_rate: number; // 0..1  (parsed / total)
  mean_coverage: number; // 0..1
  last_seen: number | null; // epoch ms
  total_events: number;
  status_counts: Record<EventStatus, number>;
  top_unmapped: { field: string; count: number }[];
  drift: { flag: boolean; reasons: string[] };
}
export interface SourcesResponse {
  items: SourceSummary[];
}
export interface SourceHealth extends SourceSummary {
  coverage_series: SeriesPoint[];
  parse_rate_series: SeriesPoint[];
  unmapped_all: { field: string; count: number; example?: string }[];
  peers: { ip: string; events: number; last_seen: number }[];
}

export interface LedgerCounts {
  ingested: number;
  vaulted: number;
  normalized_parsed: number;
  normalized_partial: number;
  unparsed: number;
  sunk: number;
  dropped: number;
  in_flight: number;
}
export interface LedgerResponse {
  as_of: number;
  totals: LedgerCounts;
  /** Server's own verdict: ingested == vaulted == normalized+unparsed == sunk + dropped, minus in_flight. */
  conserved: boolean;
  per_source: ({ source: string } & LedgerCounts)[];
  dropped_by_reason: Record<string, number>;
  sunk_by_sink: Record<string, number>;
}

export type ChainStatus = "ok" | "open" | "unverified" | "broken";
export interface VaultSegment {
  segment: string;
  node_id: string;
  created_ms: number;
  sealed_ms: number | null;
  n_events: number;
  n_blocks: number;
  size_bytes: number;
  chain_head: string;
  chain_status: ChainStatus;
  signature_ok: boolean | null;
  last_verified_ms: number | null;
  error?: { block: number; frame: number | null; message: string } | null;
}
export interface VaultSegmentsResponse {
  items: VaultSegment[];
}

export type VerifyMessage =
  | { type: "progress"; segment: string; done: number; total: number }
  | {
      type: "segment_result";
      segment: string;
      ok: boolean;
      blocks_checked: number;
      frames_checked: number;
      error?: { block: number; frame: number | null; message: string } | null;
    }
  | {
      type: "done";
      ok: boolean;
      segments_checked: number;
      frames_checked: number;
      duration_ms: number;
      first_failure?: { segment: string; block: number; frame: number | null } | null;
    };

export interface DetectionFeature {
  name: string;
  value: number;
  baseline: number;
  z: number;
}
export interface Detection {
  finding_id: string;
  event_id: string; // the Detection Finding (2004) event itself
  time: number;
  title: string;
  severity_id: number;
  score: number; // 0..1 anomaly score
  entity: { kind: string; value: string };
  window: { start: number; end: number };
  summary: string;
  features: DetectionFeature[];
  sources: string[];
  evidence_total: number;
  /** Top-N contributing events (full rows) so the UI can drill down without N+1 calls. */
  evidence: EventRow[];
}
export interface DetectionsResponse {
  items: Detection[];
  baseline?: { windows_scored: number; false_positives: number | null } | null;
}

export interface SampleAnalysisField {
  name: string;
  type: string;
  example: string;
  ocsf_path: string | null;
  confidence: number; // 0..1
}
export interface TemplateCluster {
  template_id: string;
  template: string;
  count: number;
  share: number; // 0..1 of all unparsed
  example_raw: string;
  samples?: string[];
  peer_ips?: string[];
  first_seen?: number;
  last_seen?: number;
}
export interface Coverage {
  lines_total: number;
  lines_matched: number;
  lines_matched_pct: number; // 0..1
  fields_mapped_pct: number; // 0..1
  mean_event_coverage: number; // 0..1
  unmapped: { field: string; count: number }[];
}
export interface AnalyzeResponse {
  analysis_id: string;
  format: string;
  format_confidence: number;
  class_name: string;
  class_uid: number;
  pack_id: string;
  draft_pack_yaml: string;
  templates: TemplateCluster[];
  fields: SampleAnalysisField[];
  coverage: Coverage;
  est_minutes: number | null;
  warnings: string[];
}
export interface PreviewRow {
  line_no: number;
  status: EventStatus;
  coverage: number;
  class_uid: number | null;
  raw: string;
  mapped: Record<string, unknown>;
  unmapped: Record<string, unknown>;
}
export interface LintIssue {
  level: "error" | "warning";
  message: string;
  line?: number | null;
}
export interface PreviewResponse {
  ok: boolean;
  lint: LintIssue[];
  tests: { passed: number; failed: number; failures?: { name: string; message: string }[] };
  coverage: Coverage;
  rows: PreviewRow[];
}
export interface PublishResponse {
  published: boolean;
  pack_id: string;
  version: string;
  path: string;
  reloaded: boolean;
}
export interface ClustersResponse {
  items: TemplateCluster[];
}

export interface BenchmarkResults {
  generated_at: number;
  hardware: { cpu: string; cores: number; ram_gb: number; os: string; python?: string; storage?: string; label?: string };
  config: { mix?: string; duration_s: number; events?: number; workers_list?: number[] };
  sustained: { eps: number; per_worker_eps?: number; projected_daily_events?: number };
  scaling: { workers: number; eps: number }[];
  latency_ms: { p50: number; p95?: number; p99: number; max?: number };
  resources?: { cpu_pct?: number; rss_mb?: number };
  vault?: { compression_ratio?: number };
  lake?: { bytes_per_event?: number };
  ledger?: { ingested: number; lost: number; conserved: boolean };
  accuracy?: { precision: number; recall: number };
  parse_rate?: number;
  /** Optional goals to draw as reference lines (never defaulted by the UI). */
  targets?: { eps?: number; eps_stretch?: number; latency_p99_ms?: number };
}

export interface ApiErrorBody {
  error: { code: string; message: string };
}

/** Messages on WS /stream */
export type StreamMessage =
  | { type: "hello"; server_time: number; buffer: number }
  | { type: "batch"; events: TailRow[]; dropped?: number }
  | { type: "error"; message: string };
export type StreamRequest = {
  op: "filter";
  q: string;
  sources: string[];
  statuses: EventStatus[];
};
