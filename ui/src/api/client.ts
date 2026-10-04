import type {
  AnalyzeResponse, BenchmarkResults, ClustersResponse, DetectionsResponse, EventsFilter, EventsPage,
  ExplainResponse, HealthResponse, Histogram, LedgerResponse, OcsfEvent, PreviewResponse, PublishResponse,
  QueryField, RawResponse, SourceHealth, SourcesResponse, VaultSegmentsResponse, VerifyMessage, ApiErrorBody
} from "./types";

export const API_BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api/v1";

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
  get isNetwork() {
    return this.status === 0;
  }
}

/** Observers for connection indicator + dev-mock ribbon. Kept framework-free to avoid import cycles. */
type Listener = (info: { ok: boolean; mock: boolean }) => void;
const listeners = new Set<Listener>();
export function onApiActivity(fn: Listener) {
  listeners.add(fn);
  return () => void listeners.delete(fn);
}
const emit = (ok: boolean, mock: boolean) => listeners.forEach((l) => l({ ok, mock }));

function token(): string | null {
  try {
    return localStorage.getItem("ulpf_token");
  } catch {
    return null;
  }
}
function headers(extra?: Record<string, string>): Record<string, string> {
  const t = token();
  return { Accept: "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}), ...extra };
}

async function parseError(res: Response): Promise<ApiError> {
  let code = `HTTP_${res.status}`;
  let message = res.statusText || "Request failed";
  try {
    const body = (await res.json()) as Partial<ApiErrorBody> & { detail?: unknown };
    if (body.error) {
      code = body.error.code;
      message = body.error.message;
    } else if (typeof body.detail === "string") {
      message = body.detail; // FastAPI default
    }
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(res.status, code, message);
}

async function request<T>(path: string, init?: RequestInit & { signal?: AbortSignal }): Promise<T> {
  let res: Response;
  try {
    res = await fetch(API_BASE + path, { ...init, headers: headers(init?.headers as Record<string, string>) });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    emit(false, false);
    throw new ApiError(0, "NETWORK", "Cannot reach the ULPF API");
  }
  // A dev/reverse proxy with no backend answers 5xx (often non-JSON) for connection failures.
  const mock = res.headers.get("x-ulpf-mock") === "1";
  const nonJson5xx = res.status >= 500 && !(res.headers.get("content-type") ?? "").includes("json");
  if (res.status === 502 || res.status === 503 || res.status === 504 || nonJson5xx) {
    emit(false, mock);
    throw new ApiError(0, "UPSTREAM_DOWN", "The ULPF API is not responding");
  }
  emit(true, mock);
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as T;
}

const qs = (o: Record<string, string | number | null | undefined>) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
};

export const filterParams = (f: EventsFilter) => ({
  from: f.from, to: f.to, class: f.class ?? undefined, source: f.source ?? undefined,
  status: f.status ?? undefined, q: f.q || undefined
});

export const api = {
  health: (signal?: AbortSignal) => request<HealthResponse>("/health", { signal }),
  fields: () => request<{ fields: QueryField[] }>("/events/fields"),
  fieldValues: (field: string, prefix: string) =>
    request<{ values: string[] }>(`/events/values${qs({ field, prefix, limit: 12 })}`),
  events: (f: EventsFilter, limit: number, cursor?: string | null, signal?: AbortSignal) =>
    request<EventsPage>(`/events${qs({ ...filterParams(f), limit, cursor })}`, { signal }),
  histogram: (f: EventsFilter, buckets: number, signal?: AbortSignal) =>
    request<Histogram>(`/events/histogram${qs({ ...filterParams(f), buckets })}`, { signal }),
  event: (id: string) => request<OcsfEvent>(`/events/${encodeURIComponent(id)}`),
  raw: (id: string) => request<RawResponse>(`/events/${encodeURIComponent(id)}/raw`),
  explain: (id: string) => request<ExplainResponse>(`/events/${encodeURIComponent(id)}/explain`),
  sources: () => request<SourcesResponse>("/sources"),
  sourceHealth: (id: string) => request<SourceHealth>(`/sources/${encodeURIComponent(id)}/health`),
  ledger: () => request<LedgerResponse>("/ledger"),
  segments: () => request<VaultSegmentsResponse>("/vault/segments"),
  detections: () => request<DetectionsResponse>("/analytics/detections"),
  benchmark: () => request<BenchmarkResults>("/benchmark"),
  clusters: () => request<ClustersResponse>("/onboard/clusters"),
  analyze: (body: { samples: string[]; vendor?: string; product?: string }) =>
    request<AnalyzeResponse>("/onboard/analyze", {
      method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" }
    }),
  preview: (body: { pack_yaml: string; samples: string[] }) =>
    request<PreviewResponse>("/onboard/preview", {
      method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" }
    }),
  publish: (body: { pack_yaml: string }) =>
    request<PublishResponse>("/onboard/publish", {
      method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" }
    })
};

export function exportUrl(kind: "csv" | "json" | "arrow", f: EventsFilter): string {
  const t = token();
  return `${API_BASE}/export/${kind}${qs({ ...filterParams(f), access_token: t ?? undefined })}`;
}

/** POST /vault/verify returns NDJSON; yields each message as it arrives. */
export async function* verifyVault(
  body: { all?: boolean; segment?: string },
  signal?: AbortSignal
): AsyncGenerator<VerifyMessage> {
  let res: Response;
  try {
    res = await fetch(API_BASE + "/vault/verify", {
      method: "POST", signal,
      headers: headers({ "Content-Type": "application/json", Accept: "application/x-ndjson" }),
      body: JSON.stringify(body)
    });
  } catch {
    emit(false, false);
    throw new ApiError(0, "NETWORK", "Cannot reach the ULPF API");
  }
  if (!res.ok || !res.body) throw await parseError(res);
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) yield JSON.parse(line) as VerifyMessage;
    }
  }
  if (buf.trim()) yield JSON.parse(buf) as VerifyMessage;
}

/** WS URL for /stream (same origin, ws/wss derived from page protocol). */
export function streamUrl(): string {
  const u = new URL(API_BASE, location.href);
  u.protocol = u.protocol.startsWith("https") ? "wss" : "ws"; // scheme swap only; host is same-origin
  const base = u.toString().replace(/\/$/, "");
  const t = token();
  return `${base}/stream${t ? `?access_token=${encodeURIComponent(t)}` : ""}`;
}
