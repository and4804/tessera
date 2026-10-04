# ULPF — Universal Log Pre-processing Framework

> Codename **Rosetta** · SIH 2026 · PS 26156 (NTRO) · Implementation guide for AI coding agents
> Stack: **Python 3.12** (backend, tooling, tests) + **TypeScript** (UI) + **YAML** (source packs). Nothing else.

---

## 0. Agent operating rules (read first, obey always)

| # | Rule |
|---|------|
| R1 | Languages allowed in our code: Python, TypeScript/JavaScript, YAML, SQL, Bash, Markdown. **No Go, C++, Rust, Java.** Third-party libs that ship compiled wheels (pyarrow, duckdb, orjson, zstandard, scikit-learn) are fine. |
| R2 | **Contracts first.** Milestone M0 creates the interfaces in §6. Every other module codes against them. Never change a contract without updating §6 and all callers in the same change. |
| R3 | **Never silently drop an event.** Every raw event ends in exactly one terminal state: `parsed`, `partial`, or `unparsed`, and always has a durable raw copy. Dropping is only allowed by explicit config and must be counted (`dropped_total{reason}`). Default: off. |
| R4 | **Raw-first invariant.** A normalized event is never emitted to any sink before its raw bytes are durable in the Raw Vault. |
| R5 | **No network at runtime.** No CDN assets, no telemetry, no package downloads, no external API calls. Everything is vendored. |
| R6 | **No LLM in the hot path.** An optional local LLM may assist onboarding only (§7.11). The system must work fully with it disabled. |
| R7 | **No `eval`, `exec`, `pickle`, unsafe YAML.** Packs are data. Use `yaml.CSafeLoader`/`safe_load` and a closed set of DSL operations (§7.6). |
| R8 | **Hot path discipline** (§9): no per-event logging, no per-event regex compilation, no per-event object churn, batch everything. |
| R9 | **UI shows only real API data.** No hardcoded demo numbers anywhere in `ui/`. |
| R10 | Every module ships with tests. A milestone is done only when `make verify` is green and its acceptance criteria (§12) pass. |
| R11 | Only use dependencies in the §4 allowlist. If you need another, add a `TODO(dep)` note and pick a stdlib alternative. |
| R12 | Sample logs in this doc are **illustrative**. Do not claim vendor accuracy; mark packs `verified: false` until a human checks them against vendor docs or real captures. |

**Human-only tasks** (agents must not attempt or fake): recording the demo video, running benchmarks on the final demo hardware, verifying vendor sample logs, final slide design.

---

## 1. Mission, scope, success criteria

**Mission.** Convert logs from any perimeter network device, in any format, into a standardized, lossless, analytics-ready representation for next-gen SIEM/security platforms — with provable raw preservation, traceability, fast onboarding of new sources, and fully offline deployment.

**Scope decision.** The PS says "any hardware or software", but its *Current Scope* says perimeter network devices. We build for perimeter devices (firewalls, IDS/IPS, proxies, routers, DNS, VPN/auth) and prove extensibility with a live-onboarded unseen source.

**Schema decision.** Do **not** invent a schema. Normalize to **OCSF** (Open Cybersecurity Schema Framework). Pin one version at build time (`ocsf.version` in config; the field names in this doc were written against 1.3-era; the validator catches drift). Keep source-specific leftovers in `unmapped`, and our lineage in an `ulpf` extension object. Optional P2: ECS export view.

### 1.1 PS requirement → feature → proof

| PS item | Our feature | Proof (test / demo moment) |
|---|---|---|
| a. Preserve complete raw data | Raw Vault: byte-exact, content-hashed, hash-chained, signed segments | Round-trip test (1M events byte-identical); `ulpf verify`; tamper demo |
| b. Extract source-specific attributes | Extractors (kv/regex/json/csv/cef/leef/xml/tsv) + packs | Golden tests per pack |
| c. Normalize to common taxonomy | OCSF classes + `unmapped` bucket | OCSF validator; field accuracy vs ground truth ≥ 99% |
| d. Traceability | `ulpf.raw_ref` + `raw_sha256` + **Explain** (field → byte-span in raw) | UI click-through; hash verify button |
| e. Plug-and-play onboarding | Drop-in YAML packs, hot reload, **Onboarding Studio** | Live unseen-source demo < 3 min |
| f. Unified visibility | One schema, one explorer, cross-vendor query | `src_ip:X` returns events from 3 vendors in one table |
| g. SIEM / data lake integration | Parquet lake (Hive-partitioned), OCSF JSONL, OpenSearch bulk, Splunk HEC, syslog-out | Sink integration tests |
| h. AI/ML-ready | Typed stable Parquet, DuckDB features, anomaly demo → click-through to raw | Detection page |
| i. Reduced parser effort | Declarative packs + auto-draft from samples | Metric: minutes & LOC per new source |
| j. Air-gapped | Offline bundle; egress-denied CI test | `make airgap-test`; demo shows no-egress network |
| k. Container | Single image + compose; tarball bundle | `docker compose up` on clean host |

### 1.2 Measurable targets (report these in README/slides)

| Metric | Target |
|---|---|
| Event conservation (ingested = vaulted = normalized + unparsed = sunk) | **100%**, 0 lost, on ≥ 1M-event run |
| Raw retrievability + hash verify | 100% |
| Parse success on shipped sources (generated data) | ≥ 99% |
| Mapped-field accuracy vs loggen ground truth | ≥ 99% precision & recall |
| Throughput (4-core laptop, full pipeline, all sinks on) | P0 ≥ 10k eps (≈ 0.86B/day); stretch ≥ 30k eps |
| Worker scaling | near-linear 1→N workers (show a chart) |
| Ingest→queryable latency p99 | < 10 s |
| New-source onboarding (paste samples → live normalized) | < 3 min, ≥ 85% fields mapped |
| Air-gap test | passes with `internal: true` network, no DNS |

*1B events/day = 11.6k eps average. Peak planning factor 3× = 35k eps. Throughput numbers are targets until measured; report measured values with hardware specs.*

---

## 2. Differentiators (build these; they are what judges remember)

1. **Conservation Ledger** — live proof that nothing is lost (counts per stage, per source).
2. **Tamper-evident Raw Vault** — hash chain + Ed25519 sealed segments; `verify` pinpoints a flipped byte.
3. **Explain / field-level provenance** — click a normalized field, see the exact bytes in the raw event and the rule that produced it.
4. **Onboarding Studio** — paste samples of an unseen log → draft pack (template mining + type inference + OCSF suggestions) → live preview → publish, no restart.
5. **Packs are data with built-in tests** — hot-reloadable, versioned, linted.
6. **Ground-truth accuracy benchmark** — our log generator knows the true values, so we report real precision/recall, not vibes.
7. **Honest scale story** — measured eps, worker-scaling chart, projected daily volume.
8. **Verified air-gap** — egress-denied test, not just a claim.
9. **Detection → raw click-through** — ML flags a host; one click shows the raw lines behind it.
10. **Cross-vendor unified view** — a simulated attack visible across FortiGate + ASA + pfSense + Squid in one table.

---

## 3. Architecture

```
 Sources                         ┌────────────────────────── ULPF node ──────────────────────────┐
 (firewalls, IDS, proxies,       │                                                                 │
  routers, DNS, VPN)             │  INGEST (asyncio, 1 proc)                                       │
   syslog UDP/TCP/TLS ─────────► │   framing → RawEnvelope(raw_id=UUIDv7, recv_ns, bytes)          │
   HTTP POST /ingest/raw ──────► │        │ partition = hash(peer_ip|hint) % P                     │
   file tail / replay ─────────► │        ▼                                                        │
                                 │  BUS (Redis Streams, AOF)   raw.0 … raw.P-1                     │
                                 │        │  (consumer-group per partition, at-least-once)         │
                                 │        ▼                                                        │
                                 │  WORKERS ×N (multiprocessing; each owns a vault shard + sinks)  │
                                 │   1. VAULT append  (raw-first, hash-chained blocks)  ──► /vault │
                                 │   2. DETECT  (sniff format → source-cache → pack match)         │
                                 │   3. EXTRACT (kv/regex/json/csv/cef/leef/xml/tsv)               │
                                 │   4. NORMALIZE (pack mapping → OCSF + unmapped + ulpf lineage)  │
                                 │   5. UNPARSED lane (base event + Drain3 template id)            │
                                 │   6. SINKS: Parquet lake · OCSF JSONL · OpenSearch · HEC · syslog│
                                 │   7. tail stream (capped) for live UI + ledger counters         │
                                 │                                                                 │
                                 │  API (FastAPI)  ── DuckDB over Parquet ── WebSocket live tail   │
                                 │  ANALYTICS (windowed features → IsolationForest → findings)     │
                                 │  ONBOARD (Drain3 + inference + optional local LLM, slow path)   │
                                 └──────────────┬──────────────────────────────────────────────────┘
                                                ▼
                                       UI (React + TypeScript, fully offline)
```

**System invariants** (tests enforce these):

- **I1 Raw-first**: sink writes happen only after the vault block containing the raw event is fsynced.
- **I2 Never-drop**: every envelope → exactly one terminal status with a raw ref.
- **I3 Idempotent IDs**: `raw_id` is assigned at ingest; redelivery cannot create distinct IDs. Duplicates (at-least-once) are collapsed by `raw_id` at read/compaction.
- **I4 Hot path is pure, fast Python**; slow-path features (explain, onboarding, ML) never run inline.
- **I5 Order per source** is preserved (a source maps to one partition).

**Process model.** `ulpf run --workers N` starts: 1 ingest process, N worker processes, 1 API process, 1 analytics task. In compose each role is the same image with a different command, so `docker compose up --scale worker=4` scales out.

---

## 4. Tech stack (allowlist)

### Backend (Python 3.12, managed with `uv`)

| Concern | Choice | Why |
|---|---|---|
| Async ingest | `asyncio` (+ `uvloop` on Linux; plain asyncio on Windows/dev) | Fast sockets, no extra runtime |
| Parallelism | `multiprocessing` workers (spawn) | Escapes the GIL; one worker per core |
| Message bus | **Redis Streams** (`redis-py`), AOF `everysec` | Durable, consumer groups, tiny, air-gap friendly. `Bus` interface allows Kafka later |
| Serialization | `msgspec` (structs, msgpack), `orjson` (JSON) | Fastest pure-pip options |
| Config / API models | `pydantic` v2, `PyYAML` (CSafeLoader) | Validation at the edges only |
| Raw vault compression | `zstandard` | Great ratio, fast |
| Integrity / signing | `hashlib` (SHA-256), `PyNaCl` (Ed25519) | Chain + signatures |
| Lake | `pyarrow` (Parquet writer), `duckdb` (query) | Columnar, SQL, zero-server |
| Template mining | `drain3` | Online log-template mining in pure Python |
| ML | `scikit-learn` (IsolationForest) | Simple, explainable enough |
| API | `FastAPI` + `uvicorn` | REST + WebSocket |
| CLI | `typer` | `ulpf run/replay/verify/bench/validate` |
| Metrics | `prometheus-client` | `/metrics` |
| Logging | `structlog` (never per event) | |
| Tests | `pytest`, `hypothesis`, `pytest-benchmark`, `pytest-asyncio` | Property + perf gates |
| Lint/type | `ruff`, `mypy` (strict on `model/`, `vault/`, `packs/`) | |
| Optional | `google-re2` (ReDoS-safe regex), `watchfiles` (pack hot reload) | Use if installable; fall back to `re` with length caps |
| Optional sink libs | `opensearch-py` | Only in the `siem` profile |
| Optional local LLM | Ollama container (profile `ai`) | Offline only, onboarding assist |

### Frontend (TypeScript, Node 20, `pnpm`)

React 18 + Vite · TanStack Query + TanStack Table (+ `@tanstack/react-virtual`) · Tailwind + shadcn/ui · Apache ECharts (`echarts`) · Monaco Editor **bundled locally** (see §10 gotcha) · Zustand · `@fontsource/*` fonts (self-hosted).

### Infra

Docker multi-stage build (Node build → `python:3.12-slim`), Docker Compose with profiles: default (`redis`, `api`, `ingest`, `worker`), `siem` (OpenSearch + Dashboards), `ai` (Ollama), `obs` (Prometheus + Grafana, optional).

### Rejected (and why, in one line each)
Kafka (heavy for air-gap demo; interface keeps the door open) · Elasticsearch as primary store (JVM weight; DuckDB+Parquet is lighter and more portable) · Logstash/Vector/Cribl (that is the thing we're improving on) · custom schema (reinvents OCSF; reviewers will notice).

---

## 5. Repository layout

```
ulpf/
├─ pyproject.toml            Makefile            README.md
├─ docker/                   Dockerfile  compose.yml  compose.siem.yml  compose.ai.yml
├─ configs/ulpf.yaml         (see §16.1)
├─ packs/                    built-in source packs (§8)
│   ├─ fortinet/fortigate.yaml        cisco/asa.yaml        suricata/eve.yaml
│   ├─ cef/generic_firewall.yaml      pfsense/filterlog.yaml  squid/access.yaml
│   ├─ zeek/conn.yaml (P1)  windows/event_xml.yaml (P1)  leef/generic.yaml (P1)  dns/dnsmasq.yaml (P1)
│   └─ custom/               (runtime-created via Onboarding Studio)
├─ schemas/ocsf/<version>/   vendored OCSF JSON schema (via tools/vendor_ocsf.py)
├─ src/ulpf/
│   ├─ config.py   cli.py
│   ├─ model/      envelope.py  lineage.py  event.py  ocsf.py  ids.py
│   ├─ ingest/     syslog.py  framing.py  http.py  filetail.py  replay.py
│   ├─ bus/        base.py  redis_streams.py  memory.py
│   ├─ vault/      format.py  writer.py  reader.py  integrity.py
│   ├─ detect/     sniffer.py  matcher.py  source_cache.py
│   ├─ extract/    kv.py  regex.py  json_.py  csv_.py  cef.py  leef.py  xml_.py  tsv_zeek.py  syslog_hdr.py
│   ├─ packs/      schema.py  loader.py  compiler.py  dsl_ops.py  linter.py  testrunner.py
│   ├─ normalize/  mapper.py  timeparse.py  validate.py  lake_schema.py
│   ├─ pipeline/   worker.py  router.py  unparsed.py  ledger.py
│   ├─ sinks/      base.py  parquet.py  jsonl.py  opensearch.py  splunk_hec.py  syslog_out.py
│   ├─ explain/    tracer.py
│   ├─ onboard/    miner.py  inferer.py  aliases.yaml  suggester.py  llm.py  evaluator.py
│   ├─ analytics/  features.py  anomaly.py  findings.py
│   ├─ api/        app.py  routes_events.py  routes_sources.py  routes_onboard.py
│   │               routes_integrity.py  routes_analytics.py  ws.py  query_dsl.py
│   └─ obs/        metrics.py
├─ tools/
│   ├─ loggen/     generator.py  scenarios/demo.yaml  formats/*.py   (emits log + ground truth)
│   ├─ bench/      run.py  report.py
│   ├─ vendor_ocsf.py   make_bundle.sh   airgap_test.sh
├─ ui/                       (Vite React TS app; §7.14)
├─ tests/  unit/ property/ golden/ integration/ perf/ airgap/
└─ docs/   architecture.md  lineage-spec.md  pack-dsl.md  onboarding.md  benchmarks.md
```

---

## 6. Contracts (build in M0, treat as frozen)

### 6.1 Envelope and lineage

```python
# src/ulpf/model/envelope.py
import msgspec

class RawEnvelope(msgspec.Struct, frozen=True):
    raw_id: str              # UUIDv7 string, assigned at ingest (time-ordered)
    recv_ns: int             # receive time, ns since epoch, UTC
    collector_id: str        # node id
    transport: str           # "udp" | "tcp" | "tls" | "http" | "file" | "replay"
    peer_ip: str             # "" for file/replay
    peer_port: int
    data: bytes              # EXACT bytes of ONE event after transport de-framing
    hint: str | None = None  # source hint from listener/file rule (pack id or vendor tag)

# src/ulpf/model/lineage.py
class VaultRef(msgspec.Struct, frozen=True):
    segment: str             # "n1-000042"
    block: int
    idx: int                 # index inside block
    sha256: str              # hex SHA-256 of the raw bytes
    def __str__(self) -> str: return f"{self.segment}/{self.block}/{self.idx}"
```

### 6.2 Normalized event (plain `dict` in the hot path; documented shape)

```jsonc
{
  "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, // type_uid = class_uid*100 + activity_id
  "time": 1790000000000,                       // epoch ms (int)
  "severity_id": 1, "action_id": 1, "disposition_id": 1,
  "src_endpoint": {"ip": "10.1.1.15", "port": 51512, "interface_name": "lan"},
  "dst_endpoint": {"ip": "142.250.77.14", "port": 443, "interface_name": "wan1"},
  "connection_info": {"protocol_num": 6, "protocol_name": "tcp"},
  "traffic": {"bytes_out": 1520, "bytes_in": 48210, "packets_out": 14, "packets_in": 41},
  "duration": 12000,                           // ms
  "device": {"hostname": "FGT-HQ"},
  "metadata": {"version": "1.3.0", "uid": "<event_id>", "original_time": "2026-10-04 13:21:07",
               "product": {"name": "FortiGate", "vendor_name": "Fortinet"}},
  "unmapped": {"vd": "root", "policyid": "3", "logid": "0000000013"},   // EVERY extracted-but-unmapped field
  "ulpf": {                                     // our lineage extension (docs/lineage-spec.md)
    "event_id": "018f...:0",                    // "<raw_id>:<n>", n>0 only if one raw yields many events
    "raw_ref": "n1-000042/17/233",
    "raw_sha256": "9f2c...",
    "recv_time": 1790000000123,
    "collector_id": "n1", "transport": "udp", "peer_ip": "10.0.0.1",
    "source_id": "fortinet.fortigate", "pack_version": "1.0.0",
    "schema": "ocsf-1.3.0",
    "status": "parsed",                         // parsed | partial | unparsed
    "coverage": 0.93,                           // mapped_source_fields / extracted_fields
    "time_quality": "source_tz"                 // source_tz | assumed_tz | recv_time
  }
}
```

OCSF classes we emit (verify exact names/enums against the vendored schema; treat this table as intent):

| Class | uid | Used for |
|---|---|---|
| Network Activity | 4001 | firewall/router connections, allow/deny, bytes |
| HTTP Activity | 4002 | proxy logs (Squid) |
| DNS Activity | 4003 | DNS resolver logs |
| Authentication | 3002 | VPN/Windows logon success/failure |
| Detection Finding | 2004 | IDS/IPS alerts (Suricata), UTM detections, our ML findings |
| Base Event | 0 | unparsed lane (raw preserved, template id attached) |

### 6.3 Protocols

```python
# bus/base.py
class Bus(Protocol):
    def publish(self, partition: int, batch: list[bytes]) -> None: ...            # msgpack(RawEnvelope)
    def consume(self, partitions: list[int], consumer: str, max_n: int, block_ms: int
                ) -> list[tuple[int, str, bytes]]: ...                             # (partition, msg_id, payload)
    def ack(self, partition: int, msg_ids: list[str]) -> None: ...

# extract/*.py  — pure functions, no I/O
Extractor = Callable[[bytes], dict[str, Any] | None]   # None => this extractor does not match

# sinks/base.py
class Sink(Protocol):
    name: str
    def write(self, events: list[dict]) -> None: ...   # called with batches, AFTER vault fsync (I1)
    def flush(self) -> None: ...
    def close(self) -> None: ...

# packs/compiler.py
class CompiledPack(Protocol):
    id: str; version: str; priority: int
    def match(self, data: bytes) -> bool: ...                                   # cheap prefilter + checks
    def extract(self, data: bytes, ctx: dict) -> dict[str, Any] | None: ...     # ctx carries syslog header fields
    def normalize(self, fields: dict, env: "RawEnvelope", ref: "VaultRef") -> list[dict]: ...
```

---

## 7. Component specifications

### 7.1 Ingest (`ingest/`)

- **Syslog UDP** (`asyncio.DatagramProtocol`): one datagram = one event. Max size from config (default 64 KiB); oversize is truncated *and flagged* (`ulpf.truncated: true`), never dropped.
- **Syslog TCP/TLS**: auto-detect framing per connection: RFC 6587 octet-counting (`<len> <msg>`) vs newline-delimited. Handle partial reads, connection reuse, backpressure (pause reading when bus publish lags).
- **HTTP**: `POST /ingest/raw` (body = one event, or `application/x-ndjson` = many). Optional bearer token.
- **File tail/replay**: `ulpf replay --file X --hint fortinet.fortigate [--rate max|N]` reads line-by-line as bytes (never decode). Tail mode for demo "drop a file in a folder".
- Assign `raw_id` (UUIDv7: 48-bit ms timestamp + random; implement in `model/ids.py`), `recv_ns`, `collector_id`.
- Batch publish: accumulate up to 500 envelopes or 5 ms, then `XADD` via pipeline. Partition = `crc32(peer_ip or hint) % P`.
- Ledger: increment `ingested_total{source_hint}` after successful publish.

### 7.2 Bus (`bus/`)

- `redis_streams.py`: stream per partition `raw.{p}`, consumer group `ulpf`, `XREADGROUP` with `COUNT`, `XACK` after sinks flushed (batch ack), `XAUTOCLAIM` for pending recovery on worker restart. `MAXLEN ~ 2_000_000` per partition (approximate trim) with an alert metric if lag approaches it.
- `memory.py`: in-process queue implementation used by unit tests and the thin-slice CLI (`ulpf replay --no-redis`).

### 7.3 Raw Vault (`vault/`) — the "lossless" guarantee

**Segment file format** (`/data/vault/yyyy/mm/dd/<segment>.ulpfseg`):

```
magic "ULPFSEG1"
header   : msgpack {segment_id, node_id, created_ns, version, prev_segment_head(hex)}
block*   : u32 comp_len | u32 n_frames | zstd( msgpack([frame, ...]) ) | 32B chain_hash
frame    : [raw_id, recv_ns, transport, peer_ip, peer_port, sha256(32B), data(bytes)]
footer   : msgpack {block_offsets[], n_events, chain_head(hex), sealed_ns} | ed25519_sig(chain_head)
```

- `chain_hash_i = SHA256(chain_hash_{i-1} || SHA256(plain_block_bytes))`. First block chains from `prev_segment_head`.
- **Block assignment is deterministic**: `ref = (segment, block_seq, idx)` is known at `append()` time; the block is flushed when `block_events` (default 1000) or `block_max_ms` (default 500) is reached. `append()` returns the `VaultRef` immediately; `flush()` fsyncs. Workers must call `flush()` before sinking (I1).
- Segment rotates at `segment_max_mb`; rotation writes the footer + signature and a sidecar `.manifest.json`.
- **Reader**: `read(ref)` → seek via footer/sidecar block offset → decompress one block → return bytes → **recompute SHA-256 and compare** with `ref.sha256`; raise `IntegrityError` on mismatch. Block cache (LRU 64 blocks) for UI browsing.
- **`ulpf verify [--segment S | --all]`**: recompute every frame hash, the chain, and the signature; report first bad segment/block/frame. Exit code ≠ 0 on failure.
- Keys: Ed25519 key generated by `ulpf keygen`, mounted as a secret. Unsealed (currently-open) segments are verified by chain only.
- Crash safety: on startup, scan the last segment, truncate any partial trailing block, resume chain from the last good block.
- Retention (config): delete whole segments by age; never rewrite.

### 7.4 Detection (`detect/`)

Goal: find the right pack in ~µs for 95%+ of events.

1. **Source cache** (`source_cache.py`): key = `(peer_ip | hint)` → last matched `pack.id`. Try that pack's `match()` first. On miss, increment a miss counter; after 20 consecutive misses evict.
2. **Format sniff** (`sniffer.py`), first bytes only: `{` → json; `CEF:` → cef; `LEEF:` → leef; `<` + digits + `>` → syslog (then sniff the message part); `<?xml` / `<Event` → xml; `#fields` / tab-density → tsv; else text.
3. **Candidate packs** for that format, ordered by `priority` desc; each `match()` runs cheap `contains` prefilters before any regex.
4. **No match** → unparsed lane (§7.8).
- Syslog header (RFC 3164 and 5424) is parsed once in `extract/syslog_hdr.py` and exposed to packs as `syslog.host`, `syslog.app`, `syslog.pid`, `syslog.ts`, `syslog.pri`. RFC 3164 has no year: infer from `recv_ns` with rollover handling (Dec log received in Jan ⇒ previous year); set `time_quality: assumed_tz` when the zone is assumed.

### 7.5 Extractors (`extract/`)

All are pure functions `bytes → dict[str, Any] | None`. Decode with `errors="surrogateescape"` so invalid UTF-8 survives round-trip into `unmapped`.

| Kind | Notes |
|---|---|
| `kv` | Configurable `pair_sep`, `kv_sep`, quote char; handles quoted values with spaces and escaped quotes; duplicate keys → `key`, `key_2`, … (never overwrite) |
| `regex` | Compiled once. Supports **dispatch**: first match a cheap anchor (e.g. ASA message id) then run only that message's pattern → O(1) instead of trying every pattern. Leftover text not covered by the match goes to field `_residual` (so it lands in `unmapped`) |
| `json` | `orjson.loads`; flatten with dotted paths (`alert.signature_id`); arrays kept as lists |
| `csv` | Positional with **layout branches** (e.g. pfSense `filterlog` layout depends on IP version + protocol). Quote-aware |
| `cef` | `CEF:v|vendor|product|ver|sigid|name|sev|ext` ; honor `\|` and `\\` escapes in header and `\=` in extension; split extension on `\s(?=\w+=)`; expose header as `cef.vendor`, `cef.product`, … |
| `leef` | LEEF 1.0/2.0; custom delimiter field in 2.0 |
| `xml` | `xml.etree` with defusedxml-style hardening (no DTD/entity expansion); flatten to dotted paths + attributes (`@Name`) |
| `tsv_zeek` | Reads `#separator/#fields/#types` headers (per-connection state) then maps columns |

**Rule:** every extractor returns *all* fields it found. Deciding what is mapped vs unmapped is the mapper's job, never the extractor's.

### 7.6 Pack DSL (`packs/`) — parsers as data

A **source pack** is one YAML file. The compiler turns it into Python closures at load time. No runtime interpretation of strings, no `eval`.

**Top-level keys**

| Key | Meaning |
|---|---|
| `pack: 1` | DSL version |
| `id`, `version`, `meta{vendor,product,category}`, `verified: bool` | Identity |
| `match{priority, all[], any[]}` | Predicates: `contains: str`, `regex: str`, `starts_with: str`, `field_eq: {field, value}` (post-extract) |
| `framing` | `none` \| `syslog` (strip header, expose `syslog.*`) |
| `extract{kind, options}` | One of §7.5 |
| `select[]` | Ordered `when → class` rules; `otherwise: base_event` |
| `classes.<name>.set` | Map **OCSF dotted path → expression** |
| `ignore{field: reason}` | Allowed, but each ignored field is counted in `ulpf.ignored` (no silent drops) |
| `tests[]` | `{name, raw, expect{dotted.path: value}}` — golden vectors, run by `ulpf packs test` and CI |

**Expression forms** (closed set)

```yaml
srcip                                   # shorthand: copy field
{const: 6}
{from: field_or_[a,b], pipe: [op, op, ...], default: X}
{coalesce: [expr, expr, ...]}           # first non-null
{when: {field: x, eq: y}, then: expr, else: expr}
```

**Pipe ops (complete list; adding one requires updating `dsl_ops.py` + `docs/pack-dsl.md` + tests):**
`str int float lower upper strip` · `ip` (validate v4/v6, else null) · `port` (0–65535) · `mac` · `epoch_s epoch_ms epoch_ns` (→ ms) · `iso8601` · `strptime{fmt,tz|tz_from}` · `lookup{map,default}` · `regex{pattern,group}` · `split{sep,index}` · `concat{sep}` · `mul{n}` · `proto_name` (IANA number → name).

**Compile-time guarantees**
- Static set of consumed source fields per class is computed from the expressions. At runtime: `unmapped = extracted_keys − consumed − ignored`. **Lossless-by-construction.**
- Linter (`ulpf packs lint`) rejects: unknown ops, unknown OCSF paths, ReDoS-prone regexes (nested quantifiers; also run with a per-call length cap), `type_uid` inconsistencies, missing tests.

**Reference pack (FortiGate, key=value over syslog):**

```yaml
pack: 1
id: fortinet.fortigate
version: 1.0.0
verified: false
meta: {vendor: Fortinet, product: FortiGate, category: firewall}
match:
  priority: 50
  all:
    - contains: 'devname='
    - contains: 'logid='
framing: syslog
extract:
  kind: kv
  options: {pair_sep: " ", kv_sep: "=", quote: '"'}
select:
  - when: {field: type, eq: traffic}
    class: network_activity
  - when: {field: type, eq: utm}
    class: detection_finding
  - otherwise: base_event
classes:
  network_activity:
    set:
      activity_id: {const: 6}                       # Traffic
      time:
        coalesce:
          - {from: eventtime, pipe: [int, epoch_ns]}
          - {from: [date, time], pipe: [{concat: " "}, {strptime: {fmt: "%Y-%m-%d %H:%M:%S", tz_from: tz}}]}
      severity_id:
        from: level
        pipe: [{lookup: {map: {debug: 1, information: 1, notice: 1, warning: 2, error: 3, alert: 4, critical: 5, emergency: 6}, default: 0}}]
      action_id:
        from: action
        pipe: [{lookup: {map: {accept: 1, close: 1, timeout: 1, deny: 2, "client-rst": 2, "server-rst": 2}, default: 0}}]
      disposition_id:
        from: action
        pipe: [{lookup: {map: {accept: 1, close: 1, deny: 2}, default: 0}}]
      src_endpoint.ip: {from: srcip, pipe: [ip]}
      src_endpoint.port: {from: srcport, pipe: [int, port]}
      src_endpoint.interface_name: srcintf
      dst_endpoint.ip: {from: dstip, pipe: [ip]}
      dst_endpoint.port: {from: dstport, pipe: [int, port]}
      dst_endpoint.interface_name: dstintf
      connection_info.protocol_num: {from: proto, pipe: [int]}
      connection_info.protocol_name: {from: proto, pipe: [int, proto_name]}
      traffic.bytes_out: {from: sentbyte, pipe: [int]}
      traffic.bytes_in: {from: rcvdbyte, pipe: [int]}
      traffic.packets_out: {from: sentpkt, pipe: [int]}
      traffic.packets_in: {from: rcvdpkt, pipe: [int]}
      duration: {from: duration, pipe: [int, {mul: 1000}]}
      device.hostname: devname
      metadata.original_time: {from: [date, time], pipe: [{concat: " "}]}
  detection_finding:
    set:
      activity_id: {const: 1}
      time: {from: eventtime, pipe: [int, epoch_ns]}
      finding_info.title: {coalesce: [attack, msg, subtype]}
      finding_info.uid: {from: logid}
      src_endpoint.ip: {from: srcip, pipe: [ip]}
      dst_endpoint.ip: {from: dstip, pipe: [ip]}
      device.hostname: devname
tests:
  - name: traffic-accept
    raw: '<189>date=2026-10-04 time=13:21:07 devname="FGT-HQ" devid="FGT60F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1790000467000000000 tz="+0530" srcip=10.1.1.15 srcport=51512 srcintf="lan" dstip=142.250.77.14 dstport=443 dstintf="wan1" proto=6 action="accept" policyid=3 service="HTTPS" duration=12 sentbyte=1520 rcvdbyte=48210 sentpkt=14 rcvdpkt=41'
    expect:
      class_uid: 4001
      src_endpoint.ip: 10.1.1.15
      dst_endpoint.port: 443
      action_id: 1
      traffic.bytes_in: 48210
      unmapped.policyid: "3"
```

**Reference pack excerpt (Cisco ASA, regex with dispatch):**

```yaml
id: cisco.asa
extract:
  kind: regex
  options:
    anchor: '%ASA-(?P<sev>\d)-(?P<msgid>\d{6}): (?P<body>.*)$'
    dispatch_on: msgid
    patterns:
      "302013": 'Built (?P<dir>inbound|outbound) (?P<proto>TCP|UDP) connection (?P<connid>\d+) for (?P<sif>[\w-]+):(?P<sip>[\d.]+)/(?P<sport>\d+) \((?P<sip_nat>[\d.]+)/(?P<sport_nat>\d+)\) to (?P<dif>[\w-]+):(?P<dip>[\d.]+)/(?P<dport>\d+) \((?P<dip_nat>[\d.]+)/(?P<dport_nat>\d+)\)'
      "106023": 'Deny (?P<proto>\w+) src (?P<sif>[\w-]+):(?P<sip>[\d.]+)/(?P<sport>\d+) dst (?P<dif>[\w-]+):(?P<dip>[\d.]+)/(?P<dport>\d+) by access-group "(?P<acl>[^"]+)"'
      # also ship: 302014 (teardown w/ duration+bytes), 106100, 113005/113015 (auth fail), 710003
```

### 7.7 Normalizer (`normalize/`)

- `mapper.py`: executes compiled `set` closures; builds nested dicts from dotted paths with a single pass; computes `type_uid`, `category_uid` from class; fills `metadata.*`, `ulpf.*`.
- `timeparse.py`: hand-written fast parsers for `YYYY-MM-DD HH:MM:SS`, ISO-8601 (`datetime.fromisoformat`), RFC 3164 `MMM dd HH:MM:SS`, epoch variants; **avoid `strptime` in the hot path** (cache parsed date prefix per second). TZ resolution order: field → pack default → global `default_tz`. Always set `time_quality`.
- **Status rules**: `parsed` = all required fields for the class present; `partial` = extraction succeeded but a required field missing/invalid (time falls back to `recv_time` with `time_quality: recv_time`); `unparsed` = no pack matched or extraction failed.
- `validate.py`: lightweight OCSF conformance check (required attrs, enum membership for `activity_id`/`action_id`/`severity_id`, `type_uid` arithmetic, IP/port validity, `time` is int ms). Runs in tests and sampled (1 in 1000) in production; violations increment `ocsf_violation_total{pack,field}`. P1: also validate against the vendored official JSON schema.

### 7.8 Unparsed lane (`pipeline/unparsed.py`)

Events with no matching pack still produce a **Base Event** (class 0) containing `message` (decoded raw, lossy-safe), `time = recv_time`, `ulpf.status = unparsed`, plus `ulpf.template_id` from an in-worker Drain3 instance (cheap, bounded memory, only for unparsed events). Template clusters feed the Onboarding Studio ("these 48k events look the same — onboard this source?"). Raw is already vaulted (I1).

### 7.9 Sinks (`sinks/`) and lake schema

- **Parquet (default, always on)**: path `lake/class_uid=4001/dt=YYYY-MM-DD/hour=HH/w<worker>-<ts>-<n>.parquet`. Each worker buffers rows (`flush_rows` 50k or `flush_secs` 5) and writes with `pyarrow`, zstd. A background **compactor** merges small files per partition every few minutes and collapses duplicates by `event_id`.
- Wide analytic columns (stable typed schema in `normalize/lake_schema.py`): `event_id, raw_ref, raw_sha256, time(ts ms), recv_time, class_uid, activity_id, severity_id, action_id, status, source_id, src_ip, src_port, dst_ip, dst_port, proto_name, proto_num, bytes_in, bytes_out, packets_in, packets_out, duration_ms, user_name, url, http_method, http_status, dns_query, signature, device_host, coverage, unmapped(JSON str), event(JSON str = full OCSF doc)`.
- **JSONL (OCSF)**: rotating files, one OCSF doc per line. For feeding any SIEM that ingests files.
- **OpenSearch** (`siem` profile): `_bulk` with index template; daily indices.
- **Splunk HEC / syslog-out**: simple batching HTTP/UDP emitters (proves integration breadth).
- **Tail stream**: worker `XADD`s a thin projection to capped stream `norm.tail` (`MAXLEN ~ 20000`) for the live UI.
- Sink failures: retry with backoff; on persistent failure, spool to `/data/spool/<sink>/` and keep the bus message un-ACKed. Never ACK before all enabled sinks accepted the batch.

### 7.10 Explain (`explain/tracer.py`) — field-level provenance

Slow path, single event, on demand: `GET /api/v1/events/{id}/explain`.
1. Fetch raw via vault (hash-verified).
2. Re-run detect → extract with **span tracking** (kv: key/value offsets; regex: `m.span(name)`; csv: column offsets; cef/leef: key offsets; JSON/XML: path-based pretty-print highlighting, display only).
3. Re-run normalize with tracing: return `[{ocsf_path, value, source_fields[], spans[{start,end}], expr, pack_rule}]` and `unmapped[]` with spans.
4. UI renders raw text with colored spans; clicking a normalized field highlights its bytes, and vice versa.
Test: for all golden vectors, every span slice equals the claimed value text.

### 7.11 Onboarding Studio (`onboard/`)

Pipeline (all offline, slow path, runs in API process / background task):

1. **Input**: ≥ 20 sample lines (paste/upload) + optional vendor/product label.
2. **Sniff** format. kv/json/cef/leef/xml/tsv → generic extractor gives fields directly.
3. **Free text** → `drain3` (masking for IP, MAC, numbers, hex, UUID, timestamps) → templates; pick dominant template(s); convert wildcards to named capture groups; use literal tokens before a wildcard (`src-mac`, `proto`, `len`, `->`) as field-name hints.
4. **Type inference** per field: ip, port, int, float, mac, timestamp (try known formats), url, low-cardinality enum, free text.
5. **OCSF suggestion** (`aliases.yaml` + heuristics): name aliases (`srcip|src|source_ip|saddr|src_ip → src_endpoint.ip`, …) scored with type compatibility; arrow syntax `A:p->B:q` ⇒ src/dst; class chosen by field set (src+dst+ports ⇒ network_activity; url+method ⇒ http_activity; query ⇒ dns_activity; user+result ⇒ authentication; signature/alert ⇒ detection_finding).
6. **Draft pack** YAML + auto-generated `tests[]` from the samples (human confirms).
7. **Report**: % lines matched, % fields mapped, unmapped list, estimated time-to-onboard.
8. **Optional LLM assist** (flag `onboard.llm.enabled`, local Ollama only): prompt = DSL grammar + draft + samples → returns a pack patch. Accept the patch **only if** it passes the linter, all tests, and *raises* coverage. Never required.
9. **Publish**: write `packs/custom/<id>.yaml`, publish `packs.reload` on Redis pub/sub; workers recompile atomically (swap pointer; in-flight events finish on the old version; `pack_version` in lineage shows which).
10. **Evaluator** (`evaluator.py`, `tools/`): run steps 2–7 on held-out sources (MikroTik, Sophos-style kv, Juniper SRX-style) against hand-written truth packs → report coverage; these numbers go on a slide.

### 7.12 Analytics (`analytics/`) — "AI/ML-ready", demonstrated

- `features.py`: DuckDB SQL over the lake → per `(src_ip, 60 s window)`: `conn_count, uniq_dst_ip, uniq_dst_port, deny_ratio, bytes_out_sum, auth_fail_count, uniq_sources` (cross-vendor).
- `anomaly.py`: `IsolationForest` trained on a baseline window; score each new window; per-feature z-scores give "why flagged".
- `findings.py`: emit **Detection Finding (2004)** events with `evidences` = list of `raw_ref`s (top-N contributing events) and write them through the normal sink path.
- API exposes `/analytics/detections`; UI click-through: finding → contributing events → raw ↔ normalized view.
- Also ship `docs/ml-ready.md` + `examples/notebook.py`: reading the lake with `pandas`/`duckdb` in 5 lines, plus an Arrow export endpoint `/api/v1/export/arrow?from&to` (P1).

### 7.13 API (`api/`) — prefix `/api/v1`

| Method | Path | Notes |
|---|---|---|
| GET | `/events` | Filters: `from,to,class,source,status,q,limit,cursor`. `q` uses the field-query DSL (`src_ip:10.1.1.15 action:denied dst_port:22 "free text"`) compiled to **parameterized** DuckDB SQL with a field whitelist (no string-built SQL) |
| GET | `/events/{event_id}` | Full OCSF doc |
| GET | `/events/{event_id}/raw` | Vault read + hash verification result |
| GET | `/events/{event_id}/explain` | §7.10 |
| WS | `/stream` | Live tail from `norm.tail`; server-side filter |
| GET | `/sources`, `/sources/{id}/health` | eps, parse rate, coverage, last seen, drift flags |
| POST | `/onboard/analyze` `/onboard/preview` `/onboard/publish` | §7.11 |
| GET | `/ledger` | Conservation counters per stage/source + in-flight |
| POST | `/vault/verify` | Triggers verify; streams progress |
| GET | `/analytics/detections` | §7.12 |
| GET | `/export/{csv,json,arrow}` | Result-set export (nice-to-have parity with typical SIEM UX) |
| GET | `/metrics` | Prometheus |

Extension endpoints implemented beyond the table above (shapes in `docs/api-contract.md`, all `ext`): `GET /health`, `GET /events/fields`, `GET /events/values`, `GET /events/histogram`, `GET /vault/segments`, `GET /onboard/clusters`, `GET /benchmark` (serves `bench/results.json`, written by `ulpf bench`), and `POST /ingest/raw` (HTTP ingest, §7.1; outside the `/api/v1` prefix).

Auth: single static bearer token via env (dev default off), CORS closed. Request limits on all body sizes.

### 7.14 UI (`ui/`, React + TypeScript)

Dark, dense, SOC-style. All fonts/icons/Monaco bundled locally.

| Page | Contents |
|---|---|
| **Live** | Virtualized tail via WebSocket; source badges; status chips (parsed/partial/unparsed); pause/filter; eps counter |
| **Explorer** | Query bar (field DSL with autocomplete), time-range picker, histogram (ECharts), results table, export buttons |
| **Event Detail** | Left: raw bytes (monospace, span highlighting). Right: normalized OCSF tree grouped by mapped/unmapped. Footer: **Lineage panel** (raw_ref, sha256, pack@version, status, coverage) + **Verify** button (calls `/raw`, shows ✔ hash match) |
| **Sources & Health** | Card per source: eps sparkline, parse rate, mean coverage, last seen, top unmapped fields, "schema drift" badge |
| **Onboarding Studio** | Paste samples → analysis → editable pack (Monaco YAML) → live preview table with coverage meter → Publish; shows unparsed template clusters as suggestions |
| **Integrity & Ledger** | Conservation table (ingested / vaulted / normalized / unparsed / sunk / dropped=0), segment list with chain status, **Run verify** button |
| **Detections** | Findings list → evidence drill-down to Event Detail |
| **Benchmark** | Renders `bench/results.json`: eps, scaling chart, latency percentiles, hardware string |

State: TanStack Query for REST, a small WS hook feeding a ring buffer (cap 5k rows) for Live. Playwright smoke test (P2).

### 7.15 Observability (`obs/metrics.py`)

Counters: `ingested_total`, `vaulted_total`, `normalized_total{status,source}`, `sunk_total{sink}`, `dropped_total{reason}`, `ocsf_violation_total`. Histograms: stage latency (sampled 1/256), end-to-end ingest→sink. Gauges: stream lag per partition, vault block fill, worker RSS. **Hot-path rule:** increment local Python ints, publish to Prometheus/Redis every 1 s per worker.

---

## 8. Source packs and the log generator

### 8.1 Packs to ship

| Tier | Source | Format kind | OCSF class |
|---|---|---|---|
| **P0** | FortiGate | kv over syslog | 4001 (+2004 for UTM) |
| **P0** | Cisco ASA | regex over syslog | 4001 |
| **P0** | Suricata EVE | JSON | 2004 (alerts), 4001 (flow) |
| **P0** | Generic CEF firewall | CEF | 4001 |
| **P0** | pfSense `filterlog` | positional CSV over syslog | 4001 |
| **P0** | Squid `access.log` | regex (native format) | 4002 |
| P1 | Zeek `conn.log` | TSV with `#fields` | 4001 |
| P1 | Windows Security 4624/4625 | XML | 3002 |
| P1 | Generic LEEF | LEEF | 4001 |
| P1 | dnsmasq / BIND query log | regex | 4003 |
| **Demo-unseen** | MikroTik RouterOS firewall log — **do not ship a pack**; onboard it live | free text | 4001 |

Every pack: ≥ 5 golden test vectors including malformed/edge variants (missing fields, quoted spaces, IPv6, odd timestamps).

### 8.2 `tools/loggen` (ground truth generator)

- Emits **both** the vendor-formatted log line **and** the canonical truth record (JSONL) for each event, so tests compute field-level precision/recall.
- Deterministic (`--seed`), rate-controllable, multi-vendor mixer (`--mix fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10`).
- **Scenario file** (`scenarios/demo.yaml`), ~30 min simulated, ~2k eps baseline across 6 devices, with injected incidents using RFC 5737 documentation IPs:
  - T+10 min — **port scan** from `203.0.113.50` against FortiGate + ASA
  - T+18 min — **SSH brute force** from `198.51.100.77` (ASA denies + pfSense blocks + Windows 4625 XML)
  - T+25 min — **exfiltration** from `10.1.1.42` to rare `192.0.2.99` (Squid + FortiGate large `bytes_out`)
- Formats must follow the vendor syntax as documented; **a human must verify** each generator against vendor docs/real captures (R12).
- Also provide a public-data path: Loghub / Zeek or Suricata outputs from public pcaps as *additional* realism checks (`tools/loggen/import_public.md`), clearly separated from generated truth data.

### 8.3 MikroTik demo-unseen sample (illustrative; verify before demo)

```
firewall,info forward: in:bridge out:ether1, src-mac 00:0c:29:aa:bb:cc, proto TCP (SYN), 192.168.88.254:50000->8.8.8.8:443, len 60
firewall,info input: in:ether1 out:(unknown 0), src-mac 52:54:00:12:34:56, proto UDP, 203.0.113.50:5353->192.168.88.1:53, len 76
```
Prepare 50+ varied lines (TCP/UDP/ICMP, different chains) for the live onboarding.

---

## 9. Performance plan (Python, honestly)

Python won't hit 1B/day on one core. The design reaches it by **horizontal parallelism + a lean hot path**, and we *measure and report* instead of claiming.

**Per-event budget (targets, µs):** de-frame 5 · source-cache + match 3 · extract 25 · normalize 30 · vault append 8 · sink append 10 → ≈ 80 µs ⇒ ~12k eps/core. 4 workers ⇒ ~40k eps ceiling (before I/O contention).

**Rules**
1. Batch everywhere (bus 500, vault block 1000, Parquet 50k rows).
2. Precompile all regex; prefer `google-re2` when present; length-cap inputs.
3. Compile packs into closures (no dict-of-dict interpretation per event); precompute dotted-path setters.
4. Use `msgspec`/`orjson`; avoid `dataclass`/pydantic in the hot path; keep events as plain dicts.
5. Cache: source→pack, parsed date prefix per second, IP validation via a fast path (`str.count('.') == 3` + `ipaddress` only on failure).
6. Zero per-event logging; counters are local ints flushed every 1 s.
7. Pin worker count to `cpu_count()-2`; ingest on its own core; no sinks in the ingest process.
8. Profile with `py-spy`/`cProfile` in `tools/bench/profile.sh`; keep a flamegraph in `docs/benchmarks.md`.
9. If < P0 target: first try `re2`, then reduce per-event dict allocations, then raise `block_events`; **do not** introduce other languages.

**Benchmark harness (`tools/bench/run.py`)**
- Pre-generate 5M mixed lines → replay at max rate through the real pipeline (all P0 sinks on).
- Report: sustained eps (60 s), per-worker eps, scaling for workers = 1, 2, 4, N, p50/p99 ingest→queryable latency, CPU%, RSS, vault compression ratio, lake size/event, ledger result (must be zero loss). Writes `bench/results.json` (rendered in UI) and a Markdown table.
- **Perf regression gate** in `make verify`: fail if sustained eps drops > 20% vs. `bench/baseline.json`.

---

## 10. Air-gapped delivery

- **Build machine (online)**: `uv pip compile` → `requirements.lock`; `pip download -d wheelhouse`; `pnpm install --frozen-lockfile` + `vite build` inside the Docker build stage; `python tools/vendor_ocsf.py --version <pinned>` stores the schema JSON.
- **Runtime image**: installs from the local wheelhouse (`--no-index --find-links`); contains packs, schemas, UI `dist/`.
- **Bundle**: `make bundle` → `dist/ulpf-offline-<ver>.tar.gz` = `docker save` images (ulpf, redis, optional opensearch/ollama) + compose files + sample data + `SHA256SUMS` + `install.sh` (`docker load`, `docker compose up -d`).
- **UI gotchas**: no CDN anywhere; self-hosted fonts via `@fontsource`; **Monaco must be bundled** (`loader.config({ monaco })` with Vite `?worker` imports) — the default `@monaco-editor/react` loader fetches from a CDN and will break offline.
- **Compose**: internal network `internal: true`; only the UI port is published to the host.
- **`make airgap-test`** (`tools/airgap_test.sh`): bring up the stack on the internal network, run the smoke scenario, then assert from inside the app containers that `curl https://1.1.1.1` and a DNS lookup **fail**, and that no process attempted a non-local connection. Unit tests also run with a socket guard fixture that fails on any non-loopback `connect`.
- Secrets/keys via mounted files; no default credentials in the image.

---

## 11. Testing and quality gates (`make verify`)

| Layer | What |
|---|---|
| Unit | extractors, DSL ops, compiler, timeparse, framing, ids, query DSL → SQL |
| **Property (Hypothesis)** | (1) arbitrary bytes into the full pipeline never raise and always end in a terminal state with a raw ref; (2) vault round-trip: any list of byte strings → write → read → identical + hash valid; (3) mutated valid logs (byte flips, truncation, duplicated delimiters) never crash and never silently disappear; (4) `unmapped ∪ mapped-sources == extracted` for every golden vector |
| Golden | each pack's `tests[]` + loggen ground-truth comparison (field precision/recall report) |
| Conformance | OCSF validator over all produced events in golden + generated runs |
| Integration | compose up → replay 100k events → ledger conserved → sinks populated → API queries correct |
| Tamper | flip one byte in a vault block → `ulpf verify` reports exact segment/block/frame; Explain/raw API returns `IntegrityError` for that event only |
| Perf | micro-benchmarks per stage + end-to-end regression gate (§9) |
| Air-gap | §10 |
| UI | `tsc --noEmit`, ESLint, Vitest for the query-bar & span highlighter; Playwright smoke (P2) |
| Lint | `ruff`, `mypy --strict` on `model/ vault/ packs/` |

---

## 12. Work packages, order, acceptance criteria

Dependencies: **M0 → (WP-B, WP-C, WP-D in parallel) → M1 → M2 → (WP-E, WP-F, WP-G, WP-H in parallel) → M4 → M5.** Each agent owns directories listed; do not edit others without updating contracts.

### M0 — Foundations (≈ 1–2 h)
Repo, `pyproject.toml`, `Makefile`, CI-style `make verify`, §6 contracts, `model/ids.py` (UUIDv7), config loader, structured test fixtures, pre-commit.
**AC:** `make verify` green on empty skeleton; contracts importable; mypy strict passes on `model/`.

### WP-A Vault (`vault/`) — depends M0
**AC:** round-trip property test (100k random byte strings incl. invalid UTF-8) passes; `ulpf verify` passes; tamper test pinpoints the flipped byte; crash-recovery test (kill mid-block) resumes with valid chain; ≥ 100k appends/s single-thread (target).

### WP-B Ingest + Bus (`ingest/`, `bus/`) — depends M0
**AC:** UDP/TCP (both framings)/HTTP/file replay all produce correct `RawEnvelope`s; partial-read and oversize handled; Redis and memory bus pass the same conformance suite; redelivery after worker kill yields no loss.

### WP-C Extractors + Pack engine (`extract/`, `packs/`, `normalize/`) — depends M0
**AC:** all extractors pass unit + property tests; DSL compiler/linter/test-runner done; FortiGate pack golden tests pass; hot-reload swap is atomic; `unmapped` completeness property holds.

### WP-D Packs + loggen (`packs/*`, `tools/loggen`) — depends WP-C contracts
**AC:** all P0 packs have ≥ 5 vectors and pass; loggen produces deterministic output + truth; mapped-field precision/recall ≥ 99% on 1M generated events; demo scenario file produces the 3 incidents.

### M1 — Thin slice (≈ half day total) — **this is the minimum to submit if time collapses**
`ulpf replay --file demo.log --no-redis` → vault → detect → FortiGate+ASA+Suricata packs → OCSF JSONL + Parquet, with ledger summary printed and `ulpf verify` passing.
**AC:** conservation 100% on 100k events; round-trip proof; README quick-start works on a clean machine.

### M2 — Pipeline breadth (WP-B+C+D merged)
Workers (multiprocessing), Redis bus, detection + source cache, all P0 packs, unparsed lane (Drain3), Parquet compactor, ledger, metrics.
**AC:** 1M-event mixed run: ledger zero-loss; parse ≥ 99%; throughput measured and recorded; scaling 1→4 workers recorded.

### WP-E API (`api/`) — depends M2
**AC:** all §7.13 endpoints; query DSL tests incl. injection attempts; WebSocket tail with filters; `/raw` verifies hash; `/explain` span tests pass.

### WP-F UI (`ui/`) — depends WP-E contracts (mock server allowed *during development only*, removed before M4)
**AC:** all §7.14 pages; Event Detail span-highlighting round-trips; builds offline; Lighthouse-style check: no external requests (assert in Playwright/Network log).

### WP-G Onboarding Studio (`onboard/`) — depends WP-C, WP-E
**AC:** MikroTik samples → draft pack → ≥ 85% fields mapped → publish → live events normalized in < 3 min; evaluator report on 3 held-out sources; LLM path off by default and, when on, only accepted if coverage increases and tests pass.

### WP-H Analytics (`analytics/`) — depends M2
**AC:** demo scenario's 3 incidents each yield a Detection Finding within 2 windows of onset; false-positive count on baseline reported; evidences link to real raw refs.

### M4 — Differentiator polish
Integrity page, Benchmark page, Detections page, Explain polish, ECS export (P2).

### M5 — Hardening & delivery
Bundle + `airgap-test`, benchmark on final hardware, docs, 2-page architecture PDF, 5 slides, demo video, README with 5-minute quick start, release tag.
**AC:** fresh VM, no internet: `install.sh` → UI up → `make demo` plays the scenario → ledger zero-loss.

### Agent task prompt template
> Implement **WP-X** exactly per §7.x and §12. Touch only: `<dirs>`. Contracts in §6 are frozen. Write tests first for the acceptance criteria, then code. Respect §0 rules. Run `make verify`. Report: files changed, test results, any deviation from the spec and why.

---

## 13. Demo plan (2-minute video; rehearse until timings hold)

| Time | Shot | What must be visibly real |
|---|---|---|
| 0:00–0:10 | Hook: "6 vendors. 6 formats. One SOC." | Split of 6 different raw lines |
| 0:10–0:30 | **Live** page: mixed stream flowing; query `src_ip:203.0.113.50` | Events from 3 vendors in one unified table |
| 0:30–0:50 | **Event Detail**: click a field → bytes highlight in raw; click **Verify** | Hash match ✔, `raw_ref`, pack@version |
| 0:50–1:15 | **Onboarding Studio**: paste unseen MikroTik lines → draft → coverage ≥ 85% → Publish | New events appear normalized immediately, no restart |
| 1:15–1:30 | **Integrity & Ledger**: zero loss; flip a byte → verify pinpoints it | Counters equal; tamper detected |
| 1:30–1:45 | **Benchmark**: eps, scaling chart, hardware label | Real measured numbers |
| 1:45–2:00 | Detections: port-scan finding → click to raw lines; show `internal: true` network / no-egress test; closing line | Click-through works; air-gap proof |

Pre-record the stream with the same scenario seed for repeatability, but the pipeline run on screen must be live. Keep a 2-minute fallback recording if the live run fails.

---

## 14. Submission deliverables (map to PS)

- **Source code link**: repo with tags, `README.md` (5-minute quick start: offline bundle + dev mode), `docs/`.
- **Architecture document (≤ 2 pages)** — Page 1: problem, architecture diagram (§3), invariants. Page 2: schema + lineage, onboarding, deployment (air-gap/container), results table (§1.2 with *measured* values).
- **Technical presentation (≤ 5 slides)**: (1) Problem & gap in today's tools; (2) Architecture + invariants; (3) Differentiators (lossless proof, Explain, Onboarding Studio); (4) Results (accuracy, throughput + scaling, onboarding time, air-gap); (5) Roadmap & fit for NTRO (cloud/IoT sources, ECS/STIX export, Kafka scale-out).
- **Demo video (≤ 2 min)**: §13.

---

## 15. Risks and cut order

| Risk | Mitigation |
|---|---|
| Python throughput below target | §9 order of attack; report honest numbers + horizontal scaling story |
| Vendor sample inaccuracies | `verified: false` flags; human verification before demo; public-data cross-checks |
| OCSF version drift/enum mismatches | Pin version; validator in CI; vendored schema |
| Onboarding generalizes poorly | Constrain demo to prepared MikroTik samples; evaluator numbers shown honestly; LLM stays optional |
| Monaco/UI breaks offline | Offline UI test asserting zero external requests |
| Time collapse | **Cut order (last first):** ECS export → Playwright → Splunk/syslog sinks → LLM assist → Zeek/LEEF/DNS/Windows packs → Analytics → OpenSearch profile → UI Benchmark page. **Never cut:** vault + verify, ledger, P0 packs, Explain, Onboarding Studio (basic), air-gap bundle, benchmark. |

---

## 16. Appendix

### 16.1 `configs/ulpf.yaml`

```yaml
node_id: n1
ocsf: {version: "1.3.0"}           # pin to the version vendored under schemas/ocsf/
bus: {kind: redis, url: "redis://redis:6379/0", partitions: 16, maxlen: 2000000}
ingest:
  syslog_udp: {listen: "0.0.0.0:5140"}
  syslog_tcp: {listen: "0.0.0.0:5140", framing: auto}
  syslog_tls: {enabled: false, cert: /run/secrets/tls.crt, key: /run/secrets/tls.key}
  http: {enabled: true, path: /ingest/raw}
  file_watch: [{path: "/data/in/*.log", hint: "fortinet.fortigate"}]
  max_event_bytes: 65536
vault: {dir: /data/vault, block_events: 1000, block_max_ms: 500, segment_max_mb: 256, fsync: block, signing_key: /run/secrets/ulpf_ed25519}
pipeline: {workers: auto, source_cache: true, default_tz: "UTC", sample_validate: 1000}
packs: {dirs: [/app/packs, /data/packs/custom], hot_reload: true}
sinks:
  parquet: {enabled: true, dir: /data/lake, flush_rows: 50000, flush_secs: 5}
  jsonl: {enabled: false, dir: /data/out}
  opensearch: {enabled: false, url: "http://opensearch:9200", index: "ulpf-ocsf-%Y.%m.%d"}
  splunk_hec: {enabled: false}
  syslog_out: {enabled: false}
analytics: {enabled: true, window_s: 60}
onboard: {llm: {enabled: false, endpoint: "http://ollama:11434", model: "<any local instruct model>"}}
```

### 16.2 CLI

```
ulpf run [--workers N]             # full node
ulpf replay --file F [--hint PACK] [--rate max|N] [--no-redis]
ulpf packs lint|test [PATH]
ulpf validate --events FILE        # OCSF conformance
ulpf verify [--segment S|--all]    # vault integrity
ulpf keygen
ulpf bench [--mix ...] [--duration 60] [--workers 1,2,4,N]
ulpf demo                          # starts scenario playback into a running node
```

### 16.3 Makefile targets
`make dev` · `make verify` · `make demo` · `make bench` · `make bundle` · `make airgap-test` · `make ui` · `make docs`

### 16.4 Definition of "successful submission" (checklist)

- [ ] Offline bundle installs and runs on a clean VM with no internet
- [ ] 6 P0 sources + 1 live-onboarded unseen source, all visible in one explorer
- [ ] Ledger shows zero loss on ≥ 1M events; `ulpf verify` passes; tamper test detects a flipped byte
- [ ] Explain view maps normalized fields to raw byte spans
- [ ] Measured throughput + scaling chart + accuracy numbers (with hardware stated) in docs and slides
- [ ] ≥ 2 sinks working (Parquet + one of OpenSearch/JSONL/HEC), ML finding clicks through to raw
- [ ] Architecture doc (2 pages), 5 slides, 2-minute video, README, all linked in the submission
