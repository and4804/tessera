# ULPF (Tessera) architecture

SIH 2026, PS 26156. Two pages: problem, architecture, invariants; then schema and lineage, onboarding, deployment, measured results.
Packs and the log generator are **unverified against real devices** (`verified: false`); nothing here is a vendor-accuracy claim.

## Page 1

**Problem.** Perimeter devices emit logs in dozens of formats (syslog text, key=value, CEF, LEEF, JSON, XML, TSV). A next-gen SIEM needs one
schema, no lost or altered evidence, and a way to add the next unseen source in minutes, on networks with no Internet.

**Approach.** Normalize to the open **OCSF 1.3** schema (we do not invent one). Store the raw bytes first in a hash-chained, signed vault.
Parse with **packs**, YAML data run by a closed set of operations (no `eval`, no code in packs). Unknown formats go to an unparsed lane
and to the Onboarding Studio. Everything slow (explain, onboarding, ML) stays off the hot path.

```
 sources ──► INGEST (asyncio) ──► BUS (Redis Streams, 16 partitions) ──► WORKERS xN (processes)
 syslog UDP/TCP/TLS, HTTP POST,    RawEnvelope(raw_id, bytes)           1 VAULT append, fsync per block (raw-first, hash-chained)
 file tail / replay                                                      2 DETECT  source cache -> sniff -> pack match
                                                                         3 EXTRACT kv/regex/json/csv/cef/leef/xml/tsv
                                                                         4 NORMALIZE pack -> OCSF + unmapped + ulpf lineage
                                                                         5 UNPARSED lane (base event + template id)
                                                                         6 SINKS Parquet lake, JSONL, OpenSearch, HEC, syslog
 API (FastAPI) + DuckDB over Parquet + WebSocket tail      ANALYTICS (60 s windows -> IsolationForest -> findings)
 ONBOARD Studio (slow path, optional local LLM, off)       UI (React/TypeScript, bundled fonts + Monaco, zero external requests)
```

**Invariants** (each has tests):

| | Invariant | How it is checked |
|---|---|---|
| I1 | Raw-first: no sink write before the raw block is fsynced | integration tests; vault `append` returns the `raw_ref` before normalization |
| I2 | Never-drop: one terminal status (`parsed`, `partial`, `unparsed`) and a raw ref per event | conservation ledger; 1M-event run, `lost = 0` |
| I3 | Idempotent ids: redelivery cannot mint a second `event_id` | redelivery tests; duplicates collapse on read and in the compactor |
| I4 | Hot path is plain Python: no per-event logging or regex compile; slow features never inline | per-stage perf gates in `make verify` |
| I5 | Order per source: one source = one partition = one worker | scaling note below |
| R5/R6 | No network at runtime; no LLM in the hot path | suite-wide socket guard, UI bundle scan, compose test |

## Page 2

**Schema and lineage.** Events are OCSF 1.3 (Network Activity 4001, Detection Finding 2004, base events for unparsed lines); source leftovers go to
`unmapped`, lineage to the `ulpf` object: `event_id`, `raw_ref` (`segment/block/idx`), `raw_sha256`, `source_id`, `pack_version`, `status`, `coverage`,
`time_quality`. Blocks chain as `H_i = SHA256(H_(i-1) || SHA256(block))`; sealed segments carry an Ed25519 signature. `ulpf verify` pinpoints the first
bad segment, block and frame; reading one corrupted event fails for that event only. The UI Explain view maps normalized fields to byte spans in
the raw line and its Verify button re-reads the vault and compares hashes. Detections carry `evidences = [{raw_ref}]`, so a finding resolves to the
exact raw lines. Details: `docs/lineage-spec.md`, `docs/pack-dsl.md`.

**Onboarding Studio.** Paste at least 20 lines: sniff the format, mine templates (Drain, then a Needleman-Wunsch alignment into one or a few
regexes), infer field types, suggest OCSF paths from a data file of aliases and value hints, emit a draft pack with generated tests, preview with a
coverage meter, publish atomically (workers hot-reload, no restart). Packs published this way are `verified: false`. On three held-out sources
(60 training lines, 400 unseen):

| Source | Lines matched | Field recall | Precision | Mean coverage | Fields mapped |
|---|---|---|---|---|---|
| MikroTik (free text) | 98.0% | 98.0% | 90.9% | 87.1% | 58.8% |
| Sophos-style (kv) | 100% | 95.7% | 91.3% | 72.1% | 73.1% |
| Juniper-SRX-style (kv) | 100% | 94.2% | 94.2% | 39.6% | 41.4% |

**Caveat, stated plainly:** the 85% "fields mapped" target is not met on any source (best 73.1%; MikroTik 58.8%, up from 52.6% before the latest
miner change). The truth is written by the same author as the suggester vocabulary. Analysis takes under 0.3 s; the review time (3.4 to 5.4 min) is
the Studio's own estimate, not a measured human time.

**Deployment (air-gapped).** `make bundle` builds a multi-stage image (UI build, wheelhouse from `requirements.lock`, runtime installed with
`--no-index`) and saves it with Redis, compose files, a sample log, `SHA256SUMS` and `install.sh`. Compose runs redis, api, ingest and worker on an
`internal: true` network; a `gateway` forwarder on an extra `edge` network publishes only 8080 and syslog 5140 (Docker cannot publish ports from an
internal network). Containers are read-only, non-root, `cap_drop: ALL`, with no default credentials; the signing key is a mounted file or is generated
on first start. `make airgap-test` passed on this VM with locally substituted base images (registry blocked): egress and external DNS fail from api,
ingest and worker, and the ledger conserved. Not run: official images, a clean VM with no Internet.

**Measured results** (2 vCPU Xeon 2.1 GHz, 7.8 GB, Python 3.12.3, shared VM; run-to-run noise about 15%; details and method in `docs/benchmarks.md`):

| Metric | Target | Measured |
|---|---|---|
| Conservation at 1M events | 100%, 0 lost | 1,000,000 in = vaulted = sunk; parsed 998,840 + partial 143 + unparsed 1,017; lost 0 (`bench/scale_1m.json`) |
| Raw retrievability and hash verify | 100% | 1,000,000 vault frames verified; SHA-256 multiset of input = lake = vault |
| Tamper detection | detect | 1 flipped byte: `ulpf verify` exit 1 at segment, block, frame; 94 of 1M reads fail, all in that block |
| Parse success, clean generated lines | >= 99% | 998,000 of 998,000 |
| Field precision / recall vs generator truth | >= 99% | 1.0000 / 1.0000 on 998,000 lines (self-consistency only) |
| Throughput, full pipeline, all sinks | >= 10k eps on 4 cores | 6,784 / 13,329 / 14,588 eps with 1 / 2 / 4 workers on 2 vCPUs (worker capacity, not end-to-end ingest); not measured on 4 cores |
| 1M-event drain, harder corpus (50k sources, junk) | n/a | 6.4k eps, 329 s end to end |
| Worker scaling | near-linear | 1.96x from 1 to 2 workers; flat beyond the 2 cores |
| Ingest to queryable latency | p99 < 10 s | p50 25 ms, p95 57 ms, p99 95 ms at ~50% of one worker's rate; bounded by the 5 s flush at saturation |
| Anomaly findings (generated data) | n/a | 3 of 3 incidents flagged, 0 of 4,249 baseline windows false positives |
| New-source onboarding | < 3 min, >= 85% fields mapped | analysis 0.03 to 0.29 s; fields mapped 41 to 73% (not met) |
| Air-gap | passes | passed with substituted bases (see above) |

Scale-out: workers lease partitions through Redis (`SET NX EX`); rebalancing and crash takeover are tested with two workers; multi-container scaling
under Docker was not run. Not built: ECS export (P2).
