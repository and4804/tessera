# ULPF (Tessera): slide outline (5 slides)

Human task: final slide design. Every number below is measured and sourced (`docs/benchmarks.md`, `bench/results.json`, `bench/scale_1m.json`);
hardware for all of them: 2 vCPU Xeon 2.1 GHz, 7.8 GB RAM, Linux, Python 3.12.3, shared VM. Packs and the generator are `verified: false`
(unverified against real devices): never say "vendor accuracy".

## 1. Problem and gap

* Perimeter devices log in dozens of formats; a SIEM needs one schema, intact evidence, and quick onboarding of the next unseen source, often on
  networks with no Internet.
* Gap in today's tooling: parsers are code or opaque, raw is overwritten or not provable, onboarding takes days, cloud-first deployments.
* Our answer in one line: OCSF 1.3 output, raw-first hash-chained vault, parsers as data, Onboarding Studio, fully offline.

## 2. Architecture and invariants

* Diagram: ingest -> Redis Streams bus -> workers (vault, detect, extract, normalize, unparsed lane, sinks); API + UI + analytics + Studio on the slow path.
* Invariants, each tested: raw-first (I1), never-drop (I2), idempotent ids (I3), plain-Python hot path (I4), order per source (I5), no network at runtime.
* Packs are YAML with a closed set of operations: no `eval`, no code.

## 3. Differentiators

* **Lossless proof**: vault frames, hash chain, Ed25519-signed sealed segments. 1M events in, 1M in the lake and 1M in the vault, SHA-256 multisets equal.
  Flip one byte: `ulpf verify` names the block; reading the victim event fails, its neighbours in other blocks verify.
* **Explain**: every normalized field maps to byte spans in the raw line; Verify re-reads the vault and compares hashes; findings link to raw lines.
* **Onboarding Studio**: paste samples, get a draft pack with tests and a preview, publish without restart. Honest status: on the generated MikroTik
  corpus 98.0% of lines match, 98.0% field recall, 87.1% mean coverage, but **58.8% of fields mapped against the 85% target** (not met); drafts are `verified: false`.

## 4. Results (measured)

| | Result |
|---|---|
| Conservation, 1M events | in = vaulted = sunk = 1,000,000; lost 0; parsed 998,840 / partial 143 / unparsed 1,017 |
| Field precision and recall vs generator truth | 1.0000 / 1.0000 on 998,000 lines (self-consistency, not vendor accuracy) |
| Throughput, full pipeline | 6,784 / 13,329 / 14,588 eps with 1 / 2 / 4 workers on 2 vCPUs (worker capacity; 4-core not measured) |
| Scaling | 1.96x from 1 to 2 workers, flat after 2 cores; chart on the Benchmark page |
| Latency ingest to queryable | p50 25 ms, p99 95 ms at about half of one worker's rate |
| Onboarding | analysis under 0.3 s; Studio's review estimate 3.4 to 5.4 min (an estimate); fields mapped 41 to 73% |
| Air-gap | egress and DNS blocked from api, ingest, worker on an `internal: true` network (run with locally substituted base images); bundle installs from tarball |
| Anomaly detection (generated data) | 3/3 incidents flagged, 0 of 4,249 baseline windows false positive |

## 5. Roadmap and fit for NTRO

* Verify packs against vendor documentation and real captures; benchmark on the final hardware (both human tasks).
* Raise Studio "fields mapped": rule-name and TCP-flag mappings, NAT vocabulary, more held-out sources.
* More sources (cloud, IoT, OT), ECS and STIX export (ECS export was not built), Kafka for scale-out beyond Redis Streams, multi-node tests.
* Fit: air-gapped deployment from one tarball, provable chain of custody for raw logs, open schema, no vendor lock-in, no LLM in the hot path.
