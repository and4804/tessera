# Benchmarks and measured results

Every number here was measured by the command next to it, on the hardware listed. Anything not listed was not measured.
Hardware used: Intel Xeon Processor @ 2.10 GHz, 2 vCPUs (`nproc` = 2), 7.8 GB RAM, Linux 6.18 (Firecracker VM), Python 3.12.3, no GPU.
The VM also hosts the throwaway `redis-server` the harness starts and, during these measurements, other development processes (load average
1-3): treat every number as a lower bound for an otherwise idle 2-core machine.

## Product throughput (target: P0 >= 10k eps, full pipeline, 4-core)

Measured with `ulpf bench --workers 1,2,4` (writes `bench/results.json`, served by `GET /api/v1/benchmark`) on the hardware above:
2 vCPUs shared with the throwaway `redis-server` the harness starts, Python 3.12.3, 200,000 generated lines
(`fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10`, seed 1, 40 simulated devices per format so the bus spreads over partitions).
Full pipeline per event: Redis Streams bus, vault append + fsync per block, detect, extract, normalize to OCSF 1.3, Parquet (zstd) sink,
live tail, conservation ledger. Parse rate 100 %, ledger conserved with `lost = 0` in every run.

| Worker processes | Sustained eps (ledger slope, 10-90 % of corpus) | Worker CPU | RSS (sum) |
|---|---|---|---|
| 1 | 6,784 | 82 % of one core | 156 MB |
| 2 | 13,329 | 140 % | 312 MB |
| 4 | 14,588 | 179 % | 665 MB |

(`python -m tools.bench.run --engine ulpf --count 200000 --workers 1,2,4`, which delegates to `ulpf bench`; the file is `bench/results.json`.
Tool-written, not edited by hand. An earlier run of the same command on the same VM gave 7,570 / 14,805 / 14,223.)

How to read this honestly:

* **Worker capacity, not end-to-end ingest.** The corpus is published to the bus first and the workers drain it; the publisher is idle
  while workers run. A live node also spends CPU on syslog parsing and publishing, so on the same 2 vCPUs the node-level rate is lower.
* **Run-to-run noise on this shared VM is about +/-15 %.** Runs of the same command gave 6.8k-9.0k (1 worker) and 13.3k-16.6k (2 workers).
* **Scaling stops at the core count.** 2 workers is ~1.96x one worker; 4 workers on 2 vCPUs is +9 % over 2 (within noise; CPU-bound, double the RSS).
  The `sustained.eps` headline in `bench/results.json` is the best row (4 workers); `per_worker_eps` there is that divided by 4 and understates
  what one worker does when it has a core to itself (about 6.8k-7.5k). The
  >= 10k eps target is met with 2 workers on 2 vCPUs, in this measurement setting; it was not measured on a 4-core machine.
* **One source = one partition = one worker** (per-source ordering, I5). A single device cannot use more than one worker; a replay of one
  file with `--workers N` therefore uses one. Throughput scales with the number of distinct sources, and unevenly when one source dominates.
* The in-process path (`ulpf replay --no-redis`, memory bus, one worker, JSONL + Parquet): about 6.8k-7.5k eps.
* **Ingest -> queryable latency** at ~50 % of the single-worker rate (3,392 eps, 67,842 events): p50 25 ms, p95 57 ms, p99 95 ms, max 168 ms,
  measured as Parquet file visibility (mtime of the renamed file) minus `recv_time`. Under load the group commit waits up to
  `sinks.parquet.flush_secs` (5 s) or 50,000 rows; the numbers above are low because the worker flushes every time the bus goes idle,
  producing many small files (the compactor merges them). At saturation the latency is bounded by the flush interval, not by these numbers.
* Vault compression 2.79x versus raw bytes; lake 217 bytes/event (zstd Parquet with the full OCSF document as a JSON column).
* The live tail (`norm.tail`) is rate-capped at 1,000 rows/s per worker (a view, not a store); the lake, vault and ledger are complete.

Regression gates (`tests/perf`, all part of `make verify`):

* `test_throughput_gate.py`: in-process pipeline (memory bus, 1 worker, vault + Parquet + tail) must stay above `inprocess_eps_floor` in
  `bench/baseline.json` (2,500 eps, about a third of the measured rate). Always on, cannot flake on a noisy VM.
* `test_baseline_gate.py`: the guide's "fail if sustained eps drops more than 20 %" gate. `bench/baseline.json` holds
  `inprocess_eps_measured` (median of 3 runs, 20,000 events, recorded by `python -m tools.bench.inprocess --record`: **7,864 events per CPU-second**, runs
  7,365 / 8,034 / 7,864, with hardware). It is measured in CPU time (`process_time`) so that another process sharing the core cannot make it
  flake (an earlier wall-clock version failed under load average 3). The gate compares the best of up to 3 fresh runs with 80 % of that
  median and runs only on the same CPU model and core count; on other hardware it is skipped, not passed.
* `test_stage_gates.py`: per-stage floors, vault append (fsync per block) >= 100k/s (the WP-A criterion; measured 152k-321k/s depending on
  load), detect + extract >= 8k/s (measured 19k-39k/s), normalize >= 8k/s (measured about 38k/s under load).
* `test_bench_harness.py`: `tools/bench/run.py --engine ulpf` really runs `ulpf bench` (the old `ulpf replay --json` call did not exist).

Scale-out: `ulpf run --role worker` containers coordinate partitions through Redis leases (`SET NX EX`, fair share `ceil(P/live)`).
Rebalancing, crash takeover (lease expiry, re-delivery of un-acked messages) and no-loss are tested with two workers in
`tests/integration/test_runtime.py`. A worker stalled longer than the lease TTL (10 s) can overlap its successor for one batch: duplicates
keyed by `event_id` (collapsed on read and by the compactor), never loss. Multi-container behaviour under real Docker was not run here.

## Conservation, accuracy and tamper at 1,000,000 events

`python -m tools.bench.scale --n 1000000 --workers 2` (`tools/bench/scale.py`, report in `bench/scale_1m.json`; `tests/integration/test_scale.py`
runs the same harness at 100k by default and at any size via `ULPF_SCALE_N`). Real pipeline: loggen mix of all 9 formats
(`fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5`, seed 1), every 500th line replaced by junk or a
byte-mutated variant (2,000 lines), 251x251 distinct peer IPs in runs of 20 lines, Redis Streams bus, 2 worker processes, vault fsync per
block, Parquet sink (JSONL sink off at 1M). Counts below are taken from the lake, the vault and the input, not from the ledger.

| Check | Result |
|---|---|
| ingested = vaulted = sunk (ledger) | 1,000,000 = 1,000,000 = 1,000,000; dropped 0; lost 0 |
| normalized parsed + partial + unparsed | 998,840 + 143 + 1,017 = 1,000,000 |
| Parquet rows / distinct event_id / distinct raw_ref | 1,000,000 / 1,000,000 / 1,000,000 |
| Vault frames (2 sealed segments, `verify_all`) | 1,000,000, chain + frame hashes + signatures OK |
| SHA-256 multiset of input == lake `raw_sha256` == vault frames | equal (nothing lost, duplicated or altered) |
| Set of vault frame refs == set of lake `raw_ref` | equal |
| Clean (un-mutated) lines parsed | 998,000 of 998,000 |
| Wall time end to end | 329 s (corpus 36 s, publish 26 s, drain 156 s = 6.4k eps) |

The 6.4k eps drain is **not** comparable with the table above: the corpus has about 50,000 distinct sources (one per 20-line run) (the source cache misses on every
new peer, the bench uses 40 devices per format), includes 3 KB junk lines and the heavier zeek/leef/dnsmasq formats, and the VM was shared
with other work. A 200k run of the same harness drained at 8.6k eps wall.

Ground truth (loggen `expect` vs the mapped OCSF leaves of the real pipeline's Parquet `event`, joined on raw SHA-256, 998,000 lines):

| Vendor | Lines | Precision | Recall |
|---|---|---|---|
| fortigate | 194,818 | 1.0000 | 1.0000 |
| asa | 194,787 | 1.0000 | 1.0000 |
| suricata | 145,491 | 1.0000 | 1.0000 |
| cef | 97,574 | 1.0000 | 1.0000 |
| pfsense | 97,140 | 1.0000 | 1.0000 |
| squid | 97,628 | 1.0000 | 1.0000 |
| dnsmasq | 73,073 | 1.0000 | 1.0000 |
| zeek | 48,845 | 1.0000 | 1.0000 |
| leef | 48,644 | 1.0000 | 1.0000 |
| **ALL** | 998,000 | **1.0000** | **1.0000** |

Read this as a self-consistency result only (R12): the generator and the packs encode the same reading of each vendor format, so a perfect
score proves the engine implements the packs faithfully at scale, not that the packs match real devices. The scorer itself is controlled
(`tests/integration/test_accuracy_scorer_control.py`: wrong values, missing fields and extra fields each lower the score).

Tamper (same run): one byte flipped inside one compressed block of a copy of the vault, in a position that still decompresses and silently
changes raw bytes. `ulpf verify --vault-dir` exits 1 and prints `segment n1w0-000001 block 582 frame 10: frame data does not match its recorded
SHA-256`. Reading all 1,000,000 lake `raw_ref`s through the tampered vault: 999,906 verify, 94 raise `IntegrityError`, all 94 in block 582. Over HTTP
the victim's `/raw` returns `verified: false, IntegrityError` and `/explain` 409; an event in another block verifies. Granularity is the zstd
block: a flipped byte can corrupt several frames of that block (5 to 94 across runs), never a neighbouring block.

## Reference-engine numbers (NOT the product)

The slow reference interpreter (`ulpf.onboard.refengine`) over a generated 7-vendor mix, `python -m tools.bench.run --engine ref --count 20000`:
about 12.5k events/s on 2 vCPUs, single process, detect + extract + normalize. This only shows the harness works.

Generator speed: about 48k events/s single process (`python -m tools.loggen`).

## Field accuracy vs loggen ground truth (self-consistency)

`python -m tools.loggen.accuracy --log demo.log --reference-engine`, 20,000 lines, 9 formats: precision 1.0000, recall 1.0000, 100% of
lines perfect. **This does not demonstrate correctness against real devices**: truth and packs encode the same reading of each format (R12).

## Onboarding on held-out sources (`python -m ulpf.onboard.evaluator`)

Train on 60 lines, score 400 unseen lines against generator truth (reference interpreter, not the product engine):

| Source | Format | Lines matched | Field recall | Field precision | Mean coverage | Fields mapped | Analysis time | Est. review (min) |
|---|---|---|---|---|---|---|---|---|
| MikroTik RouterOS | text/regex | 98.0% | 98.0% | 90.9% | 87.1% | 58.8% | 0.29 s | 3.7 |
| Sophos XGS | kv/kv | 100.0% | 95.7% | 91.3% | 72.1% | 73.1% | 0.03 s | 3.4 |
| Juniper SRX | kv/kv | 100.0% | 94.2% | 94.2% | 39.6% | 41.4% | 0.04 s | 5.4 |

Three different "mapped" numbers exist; always say which one you quote. **Field recall** = share of the generator's true OCSF leaves recovered.
**Mean coverage** = per line, consumed fields / extracted fields. **Fields mapped** = share of the draft's regex groups that received an OCSF path.
The spec target ">= 85% fields mapped" is **not met** by any source. On MikroTik the unmapped groups are the rule name, TCP flags and the five NAT
groups, none of which has an OCSF Network Activity attribute in the draft's vocabulary. Mean coverage and recall do clear 85%
on MikroTik only. Sophos and Juniper carry many vendor-specific fields (zones, NAT rule names, log ids) that stay in `unmapped`.

Miner change in this release (test-first, `tests/unit/onboard/test_onboard.py`): MikroTik before -> after on the same seeds:
lines matched 94.5% -> 98.0%, field recall 90.6% -> 98.0%, precision 90.4% -> 90.9%, mean coverage 83.2% -> 87.1%, fields mapped
52.6% -> 58.8%. What changed: a clause keyword that is rare overall (`, NAT a->(b)->c`, 5% of lines) now stays literal instead of becoming a
variable group, so the positional `alt_N` names are gone; templates keep semantic names (`src_ip`, `nat_src_port`); the optional rule prefix
no longer swallows the chain (`firewall,info [RULE] forward:`); a rare variant inherits optionality from the main template, so NAT lines
without a rule name still match. Sophos and Juniper numbers did not change. Precision is unchanged near 91% and the evaluator reports 0.0% perfect lines for every source (not investigated).

## Analytics

See `docs/ml-ready.md`: 3/3 incidents flagged, 0/4249 baseline false positives on generated data.

## Air-gap

Run on this VM (Docker Engine 29.8.2, daemon started by hand; the Docker Hub registry returns 403 through the sandbox proxy, so **no registry image
could be pulled**). To still exercise the real `docker/Dockerfile` and `docker/compose.yml`, the base images `python:3.12-slim`, `node:20-slim` and
`redis:7-alpine` were substituted by local images imported from this VM's Ubuntu 24.04 root filesystem (Python 3.12.3, Node 22, Ubuntu's redis-server)
and tagged with those names. The Dockerfile itself was unchanged by that. Consequences: the image is much larger than a slim image would be, the
Redis is Ubuntu's rather than the official one, and the UI/wheel stages downloaded packages through the sandbox's TLS-intercepting proxy.

* `docker build` of `docker/Dockerfile`: succeeded (UI build, wheel download from `requirements.lock`, offline `pip install --no-index`).
* `bash tools/airgap_test.sh` (stack up on the `internal: true` network, 39k-event scenario played through the published port, ledger conserved with
  lost = 0, then probes from inside api, ingest and worker): all PASS. Per container: a control (internal Redis reachable) passes, TCP to 1.1.1.1:443
  is blocked, an external DNS lookup fails, and no ESTABLISHED socket points at a non-private address. A control container on the default bridge
  *can* reach 1.1.1.1 in the same VM, so the probes are not vacuous. Redis is not probed (the real `redis:7-alpine` has no Python).
* `make bundle` produced `dist/ulpf-offline-0.1.0.tar.gz` (1.4 GB here because of the substituted images; expect a few hundred MB with slim bases);
  extracting it and running its `install.sh` after removing the images brought the stack up, the UI answered 200 on 127.0.0.1:8080 and the scenario
  ran with ledger conserved. This is not a fresh VM and not a machine without Internet; it is the same VM.
* Defects this found and fixed in the delivery files: the `# syntax=docker/dockerfile:1` line made the build fetch a frontend image from the registry
  (breaks offline builds); `COPY schemas` referred to a directory that does not exist; hatchling was missing from the wheelhouse so the
  `--no-index` install failed; the image HEALTHCHECK made ingest and worker report unhealthy (they do not serve 8080); Docker does **not publish ports
  of containers attached only to an `internal: true` network**, so the UI was unreachable: a `gateway` container (`docker/fwd.py`, stdlib TCP/UDP
  forwarder) on `internal` + `edge` now publishes 8080 and syslog 5140 while api, ingest, worker and redis stay internal-only.
* Limits that remain: the gateway itself has a route out (it only forwards fixed ports). Events posted through it appear to come from the gateway's address
  (visible as the single `per_source` row in the ledger); real deployments should rely on the syslog header's hostname. Not run: official registry
  images, a machine without Internet, a clean VM, the `siem` and `ai` profiles, multi-node scale-out.

`tests/airgap` runs the onboarding/analytics/LLM code under a socket guard that fails on any non-local connect or DNS lookup: passed.
`tests/conftest.py` installs a suite-wide guard (connect, connect_ex, sendto, getaddrinfo: loopback only), so every unit and integration test
fails on egress; `tests/airgap/test_ui_dist.py` scans `ui/dist` for external hosts and request-making calls aimed at absolute URLs (the only
hosts present are inert strings inside bundled libraries: w3.org namespaces, github.com, reactjs.org, code.visualstudio.com, microsoft.com).
Worker processes spawned by tests are not covered by the in-process guard; they only talk to the loopback Redis.
