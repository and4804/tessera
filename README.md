# ULPF (Rosetta): Universal Log Pre-processing Framework

Normalizes heterogeneous security logs to OCSF 1.3 without losing a byte (raw-first, hash-chained, signed vault), with data-driven
parser packs, an Onboarding Studio for unseen sources, ML-ready output and a deployment that runs with no network. SIH 2026, PS 26156.

Status, plainly:

* All 10 vendor packs and the log generator are **unverified against real devices** (`verified: false`, rule R12). Accuracy against generator
  truth is self-consistency only, never vendor accuracy.
* Everything below was measured on one 2-vCPU VM. Numbers and caveats: [`docs/benchmarks.md`](docs/benchmarks.md).
* The Onboarding Studio drafts a pack for an unseen source; it does **not** reach the 85% "fields mapped" target on the MikroTik corpus
  (58.8% fields mapped; 98.0% lines matched, 98.0% field recall, 90.9% precision, 87.1% mean coverage; before the latest miner change 52.6% / 94.5% /
  90.6% / 90.4% / 83.2%). Review every draft before publishing.

## Quick start A: offline bundle (no internet on the target)

On an online machine with Docker: `make bundle` (`bash tools/make_bundle.sh --with-siem --with-ai` adds the optional profiles) writes
`dist/ulpf-offline-<ver>.tar.gz` and a `.sha256`. Carry it to the target (needs Docker with the compose plugin), then:

```bash
tar xzf ulpf-offline-<ver>.tar.gz && cd ulpf-offline-<ver>
./install.sh            # verifies SHA256SUMS, docker load, docker compose up -d
# UI/API: http://127.0.0.1:8080     syslog: udp+tcp 127.0.0.1:5140 (set ULPF_SYSLOG_BIND to listen on a LAN address)
```

Play the demo scenario into it from any machine that has this repo and its Python environment (`make dev`): `make demo` (or `ulpf demo --eps 20` for
a 40k-event version that takes ~15 s). No signing key is needed: the node generates one under its data volume on first start; place your own at
`secrets/ulpf_ed25519` to use it instead.

The compose network is `internal: true` (no route out, no external DNS). Docker cannot publish ports from such a network, so a small `gateway`
container (`docker/fwd.py`) sits on the internal network plus an `edge` network and publishes 8080 and 5140; api, ingest, worker and redis have no
route out. Prove it: `make airgap-test` (needs Docker; see [`docs/benchmarks.md`](docs/benchmarks.md#air-gap) for what was and was not run).

## Quick start B: development (about 5 minutes)

Needs Python 3.12+, uv, Node 20+ and pnpm 9 (only for the UI), and optionally a local `redis-server`.

```bash
make dev                      # uv venv (.venv, Python 3.12) + editable install with dev extras
make ui                       # pnpm install --frozen-lockfile && pnpm build -> ui/dist (the node serves it)
make verify                   # ruff + mypy --strict (model, vault, packs) + pytest (about 2 minutes; 1 test skipped)

# run a node with an in-process bus (no Redis needed), then play the demo scenario into it from a second terminal
.venv/bin/ulpf run --no-redis             # UI + API on http://127.0.0.1:8080, syslog 5140, HTTP POST /ingest/raw
.venv/bin/ulpf demo --eps 20              # 3 incidents over 30 simulated minutes, ~40k events, aligned to now
```

Open <http://127.0.0.1:8080>: Live, Explorer, Sources, Studio, Integrity, Detections, Benchmark. With Redis available, `ulpf run --workers 2`
uses the Redis Streams bus (the production path). With no node running at all, `make demo` plays the scenario in-process, runs the anomaly detector,
prints the findings and serves the UI over the result.

More commands (all run in this repository):

```bash
.venv/bin/ulpf packs lint packs && .venv/bin/ulpf packs test packs      # lint + golden vectors for every pack
.venv/bin/ulpf verify --all --data-dir <dir>                         # recompute vault hashes, chain and signatures (exit 1 and location on failure)
.venv/bin/ulpf bench --workers 1,2,4                                    # sustained eps, scaling, latency -> bench/results.json
make ui-smoke                                                           # live Chromium check against a throwaway node (13 checks)
PYTHONPATH=src:. .venv/bin/python -m ulpf.onboard.evaluator             # Studio on 3 held-out sources
```

Run `make` targets: `dev verify test lint type demo bench bundle airgap-test ui ui-smoke docs` (`make docs` only points at `docs/`).

## Generate logs

```bash
python -m tools.loggen --seed 7 --count 100000 --mix fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10 --out mix.log
```

Deterministic per seed. `--out` also writes `<out>.truth.jsonl` (one record per line: source, expected OCSF fields, optional incident tag).
Formats: fortigate asa suricata cef pfsense squid zeek windows leef dnsmasq. `--heldout mikrotik|sophos_kv|juniper_srx` emits the unseen
sources used to test onboarding (there is intentionally no MikroTik pack). **Do not** run the demo scenario with its default rate:
`python -m tools.loggen --scenario tools/loggen/scenarios/demo.yaml` writes ~3.6 million events (2,000 eps baseline, about 2.7 GB with truth);
add `--eps 20` for the 40k-event version `ulpf demo` uses.

## Onboard a new source

Paste samples into the Studio (UI), or call `ulpf.onboard.studio.analyze(lines)` -> draft pack + report -> `preview` -> `publish`
(writes `packs/custom/<id>.yaml`, workers hot-reload). The optional local-LLM assist is off by default. See [`docs/onboarding.md`](docs/onboarding.md).

## Layout

`packs/` parsers as data · `src/ulpf/` backend (ingest, bus, vault, detect, extract, packs, normalize, pipeline, sinks, explain, api, analytics,
onboard) · `ui/` React console · `tools/` loggen, bench, bundle, air-gap test · `docker/` image, compose profiles (`siem`, `ai`), gateway ·
`docs/` architecture, demo, slides outline, demo script, pack-dsl, lineage-spec, onboarding, benchmarks, ml-ready, api-contract.

## Not done

ECS export (P2) was not built. Official registry images and a clean, internet-less VM were not available to test the bundle on. Vendor sample
accuracy, benchmarks on the final demo hardware and the recorded demo video are human tasks (guide section 0).
