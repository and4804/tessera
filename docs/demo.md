# Running the demo

Everything here was run in this repository. The scenario is `tools/loggen/scenarios/demo.yaml`: 7 devices (FortiGate, ASA, Suricata, CEF
firewall, pfSense, Squid, a Windows DC), 30 simulated minutes, three injected incidents (port scan from 203.0.113.50 at minute 10, SSH brute force from
198.51.100.77 at minute 18, exfiltration from 10.1.1.42 at minute 25). Vendor formats are illustrative (R12). Output is deterministic per seed.

## `ulpf demo`

```bash
ulpf demo [--eps 100] [--rate 3000] [--url http://127.0.0.1:8080]
```

* **A node is reachable** (`ulpf run`, or the compose stack): the scenario is generated and POSTed to the node's `/ingest/raw`, `--rate` events per
  wall-clock second (0 = as fast as possible). Timestamps are shifted so the scenario ends now (`--align-now`, default), which makes the UI's default time
  ranges show it. `--scenario-clock` keeps the file's fixed 2026-10-04 start.
* **No node is reachable**: standalone. The scenario is replayed in-process (no Redis), the anomaly detector runs, the findings are printed and (default)
  the UI is served over the result on port 8080. Add `--no-serve` to just print.
* `--eps` is the *simulated* baseline rate. The default 100 gives about 180,000 events (about 60 s at the default `--rate`); `--eps 20` gives 39,725 events
  in about 15 s and is what the checks in this repository use. The scenario file itself says 2,000 eps: running `tools.loggen` on it directly writes
  ~3.6 million events, so do not do that for a demo.

Measured here (`--eps 20`): 39,725 events sent in 13.2 s; ledger `ingested = vaulted = sunk = 39,725`, `unparsed 0`, `dropped 0`, `conserved: true`;
standalone mode reported 6,532 windows scored and 9 findings.

## `make demo`

`make demo` runs `.venv/bin/ulpf demo` with the defaults: standalone if nothing listens on 8080, otherwise it feeds that node (use `ulpf demo --eps 20`
for the short version). Two terminals for the full path:

```bash
.venv/bin/ulpf run --no-redis          # terminal 1: node, UI at http://127.0.0.1:8080
.venv/bin/ulpf demo --eps 20           # terminal 2: scenario
```

Against the offline bundle the same `ulpf demo` command works from any machine with this repository's Python environment and access to port 8080.
Events arrive through the gateway container, so the ledger shows the gateway's address as the single source (see `docs/benchmarks.md`, Air-gap).

## What to look at

| Page | What the demo shows | Query / action |
|---|---|---|
| Live | mixed vendors in one tail, eps counter, pause and filter | `src_ip:203.0.113.50` |
| Explorer | histogram, results, CSV/JSON export | `status:unparsed` for the junk lines, if any |
| Event Detail | raw bytes with byte-exact field spans; lineage panel; Verify re-reads the vault and compares SHA-256 | click any row |
| Studio | paste the MikroTik sample, get a draft pack, preview, publish | `python -m tools.loggen --heldout mikrotik --count 60 --out mikrotik.log`, paste the file |
| Integrity | conservation table (every delta 0), segments with chain status, Run verify | |
| Detections | findings for the three incidents, evidence rows, click through to the raw line | |
| Benchmark | renders `bench/results.json` with its hardware string | |

The Studio's coverage meter shows **mean coverage** (87.1% on this sample set). The "fields mapped" share is lower (58.8%): say which one you mean.

## Tamper demo (terminal)

```bash
python -m tools.loggen --seed 7 --count 3000 --mix fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10 --out mix.log
ulpf replay --file mix.log --no-redis --data-dir /tmp/vd          # ledger conserved, vault verify PASS
cp -r /tmp/vd /tmp/vd2 && python - <<'PY'
import glob
f = glob.glob('/tmp/vd2/vault/**/*.ulpfseg', recursive=True)[0]
b = bytearray(open(f, 'rb').read()); b[len(b) // 2] ^= 1; open(f, 'wb').write(b)
PY
ulpf verify --all --data-dir /tmp/vd2        # exit 1: "segment n1-000001 block 2 frame None: chain hash mismatch ..."
```

Run on a 3,000-event replay: the original passes (`1 segments, 3000 frames: PASS`), the copy fails and names the block. At 1M events the same
single flipped byte is reported with its exact frame and 94 of 1,000,000 reads fail, all in that block (`bench/scale_1m.json`).

## Checks

`make ui-smoke` starts a throwaway node, plays the scenario with `ulpf demo`, drives Chromium through all pages and saves screenshots to
`ui/screenshots/live/`. `make airgap-test` (Docker) proves no egress from the app containers.
