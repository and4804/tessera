# Demo video script (2 minutes, guide section 13)

Human task: record this yourself. Rehearse until the timings hold. Pre-generate the data with the same seed for repeatability, but the pipeline
on screen must be live. Keep a 2-minute fallback recording.

Before recording: `make ui`, then `.venv/bin/ulpf run --no-redis` (or the offline bundle), `ulpf demo --eps 20` until it prints `sent 39,725 events`,
`python -m tools.loggen --seed 7 --count 60 --mix fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10 --split split --out mix.log` (one file per vendor in `split/`), and `python -m tools.loggen --heldout mikrotik --count 60 --out mikrotik.log`. Browser at 1440x900, dark theme (default). Read the numbers off the
screen; do not state any that are not on it.

| Time | Shot | Say | Must be visibly real |
|---|---|---|---|
| 0:00-0:10 | Terminal: six raw lines, one per vendor (`head -1 split/*.log`) | "Six vendors. Six formats. One SOC." | six different raw formats side by side |
| 0:10-0:30 | **Live**: stream flowing; type `src_ip:203.0.113.50` | "Every event lands in one schema, OCSF 1.3." | rows from more than one vendor in one table (port scan hits fortigate, asa, suricata) |
| 0:30-0:50 | **Event Detail**: click a row, click a field, bytes highlight in the raw line; click **Verify** | "Every field points to its exact bytes, and the raw copy is hash-verified." | span highlight, `raw_ref`, `pack@version`, hash match |
| 0:50-1:15 | **Studio**: paste `mikrotik.log`, Analyze, scroll the draft, read the coverage meter, Publish | "A source we have no pack for. Draft in a second; a human reviews it. It is `verified: false` until someone checks it against the device." | the coverage meter value on screen (87.1% mean coverage on the generated sample; do not say 85% of fields mapped, it is 58.8%); after Publish the new pack should normalize new MikroTik lines without a restart (hot reload, per the spec): rehearse this, it was not exercised end to end here |
| 1:15-1:30 | **Integrity**: conservation table all deltas 0; then terminal: tamper snippet from `docs/demo.md`, `ulpf verify --all --data-dir /tmp/vd2` | "Nothing lost. Flip one byte and verification names the block." | counters equal; `FAILED` with segment and block |
| 1:30-1:45 | **Benchmark**: eps per worker count, scaling chart, hardware string | "Measured on a 2-vCPU VM: 6.8k, 13.3k and 14.6k events per second with 1, 2 and 4 workers." | the page's own numbers; read the hardware line aloud |
| 1:45-2:00 | **Detections**: port-scan finding, click evidence to the raw line; then terminal: `bash tools/airgap_test.sh --static-only` (and `make airgap-test` output if recorded with Docker) | "The finding resolves to raw lines. And the network is internal: no egress." | click-through works; `PASS compose: ...` |

Closing line: "Lossless, traceable, onboardable, offline." Do not claim vendor accuracy; packs are `verified: false`.

Fallback if the live run fails: replay the stored recording; if the Studio misbehaves, show the evaluator table
(`PYTHONPATH=src:. python -m ulpf.onboard.evaluator`) and say plainly that the 85% fields-mapped target was not met.
