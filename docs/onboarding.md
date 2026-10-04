# Onboarding Studio

Paste >= 20 lines of an unseen log, get a draft pack, preview it live, publish without a restart. Everything runs on the slow
path (I4), offline (R5), and the LLM step is optional and off by default (R6).

## Pipeline (code in `src/ulpf/onboard/`)

| Step | Module | What happens |
|---|---|---|
| 1 | `studio.analyze` | >= 20 samples, optional vendor/product label |
| 2 | `inferer.sniff` | majority vote per line: syslog framing, then json / cef / leef / xml / tsv / kv / csv / text |
| 3 | `miner` | free text only. Atomize (timestamps, IPs, MACs, UUIDs, hex, numbers, words), cluster with Drain (the `drain3` package when installed, otherwise a bundled mini-Drain), align line skeletons (Needleman-Wunsch) into one or a few regexes with named groups; literal tokens before a wildcard (`src-mac`, `proto`, `len`, `->`) name the group. Optional runs become `(?:...)?`; remaining shape differences become `alternatives` (see pack-dsl.md) |
| 4 | `inferer.infer_fields` | per field: ip port int float mac timestamp (iso8601, datetime, syslog, epoch s/ms/ns) url bool enum text |
| 5 | `suggester` + `aliases.yaml` | name aliases scored with type compatibility; value hints for generic names (`field_3` whose values are tcp/udp is a protocol); class chosen from the field set; enum maps for action/severity/status/direction; unknown enum values reported, never guessed |
| 6 | `suggester.build_pack`, `studio._pick_tests` | draft YAML plus `tests[]` auto-generated from the samples (a human must confirm them against the device) |
| 7 | `studio.analyze` report | lines matched %, mean coverage, fields mapped, unmapped list, assumptions (e.g. assumed timezone), estimated review minutes |
| 8 | `llm.LLMAssist` | optional, below |
| 9 | `studio.publish` | validate, atomic write to `packs/custom/<id>.yaml` (temp file + fsync + rename), then `packs.reload` notification; workers swap compiled packs, in-flight events finish on the old version |
| 10 | `evaluator` | steps 2-7 on three held-out sources, scored against generator truth |

API surface (the API layer calls these three): `analyze(samples, label)`, `preview(pack_yaml, lines)`, `publish(pack_yaml, dest_dir)`.
Published packs must have an id `custom.[a-z0-9_]+`, pass lint and every test, and ship `verified: false`.

`aliases.yaml` is data: extend it to teach the suggester new vocabulary without a code change.

## Optional LLM assist (off by default)

`onboard.llm.enabled: false` in `configs/ulpf.yaml`. When enabled, `llm.LLMAssist` sends the DSL grammar, the draft and a few
samples to a local Ollama and receives a JSON patch that is deep-merged into the draft.

- **Local only**: the endpoint must be loopback, RFC 1918, or a single-label hostname (compose service `ollama`). Anything else
  raises `EndpointError` before any I/O.
- **Accept rule**: the patched pack must lint clean, pass all tests and **strictly raise** mean coverage on the samples.
  Otherwise the draft is returned unchanged with the reason.
- The patch cannot change `id` or `verified`.
- Any failure (endpoint down, bad JSON) leaves the draft untouched; the system never depends on it.

## Held-out evaluation

Three sources the packs have never seen: MikroTik RouterOS firewall (free text, deliberately has **no pack**), a Sophos-style
key=value firewall, a Juniper SRX-style structured log. `python -m ulpf.onboard.evaluator` trains on 60 lines and scores 400
unseen lines against the generator's truth. Latest results are in `docs/benchmarks.md`.

Be careful what these numbers mean: the truth comes from `tools/loggen/heldout.py`, written by the same author as the suggester
vocabulary, with formats modelled on public documentation. Field recall measures "did the draft recover what the generator
knows"; mean coverage measures "what share of extracted fields got a mapping". They disagree where sources carry many vendor
fields with no OCSF home (Juniper zones, NAT details). The spec called for hand-written truth packs for step 10; this
implementation uses generator-embedded truth instead.

## Known weaknesses

- The rule name (`field`), TCP flags (`proto_detail`) and NAT clause of MikroTik stay unmapped; ">= 85% fields mapped" is not met
  (58.8% on the held-out MikroTik corpus, mean coverage 87.1%; see benchmarks.md). Review the draft; that is what the Studio preview is for.
- A rare keyword is recognised as structure only when it opens a `, keyword value` clause; other rare variants fall back to `alternatives`.
- Rare line shapes beyond `max_templates` (6) are dropped and counted (`dropped_variant_lines`).
- Timestamps without zone/year are assumed UTC and flagged in `assumptions`.
