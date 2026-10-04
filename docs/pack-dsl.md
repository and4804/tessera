# Pack DSL

A pack is a YAML file that tells ULPF how to recognise, extract and normalize one log source. Packs are data: no code, no
`eval`, loaded with a safe YAML loader, and every pack carries its own golden tests. This page describes what the
reference interpreter (`src/ulpf/onboard/refengine.py`) implements. Where it goes beyond or refines the frozen spec
(IMPLEMENTATION_GUIDE §7.6) the section is marked **Extension** or **Refinement**; the backend engine must match these or
the packs must be adapted.

All shipped packs carry `verified: false` (R12): they were written from public vendor documentation and our own samples, never
against a real device, and the loggen ground truth shares the same reading of the formats. Nothing here is proof of fidelity.

## File shape

```yaml
pack: 1
id: vendor.product            # shipped packs: dotted lowercase; Studio packs: custom.<slug>
version: 1.0.0
verified: false               # must be false in this repository
meta: {vendor: Fortinet, product: FortiGate, category: firewall}
match:   {priority: 100, all: [ {contains: "devname="}, {contains: "logid="} ]}   # or `any:`
framing: none | syslog        # syslog => RFC 3164/5424 header is stripped first and exposed as syslog.*
extract: {kind: kv, options: {...}}
select:  [ {when: {field: type, eq: traffic}, class: network_activity}, {otherwise: base_event} ]
classes: {network_activity: {set: {<ocsf.path>: <expression>, ...}}}
ignore:  {field_name: "why it is deliberately not mapped"}
tests:   [ {name: ..., raw: "...", expect: {dotted.path: value}} ]
```

`match` predicates: `contains`, `starts_with`, `regex`, `field_eq`. A pack with no predicates never matches.
Classes available: `base_event`(0) `detection_finding`(2004) `authentication`(3002) `network_activity`(4001) `http_activity`(4002)
`dns_activity`(4003). `type_uid = class_uid * 100 + activity_id`; `category_uid` is derived.

## Expressions

| Form | Meaning |
|---|---|
| `"field"` (bare string) | value of an extracted field (shorthand for `from:`) |
| `{const: v}` | literal |
| `{from: f, pipe: [ops], default: v}` | field, then ops left to right; `default` when the result is null |
| `{coalesce: [e1, e2, ...]}` | first non-null |
| `{when: {field: f, eq: v}, then: e, else: e}` | conditional on one field's string equality; the only condition form implemented |

Pipe ops (closed set; unknown ops fail lint): `str int float lower upper strip ip port mac epoch_s epoch_ms epoch_ns iso8601
strptime lookup regex split concat mul proto_name hms` (`hms` is the one extension to the §7.6 list, see Reconciliation).

Op arguments: `lookup: {map: {...}, default: v}`, `strptime: {fmt: "%Y-%m-%d %H:%M:%S", tz: "+0530"}` or `{tz_from: field}`,
`regex: {pattern, group}`, `split: {sep, index}`, `mul: 1000`, `concat: {sep: " "}` (with `from: [a, b]` a list of fields; joins them, and is null if any is missing). A failing op
(bad int, invalid IP, port out of range, wrong-length MAC) yields null, never an exception.
`epoch_s` produces milliseconds; all event times are epoch ms (int).

**Extension: `hms`** (no argument): a `h:mm:ss` duration (`0:00:12`, `12:34:56`; hours unbounded, minutes and seconds `0-59`)
becomes milliseconds; anything else yields null. See "Reconciliation" below.

### Refinement: empty-value rule
An extracted value that is the empty string is treated as null by expressions (so `default`/`coalesce` apply and no empty
strings reach OCSF). The raw bytes still hold it (R1).

### Refinement: per-expression unmapped
`unmapped = extracted fields - fields consumed - ignore`. A field counts as *consumed* only if an expression that references it
**produced a value**. If `dstip=999.1.1.1` fails the `ip` op the field stays in `unmapped` instead of vanishing: nothing is
silently dropped. `coverage = consumed / extracted`.

### syslog.* context
With `framing: syslog` expressions may reference `syslog.host`, `syslog.app`, `syslog.pid`, `syslog.ts`, `syslog.pri`, and the
engine sets `ulpf.time_quality` (`source_tz` | `assumed_tz` | `recv_time`). RFC 3164 timestamps carry no year; it is inferred from
receive time with Dec/Jan rollover handling.

## Extractors and options

| kind | options |
|---|---|
| `kv` | `pair_sep` (default `" "`), `kv_sep` (`"="`), `quote` (`"`) |
| `json` | none; nested objects flatten to dotted keys (`alert.signature`) |
| `regex` | `anchor` (pattern with named groups), `alternatives` (**Extension**, below), `dispatch_on` + `patterns` + `dispatch_text` (pick a pattern by an already-extracted field, e.g. the ASA message id) |
| `csv` | `sep`, `columns` or a `layout` with `branch: {field, cases, default}` for position-dependent record types (pfSense filterlog) |
| `cef`, `leef` | none; header fields plus extension key/values; escapes handled |
| `xml` | `strip_namespaces` (default true), `named_children: {Data: Name}`; `<!DOCTYPE`/`<!ENTITY` is rejected (no DTD, no entity expansion) |
| `tsv_zeek` | `fields` (names), `unset` (`-`), `empty` (`(empty)`) |

### xml flattening
Elements flatten to dotted paths from the first level below the root: `<System><EventID>4625</EventID></System>` gives
`System.EventID`; attributes get `@name` (`System.TimeCreated.@SystemTime`); a child named by `named_children` (e.g.
`<Data Name="IpAddress">`) is keyed by the attribute value (`EventData.IpAddress`). Duplicate keys get `_2`, `_3` suffixes.

### Extension: `regex.alternatives`
`anchor` may be followed by `alternatives: [pattern, ...]`, tried in order; the first match wins. The Onboarding Studio emits
this when free-text logs have several line shapes (MikroTik has 2-3). Same group names across alternatives are expected;
the lint check for nested quantifiers (ReDoS) runs over every alternative and extraction inputs are capped at 64 KiB.
Decision: **adopted** (see Reconciliation).

## Known limits (documented, not hidden)

- **ASA teardown**: `Teardown TCP connection` messages carry a duration as `0:00:12` (h:mm:ss). The shipped `cisco.asa` pack
  still leaves it in `unmapped.duration` (its golden vectors assert that). The backend now has the `hms` op (Reconciliation), so
  switching the pack on is a two-line change in `packs/cisco/asa.yaml` (`duration: {from: duration, pipe: [hms]}` in the 302014/302016
  class plus updated vectors). It was not made here because `packs/` belongs to the pack agent and `refengine` does not know `hms`.
- **dnsmasq** logs carry no year or zone; the year comes from receive time. The loggen truth marks `assumed_time` and
  accuracy scoring skips `time` for it. `ulpf.time_quality` comes from the syslog header parser.
- **FortiGate** `tz="+0530"` is applied with `strptime.tz_from`; `eventtime` (ns) is preferred when present.

## Reconciliation (backend engine vs reference interpreter vs frozen spec)

The production engine (`ulpf.packs`, `ulpf.extract`, `ulpf.normalize`) and `refengine` are cross-checked on every golden vector and on
4000 generated lines from all nine loggen formats (`tests/golden/test_engines_agree.py`): identical class, mapped fields, `unmapped`,
status and `time_quality`. Three points where the pack DSL goes beyond the frozen §7.6 text were decided explicitly:

1. **`regex.alternatives` - adopted as a DSL extension.** Production implements it exactly as `refengine` does: `anchor` first, then each
   alternative in order, first match wins; anchored patterns (`^...`) use `match`, others `search`; every pattern is compiled once at load;
   the ReDoS lint covers `anchor`, every alternative and every `patterns` entry; input is capped at 64 KiB. `dispatch_on` still selects one
   pattern by an extracted field, and the text it did not cover is returned as `_residual`. §7.6 should list it next to `dispatch_on`.
2. **Empty-value rule - adopted, identical in both engines.** An extracted value that is `""` is *null* to expressions: a bare field
   reference and every `from:` yield null (so `default` / `coalesce` apply), a `from:` list with any empty/missing member is null as a whole,
   and a field whose expression produced null is NOT consumed, so it stays in `unmapped` (raw bytes are untouched either way; R1/R3).
   `when:` compares the raw extracted string, so `{when: {field: x, eq: ""}}` can still test for emptiness.
3. **`hms` op - added to the closed op set** (`dsl_ops.OP_SPECS`, linter, tests, this page). `h:mm:ss` -> ms, strict (minutes/seconds `<60`,
   no sign, no fraction); invalid -> null. Motivation: ASA 302014/302016 durations. `refengine` does not implement it and would reject a
   pack that uses it at lint time, which is why the shipped ASA pack is unchanged (see Known limits).

Other deliberate production behaviour (all covered by tests): `strptime` accepts IANA zone names for `tz`/`tz_from` as well as `+hhmm`
(refengine: fixed offsets only; an unknown zone yields null in both); `mul` on a non-number yields null (never string repetition); `ip`
returns canonical text for IPv6 and rejects leading-zero octets; the day-epoch cache keeps `strptime` off the hot path.

## Lint rules (reference implementation)

Required keys; `verified: false`; at least 5 tests (Studio drafts: 1); unknown ops; unknown classes; `select` referring to an
undefined class; nested-quantifier regexes. The backend linter additionally checks OCSF paths.

## Tests

`tests[].expect` keys are dotted paths into the normalized event (e.g. `src_endpoint.ip`, `unmapped.policyid`, `ulpf.status`);
type matters (`6` is not `"6"`). The reference test runner uses a fixed receive time of 2026-10-04T13:30:00Z so RFC 3164
year inference is deterministic. Run: `PYTHONPATH=src python -m tools.packref packs` (reference) or `ulpf packs test packs`
(backend).
