# Lineage specification

Every normalized event carries a verifiable path back to the exact bytes that produced it (§6.1, §6.2, §7.3). This page is the
consumer-facing contract; the vault and model code are owned by the backend.

## The `ulpf` extension object

| Field | Meaning |
|---|---|
| `event_id` | `<raw_id>:<n>`; `n > 0` only when one raw event yields several events |
| `raw_ref` | `<segment>/<block>/<idx>` into the Raw Vault, known at `append()` time |
| `raw_sha256` | SHA-256 of the raw bytes, recomputed and compared on every read |
| `recv_time` | receive time, epoch ms |
| `collector_id`, `transport`, `peer_ip` | where it came from |
| `source_id`, `pack_version` | which pack@version produced the normalization |
| `schema` | `ocsf-<version>` |
| `status` | `parsed` (all required fields), `partial` (extraction ok, a required field missing or invalid, time falls back to recv time), `unparsed` (no pack or extraction failed; base event with `message`) |
| `coverage` | consumed source fields / extracted fields (see pack-dsl.md, per-expression unmapped) |
| `time_quality` | `source_tz`, `assumed_tz`, `recv_time` |

## Invariants consumers can rely on

1. **Raw-first (I1)**: sinks write only after the vault block holding the raw bytes is fsynced.
2. **Never-drop (I2)**: every envelope ends in exactly one terminal status and has a `raw_ref`; `unparsed` is a status, not a loss.
3. **Idempotent ids (I3)**: `raw_id` is assigned at ingest; at-least-once redelivery cannot create a second id, duplicates collapse by `event_id`.
4. **Lossless mapping**: `unmapped` holds every extracted field that no expression consumed; `ignore` entries are explicit and documented per pack.
5. **Tamper evidence**: frames hash to `raw_sha256`; blocks chain `H_i = SHA256(H_{i-1} || SHA256(block))`; sealed segments carry an Ed25519 signature over the chain head. `ulpf verify` reports the first bad segment/block/frame; reading one corrupted event raises `IntegrityError` for that event only.

## Detection findings

Analytics findings (class 2004) are synthetic events: `evidences` is a list of `{raw_ref}` (never copies of data), so a finding
resolves to the contributing raw lines through the same vault read path. `ulpf.source_id = ulpf.analytics`, `ulpf.synthetic = true`.

## Verification a user can do

`GET /api/v1/events/{id}/raw` returns bytes plus the hash result; the UI Verify button shows the match. Offline:
`ulpf verify --all`. Flip one byte in a segment and re-run to see the exact location.
