# ML-ready data

The lake is plain Parquet with a stable typed schema (§7.9): `event_id, raw_ref, raw_sha256, time, class_uid, source_id, src_ip,
src_port, dst_ip, dst_port, proto_name, bytes_in, bytes_out, ..., coverage, unmapped(JSON), event(JSON)`. Read it with any tool:

```python
import duckdb
df = duckdb.sql("SELECT src_ip, count(*) c FROM 'lake/class_uid=4001/**/*.parquet' GROUP BY 1 ORDER BY c DESC LIMIT 10").df()
```

`examples/notebook.py` is the same idea end to end: generate the demo scenario, build windows, fit, score, list findings.

## Anomaly baseline (`src/ulpf/analytics`)

1. `features.build_windows(events, window_s=60)` aggregates per `(src_ip, window)`:
   `conn_count, uniq_dst_ip, uniq_dst_port, deny_ratio, bytes_out_sum, auth_fail_count, uniq_sources`.
   `deny_ratio = denies / (conns + 4)`: smoothed, because one denied connection must not read as 100%.
   Inputs are nested OCSF events or flat dotted dicts; `ulpf.raw_ref` is carried for evidence.
2. `anomaly.Detector().fit(baseline_windows)`: scikit-learn IsolationForest on log-scaled features, plus robust z-scores
   (median / 1.4826*MAD with per-feature floors) that explain *why* a window was flagged.
3. Flag rule (hybrid, deliberate): forest outlier AND robust z >= 4, OR robust z >= 7 alone. IsolationForest by itself
   under-scores a window that is extreme on only one of seven features (our exfiltration case scored below its own threshold).
4. `findings.to_finding(scored)` emits OCSF Detection Finding (2004) with `evidences = [{raw_ref}]`, the feature vector and z-scores in `unmapped`.

## Measured on the demo scenario (generated data, so optimistic)

Trained on the first 10 incident-free minutes, scored on the remaining 20: all three incidents flagged (port scan in the minute it
starts, SSH brute force in its first minute, exfiltration in all three of its windows) with 0 false positives over 4249 unseen
baseline windows. Synthetic baselines are far cleaner than real traffic; expect a real baseline to need threshold tuning
and a longer training window. The DuckDB code path is covered by a test that is skipped when `duckdb` is not installed;
it was **not executed** while this was written.
