# %% [markdown]
# # ULPF analytics in five lines
# Runs offline. With the backend running, replace the generated events with `duckdb.sql("SELECT event FROM 'lake/**/*.parquet'")`.
# %%
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from tools.loggen import generator  # noqa: E402
from ulpf.analytics import anomaly, features, findings  # noqa: E402

# %% Generate the demo scenario (3 incidents) with ground truth, 30 simulated minutes at 20 eps baseline
events = []
for i, (_dev, _line, rec) in enumerate(generator.generate(scenario=str(ROOT / "tools/loggen/scenarios/demo.yaml"), seed=1337, eps=20, duration_s=1800)):
    events.append(rec["expect"] | {"ulpf.source_id": rec["source"], "ulpf.raw_ref": f"demo/{i}"})

# %% Features per (src_ip, 60 s window), then fit on the incident-free first 10 minutes and score the rest
windows = features.build_windows(events)            # DuckDB if installed, else pure Python
t0 = min(w.window_start_ms for w in windows)
det = anomaly.Detector().fit([w for w in windows if w.window_start_ms < t0 + 600_000])
scored = det.score([w for w in windows if w.window_start_ms >= t0 + 600_000])

# %% Findings (OCSF Detection Finding 2004) with evidence raw refs
for s in (x for x in scored if x.flagged):
    f = findings.to_finding(s)
    print(f["src_endpoint"]["ip"], f["finding_info"]["desc"], f"evidence={len(f['evidences'])} raw refs")
