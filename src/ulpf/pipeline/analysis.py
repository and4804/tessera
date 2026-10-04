"""Analytics task (§7.12): windowed features over the lake -> IsolationForest -> Detection Findings (class 2004) written back to the
lake through the normal sink. Findings are synthetic (``ulpf.synthetic``): they cite raw lines by ``raw_ref`` (never copies) and are not
part of the conservation ledger (the ledger counts events that came off the wire)."""
from __future__ import annotations

import math
import threading
import time
from pathlib import Path
from typing import Any

import orjson

from ..analytics import anomaly, features, findings
from ..analytics.features import FEATURES
from ..api.lake import Lake
from ..model.ocsf import OCSF_VERSION
from ..sinks import ParquetSink

SOURCE_ID = "ulpf.analytics"
MIN_WINDOWS = 30
MAX_ROWS = 1_500_000


def _flat_rows(lake: Lake) -> list[dict[str, Any]]:
    files = lake.files()
    rows = lake.run(files, "SELECT epoch_ms(time), src_ip, dst_ip, dst_port, class_uid, action_id, bytes_out, source_id, raw_ref, "
                           "CASE WHEN class_uid = 3002 THEN try_cast(json_extract_string(event, '$.status_id') AS INTEGER) END "
                           f"FROM {{lake}} WHERE src_ip IS NOT NULL AND source_id <> '{SOURCE_ID}' LIMIT {MAX_ROWS}")
    out = []
    for t, sip, dip, dport, cls, act, bout, sid, ref, stid in rows:
        out.append({"time": t, "src_endpoint.ip": sip, "dst_endpoint.ip": dip, "dst_endpoint.port": dport, "class_uid": cls,
                    "action_id": act, "traffic.bytes_out": bout, "ulpf.source_id": sid, "ulpf.raw_ref": ref, "status_id": stid})
    return out


def _finding_event(s: anomaly.Scored, det: anomaly.Detector, window_s: int, node_id: str, now_ms: int) -> dict[str, Any]:
    f = findings.to_finding(s)
    uid = f["finding_info"]["uid"]
    eid = f"finding-{uid}:0"
    f["unmapped"]["baselines"] = {k: (round(math.expm1(m), 3) if k != "deny_ratio" else round(m, 3)) for k, m in zip(FEATURES, det.mu, strict=True)}
    f["unmapped"]["window_s"] = window_s
    f["unmapped"]["window_start"] = s.window.window_start_ms
    f["metadata"] = {"version": OCSF_VERSION, "uid": eid, "product": {"name": "ULPF analytics", "vendor_name": "ULPF"}}
    f["ulpf"].update({"event_id": eid, "recv_time": now_ms, "collector_id": node_id, "transport": "analytics", "peer_ip": "",
                      "source_id": SOURCE_ID, "pack_version": "1", "schema": f"ocsf-{OCSF_VERSION}", "status": "parsed", "coverage": 1.0,
                      "time_quality": "source_tz"})
    return f


class AnalyticsRunner:
    def __init__(self, lake_dir: str | Path, node_id: str = "n1", window_s: int = 60, state_path: str | Path | None = None) -> None:
        self.lake_dir = Path(lake_dir)
        self.lake = Lake(lake_dir, ttl=0.0)
        self.node_id, self.window_s = node_id, window_s
        self.state_path = Path(state_path) if state_path else None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.runs = 0

    def existing_ids(self) -> set[str]:
        rows = self.lake.run(self.lake.files(2004), f"SELECT event_id FROM {{lake}} WHERE source_id = '{SOURCE_ID}'")
        return {r[0] for r in rows}

    def run_once(self) -> dict[str, Any]:
        self.runs += 1
        evs = _flat_rows(self.lake)
        windows = features.build_windows(evs, self.window_s, engine="python")   # the duckdb engine inserts row by row: 300x slower
        res: dict[str, Any] = {"windows_scored": len(windows), "new_findings": 0, "skipped": None}
        if len(windows) < MIN_WINDOWS:
            res["skipped"] = f"only {len(windows)} windows (< {MIN_WINDOWS})"
        else:
            det = anomaly.Detector().fit(windows)
            scored = det.score(windows)
            have = self.existing_ids()
            now = int(time.time() * 1000)
            new = []
            for s in scored:
                if not s.flagged:
                    continue
                ev = _finding_event(s, det, self.window_s, self.node_id, now)
                if ev["ulpf"]["event_id"] not in have:
                    new.append(ev)
            if new:
                sink = ParquetSink(self.lake_dir, "analytics", flush_rows=10**9)
                sink.write(new)
                sink.flush()
                self.lake.invalidate()
            res["new_findings"] = len(new)
        res["updated"] = int(time.time() * 1000)
        if self.state_path:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_bytes(orjson.dumps({"windows_scored": res["windows_scored"], "false_positives": None, "updated": res["updated"]}))
        return res

    def start(self, every_s: float = 30.0) -> None:
        def loop() -> None:
            while not self._stop.wait(every_s):
                try:
                    self.run_once()
                except Exception:  # noqa: BLE001 - analytics must never take the node down
                    pass

        self._thread = threading.Thread(target=loop, name="ulpf-analytics", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
