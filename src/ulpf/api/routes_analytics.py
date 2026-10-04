"""``GET /analytics/detections``: Detection Findings (class 2004) written by :mod:`ulpf.pipeline.analysis`, with their evidence rows."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import orjson
from fastapi import APIRouter

from .state import AppState

SOURCE_ID = "ulpf.analytics"


def make_router(st: AppState) -> APIRouter:
    r = APIRouter()

    @r.get("/analytics/detections")
    def detections(limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(200, limit))
        files = st.lake.files(2004)
        rows = st.lake.run(files, f"SELECT event FROM {{lake}} WHERE source_id = '{SOURCE_ID}' ORDER BY time DESC LIMIT {limit}") if files else []
        items = []
        seen: set[str] = set()
        for (js,) in rows:
            ev = orjson.loads(js)
            eid = ev["ulpf"]["event_id"]
            if eid in seen:
                continue
            seen.add(eid)
            um = ev.get("unmapped", {})
            feats = um.get("features", {})
            z = um.get("zscores", {})
            base = um.get("baselines", {})
            refs = [e["raw_ref"] for e in ev.get("evidences", []) if e.get("raw_ref")]
            evidence = st.lake.rows_by_ref(refs[:20])
            ws = int(um.get("window_start", ev.get("time", 0)))
            wsec = int(um.get("window_s", 60))
            items.append({
                "finding_id": ev["finding_info"]["uid"], "event_id": eid, "time": int(ev.get("time", ws)), "title": ev["finding_info"]["title"],
                "severity_id": int(ev.get("severity_id", 3)), "score": float(ev.get("confidence_score", 0.0)),
                "entity": {"kind": "src_ip", "value": ev.get("src_endpoint", {}).get("ip", "")},
                "window": {"start": ws, "end": ws + wsec * 1000}, "summary": ev["finding_info"].get("desc", ""),
                "features": [{"name": k, "value": v, "baseline": base.get(k, 0), "z": round(float(z.get(k, 0.0)), 2)} for k, v in feats.items()],
                "sources": sorted({e["source_id"] for e in evidence if e.get("source_id")}),
                "evidence_total": len(refs), "evidence": evidence,
            })
        state: dict[str, Any] | None = None
        sp = Path(st.cfg.data_dir) / "analytics" / "state.json"
        if sp.exists():
            try:
                state = orjson.loads(sp.read_bytes())
            except (OSError, orjson.JSONDecodeError):
                state = None
        baseline = {"windows_scored": state["windows_scored"], "false_positives": state.get("false_positives")} if state else None
        return {"items": items, "baseline": baseline}

    return r
