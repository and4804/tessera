"""Scored anomalies -> OCSF Detection Finding (class 2004). `evidences` are raw_refs, never copies of data (R1)."""
from __future__ import annotations

import hashlib
from typing import Any

from .anomaly import Scored

_WHY = {
    "uniq_dst_port": "contacted an unusually large number of destination ports",
    "uniq_dst_ip": "contacted an unusually large number of destination hosts",
    "deny_ratio": "had an unusually high share of denied connections",
    "bytes_out_sum": "sent an unusually large volume of bytes",
    "auth_fail_count": "had an unusually high number of failed authentications",
    "conn_count": "opened an unusually large number of connections",
    "uniq_sources": "was seen by an unusual number of sources",
}


def to_finding(s: Scored, model: str = "isolation_forest/v1") -> dict[str, Any]:
    w = s.window
    why = [f"{_WHY.get(f, f)} (z={z:.1f})" for f, z in s.top if z > 0]
    uid = hashlib.sha256(f"{w.src_ip}|{w.window_start_ms}|{model}".encode()).hexdigest()[:20]
    return {
        "class_uid": 2004, "category_uid": 2, "activity_id": 1, "type_uid": 200401,
        "time": w.window_start_ms, "severity_id": 4 if s.score > 0.7 else 3,
        "finding_info": {"uid": uid, "title": f"Anomalous activity from {w.src_ip}", "analytic": {"name": model, "type_id": 3},
                         "desc": f"{w.src_ip} " + "; ".join(why[:2]) if why else f"{w.src_ip} scored {s.score:.2f}"},
        "src_endpoint": {"ip": w.src_ip},
        "evidences": [{"raw_ref": r} for r in w.refs],
        "confidence_score": round(min(1.0, s.score), 3),
        "unmapped": {"features": w.features, "zscores": {k: round(v, 2) for k, v in s.zscores.items()}, "window_s": 60},
        "ulpf": {"source_id": "ulpf.analytics", "status": "parsed", "synthetic": True},
    }
