"""Onboarding Studio endpoints. ``analyze`` uses the Studio facade (miner/inferer/suggester); ``preview`` and ``publish`` use the
PRODUCTION pack engine (lint + compile + golden vectors + live normalization), so what the user previews is what workers will run."""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from ..normalize.validate import validate_event
from ..onboard import studio
from ..packs import PackError, compile_pack, lint_text, load_pack_text, run_pack_tests
from ..packs.testrunner import RECV_MS, make_env
from ..pipeline.unparsed import merge_clusters
from .state import AppState, err

MAX_SAMPLES = 5000
MAX_LINE = 65536


class AnalyzeReq(BaseModel):
    samples: list[str] = Field(max_length=MAX_SAMPLES)
    vendor: str | None = None
    product: str | None = None


class PreviewReq(BaseModel):
    pack_yaml: str = Field(max_length=500_000)
    samples: list[str] = Field(max_length=MAX_SAMPLES)


class PublishReq(BaseModel):
    pack_yaml: str = Field(max_length=500_000)


def _cluster_row(c: dict[str, Any]) -> dict[str, Any]:
    return {"template_id": c["template_id"], "template": c["template"], "count": c["count"], "share": c.get("share", 0.0),
            "example_raw": c.get("example_raw", ""), "samples": c.get("samples", []), "peer_ips": c.get("peer_ips", []),
            "first_seen": c.get("first_seen"), "last_seen": c.get("last_seen")}


def _coverage(lines_total: int, matched: list[tuple[set[str], dict[str, Any], float]]) -> dict[str, Any]:
    """``matched`` = one ``(extracted keys, unmapped, event coverage)`` per line a pack parsed."""
    seen: set[str] = set()
    consumed: set[str] = set()
    unm: dict[str, int] = {}
    cov = 0.0
    for keys, um, c in matched:
        seen |= keys
        consumed |= {k for k in keys if k not in um}
        cov += c
        for k in um:
            unm[k] = unm.get(k, 0) + 1
    n = len(matched)
    return {"lines_total": lines_total, "lines_matched": n, "lines_matched_pct": round(n / lines_total, 4) if lines_total else 0.0,
            "fields_mapped_pct": round(len(consumed & seen) / len(seen), 4) if seen else 0.0,
            "mean_event_coverage": round(cov / n, 4) if n else 0.0,
            "unmapped": [{"field": k, "count": v} for k, v in sorted(unm.items(), key=lambda kv: -kv[1])]}


def make_router(st: AppState) -> APIRouter:
    r = APIRouter()
    cfg = st.cfg

    @r.get("/onboard/clusters")
    def clusters() -> dict[str, Any]:
        if st.clusters is None:
            return {"items": []}
        return {"items": [_cluster_row(c) for c in merge_clusters(st.clusters.list())[:100]]}

    @r.post("/onboard/analyze")
    def analyze(body: AnalyzeReq) -> dict[str, Any]:
        lines = [s for s in body.samples if s and s.strip()]
        if not lines:
            raise err(400, "BAD_REQUEST", "no sample lines")
        try:
            a = studio.analyze(lines, label=body.product, vendor=body.vendor, product=body.product, default_tz=cfg.pipeline.default_tz)
        except ValueError as e:
            raise err(400, "BAD_REQUEST", str(e)) from e
        rep = a.report
        d = a.to_dict()
        cov = {"lines_total": rep["lines"], "lines_matched": round(rep["lines"] * rep["lines_matched_pct"] / 100),
               "lines_matched_pct": round(rep["lines_matched_pct"] / 100, 4), "fields_mapped_pct": round(rep["fields_mapped_pct"] / 100, 4),
               "mean_event_coverage": rep["coverage_mean"], "unmapped": [{"field": f, "count": 1} for f in rep["unmapped_fields"]]}
        mapped = {m["field"]: m for m in d["mapping"]}
        fields = [{"name": f["name"], "type": f["type"], "example": (f["examples"] or [""])[0] if f["examples"] else "",
                   "ocsf_path": mapped.get(f["name"], {}).get("ocsf_path"), "confidence": float(mapped.get(f["name"], {}).get("score", 0.0))}
                  for f in d["fields"]]
        pack_id = str(a.pack.get("id", "custom.draft"))
        return {"analysis_id": hashlib.sha256((pack_id + str(time.time_ns())).encode()).hexdigest()[:16], "format": d["sniff"]["format"],
                "format_confidence": d["sniff"]["confidence"], "class_name": d["class"],
                "class_uid": {"network_activity": 4001, "http_activity": 4002, "dns_activity": 4003, "authentication": 3002,
                              "detection_finding": 2004, "base_event": 0}.get(d["class"], 0),
                "pack_id": pack_id, "draft_pack_yaml": a.pack_yaml,
                "templates": [{"template_id": str(t["id"]), "template": t["template"], "count": t["count"], "share": 0.0,
                               "example_raw": t["example"]} for t in d["templates"]],
                "fields": fields, "coverage": cov, "est_minutes": rep.get("estimated_minutes"),
                "warnings": [*rep.get("notes", []), *[f"assumption: {x}" for x in rep.get("assumptions", [])]]}

    @r.post("/onboard/preview")
    def preview(body: PreviewReq) -> dict[str, Any]:
        issues = lint_text(body.pack_yaml, min_tests=1, require_unverified=False)
        lint = [{"level": i.level, "message": i.message, "line": i.line} for i in issues]
        out: dict[str, Any] = {"ok": False, "lint": lint, "tests": {"passed": 0, "failed": 0},
                               "coverage": _coverage(len(body.samples), []), "rows": []}
        if any(i.level == "error" for i in issues):
            return out
        try:
            pack = compile_pack(load_pack_text(body.pack_yaml), cfg.pipeline.default_tz)
        except (PackError, yaml.YAMLError, ValueError) as e:
            out["lint"].append({"level": "error", "message": str(e), "line": None})
            return out
        fails = run_pack_tests(pack)
        n_tests = len(pack.doc.tests)
        failed = len({(f.test) for f in fails})
        out["tests"] = {"passed": max(0, n_tests - failed), "failed": failed,
                        **({"failures": [{"name": f.test, "message": f.message} for f in fails][:50]} if fails else {})}
        matched: list[tuple[set[str], dict[str, Any], float]] = []
        sample_evs: list[dict[str, Any]] = []
        rows = []
        for i, line in enumerate(body.samples[:MAX_SAMPLES], 1):
            raw = line.encode("utf-8", "surrogateescape")[:MAX_LINE]
            ev: dict[str, Any] | None = None
            keys: set[str] = set()
            if pack.match(raw):
                try:
                    ctx: dict[str, Any] = {"_recv_ms": RECV_MS}
                    f = pack.extract(raw, ctx)
                    if f is not None and pack.post_match(f):
                        keys = set(f)
                        env, ref = make_env(raw, RECV_MS)
                        ev = pack.normalize(f, env, ref, ctx)[0]
                except Exception:  # noqa: BLE001 - a draft pack may be wrong; the preview reports, never raises
                    ev = None
            if ev is not None:
                matched.append((keys, ev["unmapped"], float(ev["ulpf"]["coverage"])))
                if len(sample_evs) < 200:
                    sample_evs.append(ev)
            if len(rows) < 500:
                if ev is None:
                    rows.append({"line_no": i, "status": "unparsed", "coverage": 0.0, "class_uid": None, "raw": line[:2000], "mapped": {},
                                 "unmapped": {}})
                else:
                    mapped = {}
                    _flatten({k: v for k, v in ev.items() if k not in ("unmapped", "ulpf", "metadata")}, "", mapped)
                    rows.append({"line_no": i, "status": ev["ulpf"]["status"], "coverage": ev["ulpf"]["coverage"], "class_uid": ev["class_uid"],
                                 "raw": line[:2000], "mapped": mapped, "unmapped": ev["unmapped"]})
        out["rows"] = rows
        out["coverage"] = _coverage(len(body.samples), matched)
        viol = [v for e in sample_evs for v in validate_event(e)]
        if viol:
            out["lint"].append({"level": "warning", "message": f"{len(viol)} OCSF conformance warnings, e.g. {viol[0]}", "line": None})
        out["ok"] = not any(i["level"] == "error" for i in out["lint"]) and out["tests"]["failed"] == 0
        return out

    @r.post("/onboard/publish")
    def publish(body: PublishReq, request: Request) -> dict[str, Any]:
        issues = lint_text(body.pack_yaml, min_tests=1, require_unverified=False)
        errors = [i for i in issues if i.level == "error"]
        if errors:
            raise err(400, "BAD_PACK", "; ".join(str(i) for i in errors[:5]))
        try:
            doc = load_pack_text(body.pack_yaml)
            pack = compile_pack(doc, cfg.pipeline.default_tz)
        except (PackError, yaml.YAMLError, ValueError) as e:
            raise err(400, "BAD_PACK", str(e)) from e
        if not doc.id.startswith("custom.") or not all(ch.isalnum() or ch in "._-" for ch in doc.id):
            raise err(400, "BAD_PACK", "Studio-published packs must have an id like custom.<slug> (letters, digits, . _ -)")
        fails = run_pack_tests(pack)
        if fails:
            raise err(400, "BAD_PACK", "golden vectors fail: " + "; ".join(str(f) for f in fails[:3]))
        custom = next((Path(d) for d in reversed(cfg.packs.dirs) if "custom" in str(d)), Path(cfg.data_dir) / "packs" / "custom")
        dest, rep = st.registry.publish(body.pack_yaml, custom, doc.id.split(".", 1)[1] + ".yaml")
        notified = False
        r_ = getattr(st.bus, "r", None)
        if r_ is not None:
            try:
                r_.publish(studio.RELOAD_CHANNEL, doc.id)
                notified = True
            except Exception:  # noqa: BLE001
                notified = False
        return {"published": True, "pack_id": doc.id, "version": doc.version, "path": str(dest),
                "reloaded": doc.id in rep.loaded and not rep.errors.get(str(dest)), "notified_workers": notified}

    return r


def _flatten(d: Any, prefix: str, out: dict[str, Any]) -> None:
    if isinstance(d, dict):
        for k, v in d.items():
            _flatten(v, f"{prefix}.{k}" if prefix else k, out)
    else:
        out[prefix] = d
