"""Per-(src_ip, 60 s window) features over normalized events (§7.12). Slow path / batch only.

Input rows are OCSF events as nested dicts (what the pipeline emits) or flat dotted dicts (loggen truth); `ulpf.raw_ref`
(if present) is carried through so findings can cite evidence. Two engines with identical output:
DuckDB SQL when `duckdb` is importable, otherwise a pure-Python aggregation.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

WINDOW_S = 60
FEATURES = ["conn_count", "uniq_dst_ip", "uniq_dst_port", "deny_ratio", "bytes_out_sum", "auth_fail_count", "uniq_sources"]
MAX_REFS = 20
SMOOTH = 4   # deny_ratio = denies / (conns + SMOOTH): one denied connection is not a 100% deny ratio


def _get(ev: dict[str, Any], path: str) -> Any:
    if path in ev:
        return ev[path]
    cur: Any = ev
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


@dataclass
class Row:
    """One normalized-event projection; the only thing the aggregation needs."""
    t_ms: int
    src: str
    dst: str | None
    dport: int | None
    cls: int
    deny: bool
    bytes_out: int
    auth_fail: bool
    source: str | None = None
    ref: str | None = None


def project(ev: dict[str, Any], source: str | None = None) -> Row | None:
    src, t = _get(ev, "src_endpoint.ip"), _get(ev, "time")
    if not src or t is None:
        return None
    cls = int(_get(ev, "class_uid") or 0)
    ref = _get(ev, "ulpf.raw_ref")
    return Row(int(t), str(src), _get(ev, "dst_endpoint.ip"), _get(ev, "dst_endpoint.port"), cls,
               cls == 4001 and _get(ev, "action_id") == 2,
               int(_get(ev, "traffic.bytes_out") or 0),
               cls == 3002 and _get(ev, "status_id") == 2,
               source or _get(ev, "ulpf.source_id"), str(ref) if ref else None)


@dataclass
class Window:
    src_ip: str
    window_start_ms: int
    features: dict[str, float]
    refs: list[str] = field(default_factory=list)
    n_events: int = 0


def _build(rows: Iterable[Row], window_s: int) -> list[Window]:
    w_ms = window_s * 1000
    acc: dict[tuple[str, int], dict[str, Any]] = {}
    for r in rows:
        k = (r.src, r.t_ms // w_ms * w_ms)
        a = acc.get(k)
        if a is None:
            a = acc[k] = {"n": 0, "dst": set(), "dport": set(), "deny": 0, "conn": 0, "bytes": 0, "af": 0, "srcs": set(), "refs": []}
        a["n"] += 1
        if r.cls == 4001:
            a["conn"] += 1
            a["deny"] += r.deny
            a["bytes"] += r.bytes_out
        if r.dst:
            a["dst"].add(r.dst)
        if r.dport is not None:
            a["dport"].add(r.dport)
        a["af"] += r.auth_fail
        if r.source:
            a["srcs"].add(r.source)
        if r.ref and len(a["refs"]) < MAX_REFS and (r.deny or r.auth_fail or r.bytes_out):
            a["refs"].append(r.ref)
    out = []
    for (src, ws), a in sorted(acc.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        f = {"conn_count": a["conn"], "uniq_dst_ip": len(a["dst"]), "uniq_dst_port": len(a["dport"]),
             "deny_ratio": a["deny"] / (a["conn"] + SMOOTH), "bytes_out_sum": a["bytes"],
             "auth_fail_count": a["af"], "uniq_sources": len(a["srcs"])}
        out.append(Window(src, ws, {k: float(v) for k, v in f.items()}, a["refs"], a["n"]))
    return out


_SQL = """
SELECT src, (t_ms // {w}) * {w} AS ws,
  COUNT(*) FILTER (WHERE cls = 4001) AS conn_count,
  COUNT(DISTINCT dst) AS uniq_dst_ip, COUNT(DISTINCT dport) AS uniq_dst_port,
  SUM(CASE WHEN deny THEN 1 ELSE 0 END) * 1.0 / (COUNT(*) FILTER (WHERE cls = 4001) + {s}) AS deny_ratio,
  COALESCE(SUM(CASE WHEN cls = 4001 THEN bytes_out ELSE 0 END), 0) AS bytes_out_sum,
  SUM(CASE WHEN auth_fail THEN 1 ELSE 0 END) AS auth_fail_count,
  COUNT(DISTINCT source) AS uniq_sources, COUNT(*) AS n
FROM rows GROUP BY 1, 2 ORDER BY 2, 1
"""


def _duckdb(rows: list[Row], window_s: int) -> list[Window] | None:
    try:
        import duckdb  # type: ignore
    except ImportError:
        return None
    con = duckdb.connect(":memory:")
    con.execute("CREATE TABLE rows(t_ms BIGINT, src VARCHAR, dst VARCHAR, dport BIGINT, cls INTEGER, deny BOOLEAN, bytes_out BIGINT, auth_fail BOOLEAN, source VARCHAR)")
    con.executemany("INSERT INTO rows VALUES (?,?,?,?,?,?,?,?,?)",
                    [(r.t_ms, r.src, r.dst, r.dport, r.cls, r.deny, r.bytes_out, r.auth_fail, r.source) for r in rows])
    res = con.execute(_SQL.format(w=window_s * 1000, s=SMOOTH)).fetchall()
    refs: dict[tuple[str, int], list[str]] = defaultdict(list)
    w_ms = window_s * 1000
    for r in rows:
        k = (r.src, r.t_ms // w_ms * w_ms)
        if r.ref and len(refs[k]) < MAX_REFS and (r.deny or r.auth_fail or r.bytes_out):
            refs[k].append(r.ref)
    return [Window(s, ws, dict(zip(FEATURES, map(float, vals[:7]), strict=True)), refs.get((s, ws), []), int(n))
            for s, ws, *vals, n in [(x[0], x[1], *x[2:9], x[9]) for x in res]]


def build_windows(events: Iterable[dict[str, Any]], window_s: int = WINDOW_S, source: str | None = None, engine: str = "auto") -> list[Window]:
    rows = [r for r in (project(e, source) for e in events) if r]
    if engine in ("auto", "duckdb"):
        out = _duckdb(rows, window_s)
        if out is not None:
            return out
        if engine == "duckdb":
            raise RuntimeError("duckdb not installed")
    return _build(rows, window_s)
