"""Per-source health computed from the lake (api-contract.md "Sources"). Short TTL cache: the UI polls these every few seconds."""
from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Any

import orjson

from .lake import Lake

SERIES_POINTS = 60
SERIES_STEP_MS = 5000
SAMPLE_UNMAPPED = 3000


class SourceStats:
    def __init__(self, lake: Lake, registry: Any, ttl: float = 3.0) -> None:
        self.lake, self.registry, self.ttl = lake, registry, ttl
        self._c: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def _cached(self, key: str, fn: Any) -> Any:
        now = time.monotonic()
        with self._lock:
            hit = self._c.get(key)
            if hit and now - hit[0] < self.ttl:
                return hit[1]
        val = fn()
        with self._lock:
            self._c[key] = (now, val)
        return val

    # ------------------------------------------------------------------ helpers
    def _meta(self, sid: str) -> dict[str, Any]:
        p = self.registry.snapshot.by_id.get(sid)
        if p is not None:
            m = p.doc.meta
            return {"vendor": str(m.get("vendor", "")), "product": str(m.get("product", p.id)), "category": str(m.get("category", "")),
                    "pack_version": p.version, "verified": bool(p.verified)}
        if sid == "ulpf.analytics":
            return {"vendor": "ULPF", "product": "analytics", "category": "detection", "pack_version": "", "verified": False}
        return {"vendor": "", "product": "unparsed" if sid == "unknown" else sid, "category": "unknown", "pack_version": "", "verified": False}

    def _series(self, now_ms: int, files: list[str], where_src: str | None = None, with_quality: bool = False
                ) -> dict[str, dict[int, tuple[int, int, float]]]:
        """source -> bucket_start -> (events, parsed, coverage_sum) over the last SERIES_POINTS buckets (by receive time)."""
        t0 = now_ms // SERIES_STEP_MS * SERIES_STEP_MS - (SERIES_POINTS - 1) * SERIES_STEP_MS
        w = "recv_time >= to_timestamp(? / 1000.0)"
        p: list[Any] = [t0]
        if where_src:
            w += " AND source_id = ?"
            p.append(where_src)
        rows = self.lake.run(files, f"SELECT source_id, (epoch_ms(recv_time) // {SERIES_STEP_MS}) * {SERIES_STEP_MS} AS t, count(*), "
                                    f"count(*) FILTER (WHERE status = 'parsed'), sum(coverage) FROM {{lake}} WHERE {w} GROUP BY 1, 2", p)
        out: dict[str, dict[int, tuple[int, int, float]]] = {}
        for sid, t, n, parsed, cov in rows:
            out.setdefault(sid or "unknown", {})[int(t)] = (int(n), int(parsed), float(cov or 0.0))
        return out

    @staticmethod
    def _points(now_ms: int, d: dict[int, tuple[int, int, float]], kind: str) -> list[dict[str, Any]]:
        t0 = now_ms // SERIES_STEP_MS * SERIES_STEP_MS - (SERIES_POINTS - 1) * SERIES_STEP_MS
        out = []
        for i in range(SERIES_POINTS):
            t = t0 + i * SERIES_STEP_MS
            n, parsed, cov = d.get(t, (0, 0, 0.0))
            if kind == "eps":
                v = n / (SERIES_STEP_MS / 1000)
            elif kind == "parse":
                v = parsed / n if n else 1.0
            else:
                v = cov / n if n else 0.0
            out.append({"t": t, "v": round(v, 4)})
        return out

    def _unmapped(self, files: list[str], sid: str) -> list[tuple[str, int, str | None]]:
        rows = self.lake.run(files, f"SELECT unmapped FROM {{lake}} WHERE source_id = ? AND unmapped <> '{{}}' "
                                    f"ORDER BY time DESC LIMIT {SAMPLE_UNMAPPED}", [sid])
        cnt: Counter[str] = Counter()
        ex: dict[str, str] = {}
        for (u,) in rows:
            try:
                d = orjson.loads(u)
            except orjson.JSONDecodeError:
                continue
            for k, v in d.items():
                cnt[k] += 1
                ex.setdefault(k, str(v)[:120])
        return [(k, c, ex.get(k)) for k, c in cnt.most_common(200)]    # counts are over the newest SAMPLE_UNMAPPED events

    # ------------------------------------------------------------------ public
    def summaries(self) -> list[dict[str, Any]]:
        return list(self._cached("summaries", self._summaries))

    def _summaries(self) -> list[dict[str, Any]]:
        now_ms = int(time.time() * 1000)
        files = self.lake.files()
        tot = self.lake.run(files, "SELECT source_id, count(*), count(*) FILTER (WHERE status='parsed'), "
                                   "count(*) FILTER (WHERE status='partial'), count(*) FILTER (WHERE status='unparsed'), avg(coverage), "
                                   "max(epoch_ms(recv_time)) FROM {lake} GROUP BY 1") if files else []
        ser = self._series(now_ms, files) if files else {}
        by = {r[0] or "unknown": r for r in tot}
        ids = sorted(set(by) | set(self.registry.snapshot.by_id))
        out = []
        for sid in ids:
            r = by.get(sid)
            n = int(r[1]) if r else 0
            sc = {"parsed": int(r[2]), "partial": int(r[3]), "unparsed": int(r[4])} if r else {"parsed": 0, "partial": 0, "unparsed": 0}
            d = ser.get(sid, {})
            eps_pts = self._points(now_ms, d, "eps")
            recent = [v for v in (x["v"] for x in eps_pts[-2:])]
            parse_rate = sc["parsed"] / n if n else 1.0
            mean_cov = float(r[5] or 0.0) if r else 0.0
            drift = self._drift(sid, n, parse_rate, mean_cov, now_ms, d)
            top = [{"field": k, "count": c} for k, c, _ in self._unmapped(files, sid)[:10]] if n and files else []
            out.append({**self._meta(sid), "source_id": sid, "eps": round(sum(recent) / max(1, len(recent)), 2), "eps_series": eps_pts,
                        "parse_rate": round(parse_rate, 4), "mean_coverage": round(mean_cov, 4),
                        "last_seen": int(r[6]) if r and r[6] is not None else None, "total_events": n, "status_counts": sc,
                        "top_unmapped": top, "drift": drift})
        return out

    @staticmethod
    def _drift(sid: str, n: int, parse_rate: float, mean_cov: float, now_ms: int, d: dict[int, tuple[int, int, float]]) -> dict[str, Any]:
        reasons: list[str] = []
        ev = sum(v[0] for v in d.values())
        if ev >= 50:
            rec_parse = sum(v[1] for v in d.values()) / ev
            rec_cov = sum(v[2] for v in d.values()) / ev
            if n and rec_parse < parse_rate - 0.05:
                reasons.append(f"parse rate in the last 5 minutes is {rec_parse:.0%} versus {parse_rate:.0%} overall")
            if n and rec_cov < mean_cov - 0.08:
                reasons.append(f"mean field coverage dropped to {rec_cov:.0%} from {mean_cov:.0%} overall: new fields are arriving unmapped")
        return {"flag": bool(reasons), "reasons": reasons}

    def health(self, sid: str) -> dict[str, Any] | None:
        base = next((s for s in self.summaries() if s["source_id"] == sid), None)
        if base is None:
            return None
        return self._cached(f"health:{sid}", lambda: self._health(base))

    def _health(self, base: dict[str, Any]) -> dict[str, Any]:
        sid = base["source_id"]
        now_ms = int(time.time() * 1000)
        files = self.lake.files()
        d = self._series(now_ms, files, sid).get(sid, {}) if files else {}
        unm = [{"field": k, "count": c, **({"example": e} if e else {})} for k, c, e in self._unmapped(files, sid)] if files and base["total_events"] else []
        peers: list[dict[str, Any]] = []
        if files and base["total_events"]:
            rows = self.lake.run(files, "SELECT json_extract_string(event, '$.ulpf.peer_ip') AS ip, count(*), max(epoch_ms(recv_time)) FROM "
                                        "(SELECT event, recv_time FROM {lake} WHERE source_id = ? ORDER BY time DESC LIMIT 20000) "
                                        "GROUP BY 1 ORDER BY 2 DESC LIMIT 20", [sid])
            peers = [{"ip": r[0] or "", "events": int(r[1]), "last_seen": int(r[2])} for r in rows]
        return {**base, "coverage_series": self._points(now_ms, d, "cov"), "parse_rate_series": self._points(now_ms, d, "parse"),
                "unmapped_all": unm, "peers": peers}
