"""Observability (§7.15). Hot-path rule: workers increment plain Python ints/dicts; once per second they publish a snapshot
(to Redis, so the API process can expose one `/metrics` for the whole node). Nothing here logs per event."""
from __future__ import annotations

import bisect
import json
import os
import time
from collections import defaultdict
from collections.abc import Iterable, Iterator
from typing import Any

from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, HistogramMetricFamily
from prometheus_client.exposition import generate_latest
from prometheus_client.registry import CollectorRegistry

METRICS_KEY = "ulpf:metrics"
LAT_BUCKETS = (0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


class LocalHistogram:
    __slots__ = ("buckets", "counts", "sum", "n")

    def __init__(self, buckets: tuple[float, ...] = LAT_BUCKETS) -> None:
        self.buckets = buckets
        self.counts = [0] * (len(buckets) + 1)
        self.sum = 0.0
        self.n = 0

    def observe(self, v: float) -> None:
        self.counts[bisect.bisect_left(self.buckets, v)] += 1
        self.sum += v
        self.n += 1

    def data(self) -> dict[str, Any]:
        return {"b": list(self.buckets), "c": list(self.counts), "s": self.sum, "n": self.n}


class Metrics:
    """One per process. ``flat()`` is the publishable snapshot; counters are cumulative since process start."""

    def __init__(self, worker: str = "0") -> None:
        self.worker = worker
        self.ingested: dict[str, int] = defaultdict(int)                    # source -> n
        self.vaulted = 0
        self.normalized: dict[tuple[str, str], int] = defaultdict(int)       # (status, source_id) -> n
        self.sunk: dict[str, int] = defaultdict(int)                         # sink -> n
        self.dropped: dict[str, int] = defaultdict(int)                      # reason -> n
        self.violations: dict[tuple[str, str], int] = defaultdict(int)       # (pack, field) -> n
        self.errors: dict[str, int] = defaultdict(int)                       # kind -> n (extract/normalize/sink errors)
        self.e2e = LocalHistogram()                                          # ingest -> sink seconds (sampled)
        self.stage = {k: LocalHistogram() for k in ("vault", "route", "sink")}   # stage latency per batch (sampled)
        self.gauges: dict[str, float] = {}
        self._t = time.monotonic()
        self._last_pub = 0.0

    def due(self, every: float = 1.0) -> bool:
        return time.monotonic() - self._last_pub >= every

    def flat(self) -> dict[str, Any]:
        self.gauges["worker_rss_bytes"] = float(_rss())
        self.gauges["uptime_seconds"] = time.monotonic() - self._t
        return {
            "worker": self.worker, "t": time.time(), "pid": os.getpid(),
            "ingested": dict(self.ingested), "vaulted": self.vaulted,
            "normalized": [[s, src, n] for (s, src), n in self.normalized.items()],
            "sunk": dict(self.sunk), "dropped": dict(self.dropped),
            "violations": [[p, f, n] for (p, f), n in self.violations.items()],
            "errors": dict(self.errors), "e2e": self.e2e.data(), "stage": {k: h.data() for k, h in self.stage.items()},
            "gauges": dict(self.gauges),
        }

    def publish(self, client: Any) -> None:
        self._last_pub = time.monotonic()
        client.hset(METRICS_KEY, f"{self.worker}", json.dumps(self.flat()))


def _rss() -> int:
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return 0


class NodeCollector:
    """Prometheus collector that renders a set of worker snapshots (plus API-side gauges) as one coherent exposition."""

    def __init__(self, snapshots: Any, gauges: Any = None) -> None:
        self._snaps = snapshots      # callable -> iterable of flat() dicts
        self._gauges = gauges        # callable -> iterable of (name, help, labels dict, value)

    def collect(self) -> Iterator[Any]:
        snaps: list[dict[str, Any]] = list(self._snaps())
        ing = CounterMetricFamily("ulpf_ingested", "Events published to the bus", labels=["source_hint"])
        vlt = CounterMetricFamily("ulpf_vaulted", "Events made durable in the raw vault", labels=["worker"])
        nrm = CounterMetricFamily("ulpf_normalized", "Events by terminal status", labels=["status", "source", "worker"])
        snk = CounterMetricFamily("ulpf_sunk", "Events accepted by a sink", labels=["sink", "worker"])
        drp = CounterMetricFamily("ulpf_dropped", "Events dropped by explicit configuration", labels=["reason", "worker"])
        vio = CounterMetricFamily("ulpf_ocsf_violation", "Sampled OCSF conformance violations", labels=["pack", "field", "worker"])
        err = CounterMetricFamily("ulpf_errors", "Recovered errors (never lost events)", labels=["kind", "worker"])
        e2e = HistogramMetricFamily("ulpf_e2e_latency_seconds", "Ingest to sink latency (sampled)", labels=["worker"])
        gauges: dict[str, GaugeMetricFamily] = {}
        for s in snaps:
            w = str(s.get("worker", "0"))
            for src, n in (s.get("ingested") or {}).items():
                ing.add_metric([src], n)
            vlt.add_metric([w], s.get("vaulted", 0))
            for st, src, n in s.get("normalized", []):
                nrm.add_metric([st, src, w], n)
            for k, n in (s.get("sunk") or {}).items():
                snk.add_metric([k, w], n)
            for k, n in (s.get("dropped") or {}).items():
                drp.add_metric([k, w], n)
            for p, f, n in s.get("violations", []):
                vio.add_metric([p, f, w], n)
            for k, n in (s.get("errors") or {}).items():
                err.add_metric([k, w], n)
            h = s.get("e2e")
            if h and h.get("n"):
                cum, acc = [], 0
                for b, c in zip(h["b"], h["c"]):
                    acc += c
                    cum.append((str(b), acc))
                cum.append(("+Inf", h["n"]))
                e2e.add_metric([w], cum, h["s"])
            for gname, val in (s.get("gauges") or {}).items():
                g = gauges.setdefault(gname, GaugeMetricFamily(f"ulpf_{gname}", f"worker gauge {gname}", labels=["worker"]))
                g.add_metric([w], val)
        yield from (ing, vlt, nrm, snk, drp, vio, err, e2e, *gauges.values())
        if self._gauges:
            fam: dict[str, GaugeMetricFamily] = {}
            for name, helptext, labels, value in self._gauges():
                g = fam.get(name)
                if g is None:
                    g = fam[name] = GaugeMetricFamily(name, helptext, labels=list(labels))
                g.add_metric(list(labels.values()), value)
            yield from fam.values()


def render(snapshots: Any, gauges: Any = None) -> bytes:
    reg = CollectorRegistry()
    reg.register(NodeCollector(snapshots, gauges))  # type: ignore[arg-type]
    return generate_latest(reg)


def read_snapshots(client: Any) -> Iterable[dict[str, Any]]:
    out = []
    for _k, v in client.hgetall(METRICS_KEY).items():
        try:
            out.append(json.loads(v))
        except ValueError:
            continue
    return out
