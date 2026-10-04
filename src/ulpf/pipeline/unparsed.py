"""Unparsed lane (§7.8): events no pack could parse still get a Base Event plus a Drain3 template id, so the Onboarding Studio can
say "these 48k events look the same - onboard this source?". Bounded memory; only unparsed events pass through here."""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

from ..model.envelope import RawEnvelope
from ..model.lineage import VaultRef
from ..normalize.mapper import unparsed_event

MASKS = [
    (r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "UUID"),
    (r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b", "MAC"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "IP"),
    (r"\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?\b", "TS"),
    (r"\b0x[0-9a-fA-F]+\b", "HEX"),
    (r"\b\d+\b", "NUM"),
]
MAX_CLUSTERS = 500
MAX_LINE = 600


class ClusterStore:
    """Where lanes publish template summaries (key = ``<worker>:<cluster_id>``)."""

    def put(self, items: dict[str, dict[str, Any]]) -> None:
        raise NotImplementedError

    def list(self) -> list[dict[str, Any]]:
        raise NotImplementedError


class MemoryClusterStore(ClusterStore):
    def __init__(self) -> None:
        self._d: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def put(self, items: dict[str, dict[str, Any]]) -> None:
        with self._lock:
            self._d.update(items)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._d.values())


class RedisClusterStore(ClusterStore):
    KEY = "ulpf:clusters"

    def __init__(self, client: Any) -> None:
        self.r = client

    def put(self, items: dict[str, dict[str, Any]]) -> None:
        if items:
            self.r.hset(self.KEY, mapping={k: json.dumps(v) for k, v in items.items()})

    def list(self) -> list[dict[str, Any]]:
        return [json.loads(v) for v in self.r.hvals(self.KEY)]


class UnparsedLane:
    def __init__(self, worker: str = "0", store: ClusterStore | None = None, publish_every: float = 2.0) -> None:
        cfg = TemplateMinerConfig()
        cfg.profiling_enabled = False
        cfg.drain_max_clusters = MAX_CLUSTERS
        cfg.drain_sim_th = 0.5
        cfg.masking_instructions = [MaskingInstruction(p, n) for p, n in MASKS]
        self.miner = TemplateMiner(None, cfg)
        self.worker = worker
        self.store = store
        self.publish_every = publish_every
        self._info: dict[int, dict[str, Any]] = {}
        self._dirty: set[int] = set()
        self._last = time.monotonic()
        self.count = 0

    def event(self, env: RawEnvelope, ref: VaultRef, reason: str | None = None) -> dict[str, Any]:
        line = env.data[:MAX_LINE].decode("utf-8", "replace")
        tid: str | None = None
        try:
            r = self.miner.add_log_message(line)
            cid = int(r["cluster_id"])
            tid = f"{self.worker}:{cid}"
            info = self._info.get(cid)
            now = int(time.time() * 1000)
            if info is None:
                info = self._info[cid] = {"template_id": tid, "template": "", "count": 0, "example_raw": line[:300], "samples": [],
                                          "peer_ips": [], "first_seen": now, "last_seen": now}
            info["template"] = r["template_mined"]
            info["count"] = int(r["cluster_size"])
            info["last_seen"] = now
            if len(info["samples"]) < 5:
                info["samples"].append(line[:300])
            if env.peer_ip and env.peer_ip not in info["peer_ips"] and len(info["peer_ips"]) < 5:
                info["peer_ips"].append(env.peer_ip)
            self._dirty.add(cid)
        except Exception:  # noqa: BLE001 - template mining is best effort; the event itself must still flow
            tid = None
        self.count += 1
        return unparsed_event(env, ref, tid, reason)

    def maybe_publish(self, force: bool = False) -> None:
        if self.store is None or not self._dirty:
            return
        if not force and time.monotonic() - self._last < self.publish_every:
            return
        self._last = time.monotonic()
        self.store.put({f"{self.worker}:{c}": self._info[c] for c in self._dirty})
        self._dirty.clear()


def merge_clusters(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Same template mined by several workers -> one cluster; ``share`` = fraction of all unparsed."""
    by: dict[str, dict[str, Any]] = {}
    for it in items:
        m = by.get(it["template"])
        if m is None:
            by[it["template"]] = dict(it, samples=list(it.get("samples", [])), peer_ips=list(it.get("peer_ips", [])))
        else:
            m["count"] += it["count"]
            m["samples"] = (m["samples"] + it.get("samples", []))[:5]
            m["peer_ips"] = sorted(set(m["peer_ips"]) | set(it.get("peer_ips", [])))[:5]
            m["first_seen"] = min(m["first_seen"], it["first_seen"])
            m["last_seen"] = max(m["last_seen"], it["last_seen"])
    out = sorted(by.values(), key=lambda x: -x["count"])
    total = sum(x["count"] for x in out) or 1
    for x in out:
        x["share"] = round(x["count"] / total, 4)
    return out
