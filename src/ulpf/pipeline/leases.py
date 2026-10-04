"""Partition leases for horizontally scaled workers (``docker compose up --scale worker=N``).

A worker has no static index in that setting, so partition ownership is negotiated through Redis: every worker registers a heartbeat,
computes its fair share ``ceil(partitions / live_workers)``, takes free partitions with ``SET NX EX`` and renews what it owns; a worker
above its share (a new peer joined) releases the surplus. A partition therefore has at most one live consumer (I5: per-source order),
and a crashed worker's partitions are picked up when its lease expires (its un-acked messages are re-delivered via ``claim_stale``).

Known limit: a worker that stalls longer than the lease TTL (``ttl_s``) can overlap its successor for one batch; the result is a
duplicate keyed by ``event_id`` (collapsed on read/compaction, I3), never a loss. A single-process node uses static assignment instead."""
from __future__ import annotations

import time
import uuid
from typing import Any

WORKERS_KEY = "ulpf:workers"
LEASE_KEY = "ulpf:lease:{p}"


class LeaseManager:
    def __init__(self, client: Any, partitions: int, uid: str | None = None, ttl_s: int = 10, every_s: float = 1.0) -> None:
        self.r = client
        self.partitions = partitions
        self.uid = uid or uuid.uuid4().hex[:8]
        self.ttl = ttl_s
        self.every = every_s
        self.owned: set[int] = set()
        self._t = 0.0

    def _live(self, now: float) -> int:
        self.r.zadd(WORKERS_KEY, {self.uid: now})
        self.r.zremrangebyscore(WORKERS_KEY, 0, now - self.ttl)
        return max(1, int(self.r.zcard(WORKERS_KEY)))

    def _holder(self, p: int) -> str | None:
        v = self.r.get(LEASE_KEY.format(p=p))
        return None if v is None else (v.decode() if isinstance(v, bytes) else str(v))

    def refresh(self, force: bool = False, before_release: Any = None) -> tuple[set[int], set[int]]:
        """Renew/acquire/release. Returns ``(gained, lost)`` partition sets (empty when nothing changed or not yet due).
        ``before_release(partitions)`` runs before a surplus partition is let go (the worker commits what it has pending there)."""
        now = time.time()
        if not force and now - self._t < self.every:
            return set(), set()
        self._t = now
        live = self._live(now)
        share = -(-self.partitions // live)
        gained: set[int] = set()
        lost: set[int] = set()
        for p in sorted(self.owned):                       # renew; a lease we no longer hold is lost
            if self._holder(p) == self.uid:
                self.r.expire(LEASE_KEY.format(p=p), self.ttl)
            else:
                self.owned.discard(p)
                lost.add(p)
        surplus = sorted(self.owned, reverse=True)[: max(0, len(self.owned) - share)]
        if surplus:
            if before_release:
                before_release(set(surplus))
            for p in surplus:
                if self._holder(p) == self.uid:
                    self.r.delete(LEASE_KEY.format(p=p))
                self.owned.discard(p)
                lost.add(p)
        if len(self.owned) < share:
            for p in range(self.partitions):
                if len(self.owned) >= share:
                    break
                if p not in self.owned and self.r.set(LEASE_KEY.format(p=p), self.uid, nx=True, ex=self.ttl):
                    self.owned.add(p)
                    gained.add(p)
        return gained, lost

    def release_all(self) -> None:
        for p in list(self.owned):
            if self._holder(p) == self.uid:
                self.r.delete(LEASE_KEY.format(p=p))
        self.owned.clear()
        self.r.zrem(WORKERS_KEY, self.uid)
