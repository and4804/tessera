"""Envelope factory + batching publisher shared by every ingest path (§7.1)."""
from __future__ import annotations

import time
from collections.abc import Callable

from ..bus.base import Bus, LedgerDeltas, partition_for
from ..model.envelope import RawEnvelope, encode_envelope
from ..model.ids import uuid7


def source_key(hint: str | None, peer_ip: str) -> str:
    """Ledger/source identity at ingest: the explicit hint when given, else the peer address."""
    return hint or peer_ip or "unknown"


class Publisher:
    """Accumulates envelopes per partition; publishes at ``batch_max`` envelopes or when ``flush_due`` says 5 ms elapsed.

    ``ingested_total{source}`` is applied atomically with the XADD (Redis MULTI), so the ledger counts exactly what was published.
    """

    def __init__(self, bus: Bus, collector_id: str, *, max_event_bytes: int = 65536, batch_max: int = 500, batch_ms: float = 5.0,
                 clock_ns: Callable[[], int] = time.time_ns) -> None:
        self.bus = bus
        self.collector_id = collector_id
        self.max_event_bytes = max_event_bytes
        self.batch_max = batch_max
        self.batch_s = batch_ms / 1000.0
        self._clock = clock_ns
        self._parts: dict[int, list[bytes]] = {}
        self._deltas: dict[int, LedgerDeltas] = {}
        self._n = 0
        self._first = 0.0
        self.published = 0
        self.truncated = 0

    def make(self, data: bytes, transport: str, peer_ip: str = "", peer_port: int = 0, hint: str | None = None,
             truncated: bool = False) -> RawEnvelope:
        if len(data) > self.max_event_bytes:
            data, truncated = data[: self.max_event_bytes], True
        if truncated:
            self.truncated += 1
        return RawEnvelope(uuid7(), self._clock(), self.collector_id, transport, peer_ip, peer_port, data, hint, truncated)

    def submit(self, env: RawEnvelope) -> None:
        p = partition_for(env.peer_ip or env.hint or "unknown", self.bus.partitions)
        if self._n == 0:
            self._first = time.monotonic()
        self._parts.setdefault(p, []).append(encode_envelope(env))
        d = self._deltas.setdefault(p, {}).setdefault(source_key(env.hint, env.peer_ip), {})
        d["ingested"] = d.get("ingested", 0) + 1
        self._n += 1
        if self._n >= self.batch_max:
            self.flush()

    def ingest(self, data: bytes, transport: str, peer_ip: str = "", peer_port: int = 0, hint: str | None = None,
               truncated: bool = False) -> RawEnvelope:
        env = self.make(data, transport, peer_ip, peer_port, hint, truncated)
        self.submit(env)
        return env

    def flush_due(self) -> bool:
        return self._n > 0 and time.monotonic() - self._first >= self.batch_s

    @property
    def pending(self) -> int:
        return self._n

    def flush(self) -> int:
        """Publish everything buffered. A partition whose publish raises stays buffered (retried on the next flush) and the
        exception propagates; partitions already published are not repeated."""
        if not self._n:
            return 0
        done = 0
        try:
            for p in list(self._parts):
                batch = self._parts[p]
                self.bus.publish(p, batch, self._deltas[p])
                del self._parts[p], self._deltas[p]
                self._n -= len(batch)
                done += len(batch)
        finally:
            self.published += done
        return done
