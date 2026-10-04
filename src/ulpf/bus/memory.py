"""In-process bus: same semantics as the Redis one (consumer ownership, ack, redelivery) for tests and ``--no-redis`` replay."""
from __future__ import annotations

import threading
import time
from collections import deque

from .base import LedgerDeltas


class MemoryLedger:
    def __init__(self) -> None:
        self._d: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()

    def apply(self, deltas: LedgerDeltas) -> None:
        with self._lock:
            for src, fields in deltas.items():
                row = self._d.setdefault(src, {})
                for k, v in fields.items():
                    row[k] = row.get(k, 0) + v

    def snapshot(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {s: dict(r) for s, r in self._d.items()}

    def reset(self) -> None:
        with self._lock:
            self._d.clear()


class MemoryBus:
    def __init__(self, partitions: int = 4, maxlen: int = 2_000_000) -> None:
        self.partitions = partitions
        self.maxlen = maxlen
        self.ledger = MemoryLedger()
        self._q: list[deque[tuple[str, bytes]]] = [deque() for _ in range(partitions)]
        self._pending: list[dict[str, tuple[bytes, str, float]]] = [{} for _ in range(partitions)]
        self._seq = [0] * partitions
        self._cv = threading.Condition()

    def publish(self, partition: int, batch: list[bytes], ledger_deltas: LedgerDeltas | None = None) -> None:
        with self._cv:
            q = self._q[partition]
            for payload in batch:
                self._seq[partition] += 1
                q.append((f"{self._seq[partition]}-0", payload))
            if ledger_deltas:
                self.ledger.apply(ledger_deltas)
            self._cv.notify_all()

    def consume(self, partitions: list[int], consumer: str, max_n: int, block_ms: int) -> list[tuple[int, str, bytes]]:
        deadline = time.monotonic() + block_ms / 1000.0
        with self._cv:
            while True:
                out: list[tuple[int, str, bytes]] = []
                now = time.monotonic()
                for p in partitions:
                    q = self._q[p]
                    while q and len(out) < max_n:
                        mid, payload = q.popleft()
                        self._pending[p][mid] = (payload, consumer, now)
                        out.append((p, mid, payload))
                if out or block_ms <= 0:
                    return out
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return out
                self._cv.wait(remaining)

    def ack(self, partition: int, msg_ids: list[str], ledger_deltas: LedgerDeltas | None = None) -> None:
        with self._cv:
            pend = self._pending[partition]
            for m in msg_ids:
                pend.pop(m, None)
            if ledger_deltas:
                self.ledger.apply(ledger_deltas)

    def claim_stale(self, partitions: list[int], consumer: str, min_idle_ms: int, max_n: int) -> list[tuple[int, str, bytes]]:
        out: list[tuple[int, str, bytes]] = []
        now = time.monotonic()
        with self._cv:
            for p in partitions:
                for mid, (payload, _owner, ts) in sorted(self._pending[p].items(), key=lambda kv: int(kv[0].split("-")[0])):
                    if len(out) >= max_n:
                        return out
                    if (now - ts) * 1000 >= min_idle_ms:
                        self._pending[p][mid] = (payload, consumer, now)
                        out.append((p, mid, payload))
        return out

    def lag(self, partition: int) -> int:
        with self._cv:
            return len(self._q[partition]) + len(self._pending[partition])

    def close(self) -> None:
        pass
