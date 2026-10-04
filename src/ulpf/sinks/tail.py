"""Live tail stream (§7.9): a thin projection of every event into a capped stream for the UI WebSocket.

Redis: ``XADD norm.tail MAXLEN ~ 20000``. Memory: a bounded deque (single-process runs)."""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

import orjson

from ..normalize.lake_schema import tail_row

TAIL_STREAM = "norm.tail"
DEFAULT_MAX_EPS = 1000.0


class RateCap:
    """Token bucket (rows/second, burst = one second). The tail is a live *view*: above the cap it becomes a uniform-by-arrival sample
    (the lake, vault and ledger stay complete). ``skipped`` counts rows not offered to the stream. ``max_eps <= 0`` disables the cap."""

    def __init__(self, max_eps: float = DEFAULT_MAX_EPS) -> None:
        self.max_eps = max_eps
        self.tokens = max_eps
        self.t = time.monotonic()
        self.skipped = 0

    def take(self, n: int) -> int:
        if self.max_eps <= 0:
            return n
        now = time.monotonic()
        self.tokens = min(self.max_eps, self.tokens + (now - self.t) * self.max_eps)
        self.t = now
        k = min(n, int(self.tokens))
        self.tokens -= k
        self.skipped += n - k
        return k


def _sample(events: list[dict[str, Any]], k: int) -> list[int]:
    n = len(events)
    if k >= n:
        return list(range(n))
    return [i * n // k for i in range(k)]


def preview(ev: dict[str, Any], limit: int = 140) -> str | None:
    m = ev.get("message")
    if isinstance(m, str):
        return m[:limit]
    return None


class MemoryTail:
    name = "tail"

    def __init__(self, maxlen: int = 20_000, max_eps: float = 0.0) -> None:
        self.cap = RateCap(max_eps)
        self.q: deque[tuple[int, dict[str, Any]]] = deque(maxlen=maxlen)
        self._seq = 0
        self._lock = threading.Lock()

    def write(self, events: list[dict[str, Any]], messages: list[str | None] | None = None) -> None:
        keep = _sample(events, self.cap.take(len(events)))
        with self._lock:
            for i in keep:
                ev = events[i]
                self._seq += 1
                self.q.append((self._seq, tail_row(ev, messages[i] if messages else preview(ev))))

    def read_after(self, last_id: int, limit: int = 1000) -> tuple[int, list[dict[str, Any]]]:
        with self._lock:
            rows = [(i, r) for i, r in self.q if i > last_id][:limit]
        return (rows[-1][0] if rows else last_id), [r for _, r in rows]

    def head(self) -> int:
        return self._seq

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class RedisTail:
    name = "tail"

    def __init__(self, client: Any, maxlen: int = 20_000, stream: str = TAIL_STREAM, max_eps: float = DEFAULT_MAX_EPS) -> None:
        self.cap = RateCap(max_eps)
        self.r = client
        self.maxlen = maxlen
        self.stream = stream

    def write(self, events: list[dict[str, Any]], messages: list[str | None] | None = None) -> None:
        keep = _sample(events, self.cap.take(len(events)))
        if not keep:
            return
        pipe = self.r.pipeline(transaction=False)
        for i in keep:
            ev = events[i]
            row = tail_row(ev, messages[i] if messages else preview(ev))
            pipe.xadd(self.stream, {b"d": orjson.dumps(row)}, maxlen=self.maxlen, approximate=True)
        pipe.execute()

    def read_after(self, last_id: str, limit: int = 1000) -> tuple[str, list[dict[str, Any]]]:
        res = self.r.xread({self.stream: last_id}, count=limit)
        rows: list[dict[str, Any]] = []
        new = last_id
        for _name, msgs in res or []:
            for mid, fields in msgs:
                new = mid.decode() if isinstance(mid, bytes) else mid
                rows.append(orjson.loads(fields[b"d"]))
        return new, rows

    def head(self) -> str:
        info = self.r.xinfo_stream(self.stream) if self.r.exists(self.stream) else None
        return info["last-generated-id"].decode() if info and isinstance(info["last-generated-id"], bytes) else (info or {}).get("last-generated-id", "0-0")

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass
