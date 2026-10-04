"""Sink contract (§6.3) and the retry/spool wrapper (§7.9: never ACK before every enabled sink accepted the batch)."""
from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

import orjson


class Sink(Protocol):
    name: str

    def write(self, events: list[dict[str, Any]]) -> None:
        """Called with batches AFTER the vault fsync (I1). May buffer; ``flush`` makes the buffer durable/visible."""

    def flush(self) -> None: ...
    def close(self) -> None: ...


class SinkError(Exception):
    """A sink could not accept a batch (after retries)."""


def spool_batch(spool_dir: str | Path, sink: str, events: list[dict[str, Any]]) -> Path:
    """Persist a batch a sink refused so nothing depends on process memory alone (one JSON document per line)."""
    d = Path(spool_dir) / sink
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{time.time_ns()}.jsonl"
    tmp = p.with_suffix(".tmp")
    with open(tmp, "wb") as f:
        for ev in events:
            try:
                f.write(orjson.dumps(ev) + b"\n")
            except TypeError:
                import json

                f.write(json.dumps(ev, default=str).encode() + b"\n")
        f.flush()
    tmp.replace(p)
    return p


def with_retry(fn: Callable[[], Any], attempts: int = 3, backoff: float = 0.1, sleep: Callable[[float], None] = time.sleep) -> None:
    """Run ``fn`` with exponential backoff; raise SinkError after ``attempts`` failures."""
    last: Exception | None = None
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as e:  # noqa: BLE001 - any transport/IO failure counts
            last = e
            if i + 1 < attempts:
                sleep(backoff * (5**i))
    raise SinkError(f"{type(last).__name__}: {last}") from last
