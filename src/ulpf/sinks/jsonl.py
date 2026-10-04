"""OCSF JSONL sink: rotating files, one OCSF document per line (feed any file-ingesting SIEM)."""
from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..normalize.lake_schema import dumps_event


class JsonlSink:
    name = "jsonl"

    def __init__(self, root: str | Path, worker: str = "0", rotate_mb: float = 64, fsync: bool = True) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.worker = worker
        self.rotate_bytes = int(rotate_mb * 1024 * 1024)
        self.fsync = fsync
        self._f: Any = None
        self._size = 0
        self._n = 0
        self.rows_written = 0

    def _open(self) -> None:
        self._n += 1
        name = f"ocsf-{datetime.now(UTC):%Y%m%dT%H%M%S}-w{self.worker}-{time.time_ns() % 10**9}-{self._n}.jsonl"
        self._f = open(self.root / name, "ab")
        self._size = 0

    def write(self, events: list[dict[str, Any]]) -> None:
        if self._f is None:
            self._open()
        buf = ("\n".join(dumps_event(e) for e in events) + "\n").encode("utf-8")
        self._f.write(buf)
        self._size += len(buf)
        self.rows_written += len(events)
        if self._size >= self.rotate_bytes:
            self.flush()
            self._f.close()
            self._f = None

    def flush(self) -> None:
        if self._f is not None:
            self._f.flush()
            if self.fsync:
                os.fsync(self._f.fileno())

    def close(self) -> None:
        self.flush()
        if self._f is not None:
            self._f.close()
            self._f = None
