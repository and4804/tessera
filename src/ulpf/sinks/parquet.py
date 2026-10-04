"""Parquet lake sink + compactor (§7.9).

Layout: ``lake/class_uid=4001/dt=YYYY-MM-DD/hour=HH/w<worker>-<ts>-<n>.parquet`` (zstd). Rows buffer in memory until ``flush_rows``
or ``flush_secs``; the worker group-commits (acks the bus) only after ``flush()``. Files appear atomically (write ``.tmp`` then rename).
The compactor merges small files per partition and collapses duplicates by ``event_id`` (I3)."""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from ..normalize.lake_schema import SCHEMA, project, rows_to_table


def partition_dir(root: Path, class_uid: int, t_ms: int) -> Path:
    d = datetime.fromtimestamp(t_ms / 1000, UTC)
    return root / f"class_uid={class_uid}" / f"dt={d:%Y-%m-%d}" / f"hour={d:%H}"


class ParquetSink:
    name = "parquet"

    def __init__(self, root: str | Path, worker: str = "0", flush_rows: int = 50_000, flush_secs: float = 5.0) -> None:
        self.root = Path(root)
        self.worker = worker
        self.flush_rows = flush_rows
        self.flush_secs = flush_secs
        self._rows: dict[tuple[int, str, str], list[tuple[Any, ...]]] = defaultdict(list)
        self._n = 0
        self._first = 0.0
        self._seq = 0
        self.files_written = 0
        self.rows_written = 0

    def write(self, events: list[dict[str, Any]]) -> None:
        for ev in events:
            row = project(ev)
            t = row[3] if row[3] is not None else (row[4] or 0)
            d = datetime.fromtimestamp(t / 1000, UTC) if 0 <= t < 253402300799000 else datetime.fromtimestamp(0, UTC)
            key = (row[5] or 0, f"{d:%Y-%m-%d}", f"{d:%H}")
            if not self._n:
                self._first = time.monotonic()
            self._rows[key].append(row)
            self._n += 1

    def due(self) -> bool:
        """True when a flush is warranted by size or age (the worker also flushes when idle)."""
        return self._n >= self.flush_rows or (self._n > 0 and time.monotonic() - self._first >= self.flush_secs)

    @property
    def buffered(self) -> int:
        return self._n

    def flush(self) -> None:
        if not self._n:
            return
        rows_by_key, self._rows, self._n = self._rows, defaultdict(list), 0
        try:
            for (cuid, dt, hour), rows in rows_by_key.items():
                d = self.root / f"class_uid={cuid}" / f"dt={dt}" / f"hour={hour}"
                d.mkdir(parents=True, exist_ok=True)
                self._seq += 1
                name = f"w{self.worker}-{time.time_ns()}-{self._seq}.parquet"
                tmp = d / (name + ".tmp")
                pq.write_table(rows_to_table(rows), tmp, compression="zstd", compression_level=3)
                os.replace(tmp, d / name)
                self.files_written += 1
                self.rows_written += len(rows)
        except BaseException:
            # keep what was not written so a retry is lossless (written partitions are idempotent by event_id)
            for k, v in rows_by_key.items():
                self._rows[k][:0] = v
                self._n += len(v)
            raise

    def close(self) -> None:
        self.flush()


class Compactor:
    """Merge small parquet files per ``hour=`` partition and drop duplicate ``event_id``s."""

    def __init__(self, root: str | Path, min_files: int = 4, settle_s: float = 30.0, target_rows: int = 2_000_000) -> None:
        self.root = Path(root)
        self.min_files = min_files
        self.settle_s = settle_s
        self.target_rows = target_rows
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.compacted = 0
        self.duplicates_removed = 0

    def _partitions(self) -> list[Path]:
        return sorted({p.parent for p in self.root.glob("class_uid=*/dt=*/hour=*/*.parquet")})

    def compact_partition(self, d: Path, now: float | None = None, force: bool = False) -> int:
        """Merge the settled files of one partition; returns the number of source files replaced."""
        now = time.time() if now is None else now
        files = sorted(p for p in d.glob("*.parquet") if force or now - p.stat().st_mtime >= self.settle_s)
        if len(files) < (2 if force else self.min_files):
            return 0
        tables = [pq.read_table(f) for f in files]
        merged = pa.concat_tables(tables, promote_options="default") if len(tables) > 1 else tables[0]
        before = merged.num_rows
        ids = merged.column("event_id").to_pylist()
        seen: set[str | None] = set()
        keep = []
        for i, e in enumerate(ids):
            if e is None or e not in seen:
                keep.append(i)
                seen.add(e)
        if len(keep) != before:
            merged = merged.take(pa.array(keep))
            self.duplicates_removed += before - len(keep)
        # order by event time inside the file: tighter row-group stats for time-range queries
        merged = merged.sort_by([("time", "descending")]).cast(SCHEMA)
        name = f"c-{time.time_ns()}.parquet"
        tmp = d / (name + ".tmp")
        pq.write_table(merged, tmp, compression="zstd", compression_level=6)
        os.replace(tmp, d / name)             # merged file becomes visible first ...
        for f in files:                       # ... then the sources go (readers may briefly see duplicates; reads dedupe by event_id)
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        self.compacted += len(files)
        return len(files)

    def compact_once(self, force: bool = False) -> int:
        n = 0
        for d in self._partitions():
            try:
                n += self.compact_partition(d, force=force)
            except (OSError, pa.ArrowInvalid):
                continue
        return n

    def start(self, every_s: float = 300.0) -> None:
        def loop() -> None:
            while not self._stop.wait(every_s):
                try:
                    self.compact_once()
                except Exception:  # noqa: BLE001 - never kill the supervisor over a compaction hiccup
                    pass

        self._thread = threading.Thread(target=loop, name="ulpf-compactor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
