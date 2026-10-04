"""DuckDB reader over the Parquet lake. One short-lived in-memory connection per call (cheap, thread-safe); files are listed from the
Hive-style layout so ``from``/``to`` prune whole ``dt=/hour=`` partitions before DuckDB opens anything.

Duplicates from at-least-once redelivery (I3) collapse by ``event_id`` at read time: listings drop adjacent repeats (rows sort by
``(time, event_id)``), counts use ``count(DISTINCT event_id)``. The compactor removes them physically."""
from __future__ import annotations

import base64
import os
import re
import threading
import time
from collections import defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import orjson

from .query_dsl import compile_query

ROW_COLS = ("event_id, raw_ref, epoch_ms(time) AS time, epoch_ms(recv_time) AS recv_time, class_uid, activity_id, severity_id, "
            "action_id, status, source_id, src_ip, src_port, dst_ip, dst_port, proto_name, bytes_in, bytes_out, user_name, url, "
            "dns_query, signature, device_host, coverage")
ROW_NAMES = ["event_id", "raw_ref", "time", "recv_time", "class_uid", "activity_id", "severity_id", "action_id", "status", "source_id",
             "src_ip", "src_port", "dst_ip", "dst_port", "proto_name", "bytes_in", "bytes_out", "user_name", "url", "dns_query",
             "signature", "device_host", "coverage"]
NICE_MS = [1000, 5000, 10_000, 30_000, 60_000, 300_000, 600_000, 1_800_000, 3_600_000, 3 * 3_600_000, 6 * 3_600_000, 12 * 3_600_000,
           86_400_000, 7 * 86_400_000]
_PART = re.compile(r"dt=(\d{4})-(\d\d)-(\d\d)[/\\]hour=(\d\d)")
EXPORT_MAX = 1_000_000


class BadCursor(ValueError):
    pass


def enc_cursor(t: int, event_id: str) -> str:
    return base64.urlsafe_b64encode(orjson.dumps([t, event_id])).decode().rstrip("=")


def dec_cursor(c: str) -> tuple[int, str]:
    try:
        t, eid = orjson.loads(base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)))
        return int(t), str(eid)
    except Exception as e:  # noqa: BLE001
        raise BadCursor("invalid cursor") from e


def _sql_list(files: list[str]) -> str:
    return "[" + ", ".join("'" + f.replace("'", "''") + "'" for f in files) + "]"


class Lake:
    def __init__(self, root: str | Path, ttl: float = 1.0) -> None:
        self.root = Path(root)
        self.ttl = ttl
        self._cache: tuple[float, list[tuple[str, int, int, float]]] | None = None   # (t, [(path, class, hour_start_ms, mtime)])
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ files
    def _scan(self) -> list[tuple[str, int, int, float]]:
        now = time.monotonic()
        with self._lock:
            if self._cache and now - self._cache[0] < self.ttl:
                return self._cache[1]
        out: list[tuple[str, int, int, float]] = []
        if self.root.is_dir():
            for cdir in os.scandir(self.root):
                if not cdir.name.startswith("class_uid=") or not cdir.is_dir():
                    continue
                try:
                    cuid = int(cdir.name.split("=", 1)[1])
                except ValueError:
                    continue
                for ddir in os.scandir(cdir.path):
                    if not ddir.name.startswith("dt="):
                        continue
                    for hdir in os.scandir(ddir.path):
                        m = _PART.search(f"{ddir.name}/{hdir.name}")
                        if not m:
                            continue
                        y, mo, d, h = map(int, m.groups())
                        start = int(datetime(y, mo, d, h, tzinfo=UTC).timestamp() * 1000)
                        for f in os.scandir(hdir.path):
                            if f.name.endswith(".parquet"):
                                try:
                                    out.append((f.path, cuid, start, f.stat().st_mtime))
                                except OSError:
                                    continue
        with self._lock:
            self._cache = (now, out)
        return out

    def invalidate(self) -> None:
        with self._lock:
            self._cache = None

    def files(self, class_uid: int | None = None, t_from: int | None = None, t_to: int | None = None) -> list[str]:
        res = []
        for path, cuid, start, _m in self._scan():
            if class_uid is not None and cuid != class_uid:
                continue
            if t_from is not None and start + 3_600_000 <= t_from:
                continue
            if t_to is not None and start > t_to:
                continue
            res.append(path)
        return sorted(res)

    def recent_files(self, n: int = 200, class_uid: int | None = None) -> list[str]:
        rows = [r for r in self._scan() if class_uid is None or r[1] == class_uid]
        rows.sort(key=lambda r: r[3], reverse=True)
        return [r[0] for r in rows[:n]]

    def has_data(self) -> bool:
        return bool(self._scan())

    # ------------------------------------------------------------------ execution
    def run(self, files: list[str], sql: str, params: list[Any] | None = None, retries: int = 2) -> list[tuple[Any, ...]]:
        """``sql`` refers to the lake as ``{lake}``; returns rows. Empty file list -> no rows."""
        if not files:
            return []
        last: Exception | None = None
        for _ in range(retries + 1):
            con = duckdb.connect(":memory:")
            try:
                con.execute("SET threads TO 2")
                q = sql.replace("{lake}", f"read_parquet({_sql_list(files)})")
                return con.execute(q, params or []).fetchall()
            except duckdb.IOException as e:     # a file vanished under us (compaction): relist and retry
                last = e
                self.invalidate()
                files = [f for f in files if os.path.exists(f)]
                if not files:
                    return []
            finally:
                con.close()
        raise RuntimeError(f"lake query failed: {last}")

    def arrow(self, files: list[str], sql: str, params: list[Any] | None = None) -> Any:
        con = duckdb.connect(":memory:")
        try:
            return con.execute(sql.replace("{lake}", f"read_parquet({_sql_list(files)})"), params or []).fetch_arrow_table()
        finally:
            con.close()

    # ------------------------------------------------------------------ filters
    @staticmethod
    def where(q: str | None = None, t_from: int | None = None, t_to: int | None = None, class_uid: int | None = None,
              source: str | None = None, status: str | None = None) -> tuple[str, list[Any]]:
        w, p = compile_query(q)
        parts = [w]
        if t_from is not None:
            parts.append("time >= to_timestamp(? / 1000.0)")
            p.append(t_from)
        if t_to is not None:
            parts.append("time <= to_timestamp(? / 1000.0)")
            p.append(t_to)
        if class_uid is not None:
            parts.append("class_uid = ?")
            p.append(class_uid)
        if source:
            parts.append("source_id = ?")
            p.append(source)
        if status:
            parts.append("status = ?")
            p.append(status)
        return " AND ".join(f"({x})" for x in parts), p

    # ------------------------------------------------------------------ queries
    def list_events(self, where: str, params: list[Any], limit: int, cursor: str | None, t_from: int | None, t_to: int | None,
                    class_uid: int | None) -> tuple[list[dict[str, Any]], str | None]:
        files = self.files(class_uid, t_from, t_to)
        w, p = where, list(params)
        if cursor:
            t, eid = dec_cursor(cursor)
            w += " AND (time < to_timestamp(? / 1000.0) OR (time = to_timestamp(? / 1000.0) AND event_id < ?))"
            p += [t, t, eid]
        rows = self.run(files, f"SELECT {ROW_COLS} FROM {{lake}} WHERE {w} ORDER BY time DESC, event_id DESC LIMIT {int(limit) + 1}", p)
        more = len(rows) > limit
        items: list[dict[str, Any]] = []
        last_id = None
        for r in rows[:limit]:
            if r[0] == last_id:
                continue
            last_id = r[0]
            items.append(row_dict(r))
        nxt = enc_cursor(items[-1]["time"], items[-1]["event_id"]) if (more and items) else None
        return items, nxt

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        for files in (self._guess_files(event_id), self.files()):
            if not files:
                continue
            rows = self.run(files, "SELECT event FROM {lake} WHERE event_id = ? LIMIT 1", [event_id])
            if rows:
                return dict(orjson.loads(rows[0][0]))
        return None

    def _guess_files(self, event_id: str) -> list[str]:
        """UUIDv7 raw ids embed receive time: live data lives in partitions near it, so try those before a full scan."""
        try:
            ms = int(event_id.replace("-", "")[:12], 16)
        except ValueError:
            return []
        return self.files(None, ms - 3_600_000, ms + 3_600_000)

    def find_row(self, event_id: str, cols: str) -> tuple[Any, ...] | None:
        for files in (self._guess_files(event_id), self.files()):
            if files:
                rows = self.run(files, f"SELECT {cols} FROM {{lake}} WHERE event_id = ? LIMIT 1", [event_id])
                if rows:
                    return rows[0]
        return None

    def rows_by_ref(self, refs: list[str]) -> list[dict[str, Any]]:
        if not refs:
            return []
        ph = ",".join("?" for _ in refs)
        rows = self.run(self.files(), f"SELECT {ROW_COLS} FROM {{lake}} WHERE raw_ref IN ({ph}) ORDER BY time DESC", list(refs))
        seen: set[str] = set()
        out = []
        for r in rows:
            if r[0] not in seen:
                seen.add(r[0])
                out.append(row_dict(r))
        return out

    def histogram(self, where: str, params: list[Any], t_from: int | None, t_to: int | None, class_uid: int | None,
                  buckets: int) -> dict[str, Any]:
        files = self.files(class_uid, t_from, t_to)
        buckets = max(10, min(200, buckets))
        mm = self.run(files, f"SELECT min(epoch_ms(time)), max(epoch_ms(time)) FROM {{lake}} WHERE {where}", params)
        lo = t_from if t_from is not None else (mm[0][0] if mm and mm[0][0] is not None else None)
        hi = t_to if t_to is not None else (mm[0][1] if mm and mm[0][1] is not None else None)
        if lo is None or hi is None:
            now = int(time.time() * 1000)
            return {"from": now - 3_600_000, "to": now, "interval_ms": 300_000, "buckets": []}
        span = max(1, hi - lo)
        interval = next((n for n in NICE_MS if span / n <= buckets), NICE_MS[-1])
        start = lo // interval * interval
        rows = self.run(files, f"SELECT (epoch_ms(time) // {interval}) * {interval} AS t, status, count(DISTINCT event_id) FROM {{lake}} "
                               f"WHERE {where} GROUP BY 1, 2", params)
        acc: dict[int, dict[str, int]] = defaultdict(lambda: {"parsed": 0, "partial": 0, "unparsed": 0})
        for t, st, n in rows:
            if st in ("parsed", "partial", "unparsed"):
                acc[int(t)][st] += int(n)
        out = []
        t = start
        while t <= hi:
            out.append({"t": t, **acc.get(t, {"parsed": 0, "partial": 0, "unparsed": 0})})
            t += interval
        return {"from": start, "to": hi, "interval_ms": interval, "buckets": out}

    def values(self, column: str, prefix: str, limit: int) -> list[str]:
        like = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = self.run(self.files(), f"SELECT {column}, count(*) c FROM {{lake}} WHERE {column} IS NOT NULL AND lower({column}) LIKE lower(?) "
                                      f"ESCAPE '\\' GROUP BY 1 ORDER BY c DESC LIMIT {int(limit)}", [like])
        return [str(r[0]) for r in rows]

    def export_rows(self, where: str, params: list[Any], t_from: int | None, t_to: int | None, class_uid: int | None,
                    chunk: int = 5000) -> Iterator[list[dict[str, Any]]]:
        files = self.files(class_uid, t_from, t_to)
        done, last = 0, None
        while done < EXPORT_MAX:
            w, p = where, list(params)
            if last is not None:
                w += " AND (time < to_timestamp(? / 1000.0) OR (time = to_timestamp(? / 1000.0) AND event_id < ?))"
                p += [last[0], last[0], last[1]]
            rows = self.run(files, f"SELECT {ROW_COLS} FROM {{lake}} WHERE {w} ORDER BY time DESC, event_id DESC LIMIT {chunk}", p)
            if not rows:
                return
            last = (rows[-1][2], rows[-1][0])
            done += len(rows)
            yield [row_dict(r) for r in rows]
            if len(rows) < chunk:
                return


def row_dict(r: tuple[Any, ...]) -> dict[str, Any]:
    d = dict(zip(ROW_NAMES, r, strict=True))
    d["coverage"] = float(d["coverage"] or 0.0)
    return d

