"""Redis Streams bus (§7.2): stream per partition ``raw.{p}``, consumer group ``ulpf``, XREADGROUP/XACK/XAUTOCLAIM."""
from __future__ import annotations

from typing import Any

import redis

from .base import LedgerDeltas

GROUP = "ulpf"
FIELD = b"d"
LEDGER_INDEX = "ulpf:ledger:sources"


class RedisLedger:
    """Counters in Redis hashes ``ulpf:ledger:<source>`` so every process (ingest, N workers, API) shares one view."""

    def __init__(self, client: redis.Redis, prefix: str = "ulpf:ledger:") -> None:
        self.r = client
        self.prefix = prefix
        self.index = prefix + "sources"

    def add_to_pipeline(self, pipe: Any, deltas: LedgerDeltas) -> None:
        for src, fields in deltas.items():
            pipe.sadd(self.index, src)
            key = self.prefix + src
            for k, v in fields.items():
                if v:
                    pipe.hincrby(key, k, v)

    def apply(self, deltas: LedgerDeltas) -> None:
        pipe = self.r.pipeline(transaction=True)
        self.add_to_pipeline(pipe, deltas)
        pipe.execute()

    def snapshot(self) -> dict[str, dict[str, int]]:
        srcs = sorted(s.decode() for s in self.r.smembers(self.index))
        pipe = self.r.pipeline(transaction=False)
        for s in srcs:
            pipe.hgetall(self.prefix + s)
        rows = pipe.execute()
        return {s: {k.decode(): int(v) for k, v in row.items()} for s, row in zip(srcs, rows)}

    def reset(self) -> None:
        srcs = [s.decode() for s in self.r.smembers(self.index)]
        pipe = self.r.pipeline()
        for s in srcs:
            pipe.delete(self.prefix + s)
        pipe.delete(self.index)
        pipe.execute()


class RedisBus:
    def __init__(self, url: str = "redis://localhost:6379/0", partitions: int = 16, maxlen: int = 2_000_000,
                 client: redis.Redis | None = None, prefix: str = "raw") -> None:
        self.r: redis.Redis = client or redis.Redis.from_url(url)
        self.partitions = partitions
        self.maxlen = maxlen
        self.prefix = prefix
        self.ledger = RedisLedger(self.r)
        self._ensure_groups()

    def stream(self, p: int) -> str:
        return f"{self.prefix}.{p}"

    def _ensure_groups(self) -> None:
        for p in range(self.partitions):
            try:
                self.r.xgroup_create(self.stream(p), GROUP, id="0", mkstream=True)
            except redis.ResponseError as e:
                if "BUSYGROUP" not in str(e):
                    raise

    def publish(self, partition: int, batch: list[bytes], ledger_deltas: LedgerDeltas | None = None) -> None:
        pipe = self.r.pipeline(transaction=ledger_deltas is not None)
        name = self.stream(partition)
        for payload in batch:
            pipe.xadd(name, {FIELD: payload}, maxlen=self.maxlen, approximate=True)
        if ledger_deltas:
            self.ledger.add_to_pipeline(pipe, ledger_deltas)
        pipe.execute()

    def consume(self, partitions: list[int], consumer: str, max_n: int, block_ms: int) -> list[tuple[int, str, bytes]]:
        """At most ``max_n`` messages in total (extra delivered messages would be left pending). COUNT is per stream in Redis, so round 1
        splits the budget evenly; a stream that came back full is asked again with what is left of the budget. Without the follow-up a
        single busy source (one partition) would be read in max_n / partitions slices: one vault fsync per ~30 events."""
        out: list[tuple[int, str, bytes]] = []
        active = list(partitions)
        per = max(1, max_n // max(1, len(active)))
        first = True
        for _ in range(4):
            res = self.r.xreadgroup(GROUP, consumer, {self.stream(p): ">" for p in active}, count=per,
                                    block=block_ms if (first and block_ms > 0) else None)
            first = False
            full: list[int] = []
            for name, msgs in res or []:
                p = int(name.decode().rsplit(".", 1)[1])
                for mid, fields in msgs:
                    out.append((p, mid.decode(), fields[FIELD]))
                if len(msgs) >= per:
                    full.append(p)
            left = max_n - len(out)
            if left <= 0 or not full:
                break
            active, per = full, max(1, left // len(full))
        return out

    def ack(self, partition: int, msg_ids: list[str], ledger_deltas: LedgerDeltas | None = None) -> None:
        if not msg_ids and not ledger_deltas:
            return
        pipe = self.r.pipeline(transaction=True)
        if msg_ids:
            pipe.xack(self.stream(partition), GROUP, *msg_ids)
        if ledger_deltas:
            self.ledger.add_to_pipeline(pipe, ledger_deltas)
        pipe.execute()

    def claim_stale(self, partitions: list[int], consumer: str, min_idle_ms: int, max_n: int) -> list[tuple[int, str, bytes]]:
        out: list[tuple[int, str, bytes]] = []
        for p in partitions:
            start = "0-0"
            while len(out) < max_n:
                res = self.r.xautoclaim(self.stream(p), GROUP, consumer, min_idle_time=min_idle_ms, start_id=start, count=max_n - len(out))
                nxt, msgs = res[0], res[1]
                for mid, fields in msgs:
                    if fields:  # fields are empty for entries trimmed away (MAXLEN) while pending
                        out.append((p, mid.decode(), fields[FIELD]))
                if nxt in (b"0-0", "0-0"):
                    break
                start = nxt.decode() if isinstance(nxt, bytes) else nxt
        return out

    def lag(self, partition: int) -> int:
        try:
            for g in self.r.xinfo_groups(self.stream(partition)):
                if g["name"] in (GROUP, GROUP.encode()):
                    lag = g.get("lag")
                    return int(lag or 0) + int(g.get("pending", 0))
        except redis.ResponseError:
            return 0
        return 0

    def close(self) -> None:
        self.r.close()


def make_bus(kind: str, url: str, partitions: int, maxlen: int) -> Any:
    if kind == "memory":
        from .memory import MemoryBus

        return MemoryBus(partitions, maxlen)
    return RedisBus(url, partitions, maxlen)
