"""Bus contract (§6.3) plus the small additive extensions the pipeline needs (stale-claim, lag, atomic ledger deltas)."""
from __future__ import annotations

import zlib
from typing import Protocol

# source -> field -> increment.  Fields: ingested vaulted parsed partial unparsed sunk dropped:<reason> sink:<name>
LedgerDeltas = dict[str, dict[str, int]]


def partition_for(key: str, partitions: int) -> int:
    """I5: one source key always maps to one partition."""
    return zlib.crc32(key.encode("utf-8", "surrogateescape")) % partitions


class LedgerStore(Protocol):
    def apply(self, deltas: LedgerDeltas) -> None: ...
    def snapshot(self) -> dict[str, dict[str, int]]: ...
    def reset(self) -> None: ...


class Bus(Protocol):
    partitions: int
    ledger: LedgerStore

    def publish(self, partition: int, batch: list[bytes], ledger_deltas: LedgerDeltas | None = None) -> None:
        """Append msgpack(RawEnvelope) payloads. ``ledger_deltas`` are applied atomically with the publish."""

    def consume(self, partitions: list[int], consumer: str, max_n: int, block_ms: int) -> list[tuple[int, str, bytes]]:
        """Deliver up to ``max_n`` new messages as ``(partition, msg_id, payload)``; blocks up to ``block_ms``."""

    def ack(self, partition: int, msg_ids: list[str], ledger_deltas: LedgerDeltas | None = None) -> None:
        """Acknowledge. ``ledger_deltas`` are applied atomically with the ack (counted iff acked: redelivery cannot double count)."""

    def claim_stale(self, partitions: list[int], consumer: str, min_idle_ms: int, max_n: int) -> list[tuple[int, str, bytes]]:
        """Take over delivered-but-unacked messages idle for >= ``min_idle_ms`` (0 = everything pending). At-least-once recovery."""

    def lag(self, partition: int) -> int:
        """Messages published but not yet acked (queued + pending)."""

    def close(self) -> None: ...
