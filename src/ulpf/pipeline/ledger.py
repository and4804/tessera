"""Conservation ledger (§2.1). Counters are per ingest source key (hint, else peer ip) and committed atomically with the bus ack, so
a redelivered batch is counted once. Fields: ingested vaulted parsed partial unparsed sunk dropped dropped:<reason> sink:<name>."""
from __future__ import annotations

from typing import Any

from ..bus.base import Bus, LedgerDeltas

FIELDS = ("ingested", "vaulted", "normalized_parsed", "normalized_partial", "unparsed", "sunk", "dropped")


class BatchCounts:
    def __init__(self) -> None:
        self.d: LedgerDeltas = {}

    def add(self, source: str, field: str, n: int = 1) -> None:
        row = self.d.setdefault(source, {})
        row[field] = row.get(field, 0) + n


def _row(r: dict[str, int]) -> dict[str, int]:
    out = {
        "ingested": r.get("ingested", 0), "vaulted": r.get("vaulted", 0), "normalized_parsed": r.get("parsed", 0),
        "normalized_partial": r.get("partial", 0), "unparsed": r.get("unparsed", 0), "sunk": r.get("sunk", 0),
        "dropped": r.get("dropped", 0),
    }
    out["in_flight"] = out["ingested"] - out["sunk"] - out["dropped"]
    return out


def backlog(bus: Bus) -> int:
    return sum(bus.lag(p) for p in range(bus.partitions))


def report(snapshot: dict[str, dict[str, int]], bus_backlog: int, now_ms: int) -> dict[str, Any]:
    """The `/ledger` document. ``lost`` = ingested - sunk - dropped - (queued or pending on the bus): anything non-zero is a real loss."""
    per = [{"source": s, **_row(r)} for s, r in sorted(snapshot.items())]
    tot: dict[str, int] = {k: sum(p[k] for p in per) for k in FIELDS}
    norm = tot["normalized_parsed"] + tot["normalized_partial"] + tot["unparsed"]
    lost = tot["ingested"] - tot["sunk"] - tot["dropped"] - bus_backlog
    tot["in_flight"] = bus_backlog
    reasons: dict[str, int] = {}
    sinks: dict[str, int] = {}
    for r in snapshot.values():
        for k, v in r.items():
            if k.startswith("dropped:"):
                reasons[k[8:]] = reasons.get(k[8:], 0) + v
            elif k.startswith("sink:"):
                sinks[k[5:]] = sinks.get(k[5:], 0) + v
    conserved = lost == 0 and tot["vaulted"] == norm and norm == tot["sunk"] + tot["dropped"] and tot["ingested"] == tot["vaulted"] + bus_backlog
    return {"as_of": now_ms, "totals": tot, "per_source": per, "conserved": conserved, "dropped_by_reason": reasons,
            "sunk_by_sink": sinks, "lost": lost}
