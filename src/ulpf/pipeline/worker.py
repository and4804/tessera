"""Pipeline worker (§3): bus -> vault (fsync) -> detect/extract/normalize -> sinks -> ack (with ledger deltas).

Group commit: sinks buffer (Parquet: 50k rows / 5 s); bus messages are acknowledged only after every enabled sink flushed, so a crash
re-delivers instead of losing. Duplicates from redelivery collapse by event_id (I3)."""
from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import msgspec

from ..bus.base import Bus
from ..config import Config
from ..detect import Detector
from ..ingest.publisher import source_key
from ..model.envelope import RawEnvelope
from ..normalize.validate import validate_event
from ..obs.metrics import Metrics
from ..packs import PackRegistry
from ..sinks import (
    JsonlSink,
    MemoryTail,
    OpenSearchSink,
    ParquetSink,
    RedisTail,
    SinkError,
    SplunkHecSink,
    SyslogOutSink,
    spool_batch,
)
from ..vault import VaultWriter, load_signing_key
from .leases import LeaseManager
from .ledger import BatchCounts
from .router import Router
from .unparsed import ClusterStore, UnparsedLane

log = logging.getLogger("ulpf.worker")
_dec = msgspec.msgpack.Decoder(RawEnvelope)


@dataclass
class _Pending:
    partition: int
    ids: list[str]
    counts: BatchCounts
    events: list[dict[str, Any]]
    recv_ns: int
    t0: float = field(default_factory=time.monotonic)


def build_sinks(cfg: Config, worker: str) -> list[Any]:
    s = cfg.sinks
    out: list[Any] = []
    if s.parquet.enabled:
        out.append(ParquetSink(s.parquet.dir, worker, s.parquet.flush_rows, s.parquet.flush_secs))
    if s.jsonl.enabled:
        out.append(JsonlSink(s.jsonl.dir, worker, s.jsonl.rotate_mb))
    if s.opensearch.enabled:
        out.append(OpenSearchSink(s.opensearch.url, s.opensearch.index, s.opensearch.bulk_size))
    if s.splunk_hec.enabled:
        out.append(SplunkHecSink(s.splunk_hec.url, s.splunk_hec.token, s.splunk_hec.batch))
    if s.syslog_out.enabled:
        out.append(SyslogOutSink(s.syslog_out.host, s.syslog_out.port))
    return out


class Worker:
    def __init__(self, cfg: Config, bus: Bus, registry: PackRegistry, worker_id: int = 0, n_workers: int = 1, *,
                 sinks: list[Any] | None = None, tail: Any = None, cluster_store: ClusterStore | None = None,
                 metrics_client: Any = None, shard: bool | None = None, leases: LeaseManager | None = None,
                 name: str | None = None) -> None:
        self.cfg, self.bus, self.registry = cfg, bus, registry
        self.id = worker_id
        self.name = name or f"w{worker_id}"
        self.consumer = f"{cfg.node_id}-{self.name}"
        self.leases = leases
        self.partitions = [] if leases else [p for p in range(bus.partitions) if p % n_workers == worker_id]
        shard_s = self.name if (n_workers > 1 if shard is None else shard) or leases else ""
        pc = cfg.pipeline
        self.vault = VaultWriter(
            cfg.vault.dir, cfg.node_id, shard=shard_s, block_events=cfg.vault.block_events, block_max_ms=cfg.vault.block_max_ms,
            segment_max_mb=cfg.vault.segment_max_mb, fsync=cfg.vault.fsync == "block", signing_key=load_signing_key(cfg.vault.signing_key),
        )
        self.sinks = sinks if sinks is not None else build_sinks(cfg, self.name)
        self.tail = tail
        self.lane = UnparsedLane(self.name, cluster_store)
        self.detector = Detector(lambda: self.registry.snapshot, use_cache=pc.source_cache)
        self.router = Router(self.detector, self.lane)
        self.metrics = Metrics(self.name)
        self.metrics_client = metrics_client
        self.pending: list[_Pending] = []
        self.stuck = False
        self.drop_unparsed = pc.drop_unparsed
        self.sample_every = max(1, pc.sample_validate)
        self._since_sample = random.randrange(self.sample_every)
        self.processed = 0
        self._recovered = False
        self._pack_poll = 0.0

    # ------------------------------------------------------------------ one batch
    def _process(self, msgs: list[tuple[int, str, bytes]]) -> None:
        m = self.metrics
        t0 = time.perf_counter()
        envs: list[tuple[int, str, RawEnvelope | None]] = []
        for p, mid, payload in msgs:
            try:
                envs.append((p, mid, _dec.decode(payload)))
            except (msgspec.DecodeError, msgspec.ValidationError):
                envs.append((p, mid, None))
        refs = [self.vault.append_envelope(e) if e is not None else None for _, _, e in envs]
        self.vault.flush()                                           # I1: raw durable before anything downstream
        t1 = time.perf_counter()
        per: dict[int, _Pending] = {}
        for (p, mid, env), ref in zip(envs, refs):
            pend = per.get(p)
            if pend is None:
                pend = per[p] = _Pending(p, [], BatchCounts(), [], 0)
            pend.ids.append(mid)
            if env is None or ref is None:      # undecodable bus payload: nothing to recover; counted, never silent
                pend.counts.add("unknown", "dropped", 1)
                pend.counts.add("unknown", "dropped:undecodable_envelope", 1)
                m.dropped["undecodable_envelope"] += 1
                continue
            src = source_key(env.hint, env.peer_ip)
            c = pend.counts
            c.add(src, "vaulted")
            evs = self.router.route(env, ref)
            st = evs[0]["ulpf"]["status"]
            c.add(src, "parsed" if st == "parsed" else "partial" if st == "partial" else "unparsed")
            m.normalized[(st, evs[0]["ulpf"]["source_id"])] += 1
            m.vaulted += 1
            if st == "unparsed" and self.drop_unparsed:
                c.add(src, "dropped")
                c.add(src, "dropped:unparsed_dropped")
                m.dropped["unparsed_dropped"] += 1
                continue
            c.add(src, "sunk")
            pend.events.extend(evs)
            if not pend.recv_ns:
                pend.recv_ns = env.recv_ns
            self._since_sample += 1
            if self._since_sample >= self.sample_every:
                self._since_sample = 0
                for v in validate_event(evs[0]):
                    m.violations[(evs[0]["ulpf"]["source_id"], v.field)] += 1
        t2 = time.perf_counter()
        for pend in per.values():
            for name in [s.name for s in self.sinks]:
                for src, row in pend.counts.d.items():
                    if row.get("sunk"):
                        pend.counts.add(src, f"sink:{name}", row["sunk"])
            for s in self.sinks:
                self._write(s, pend.events)
            if self.tail is not None and pend.events:
                try:
                    self.tail.write(pend.events)
                    cap = getattr(self.tail, "cap", None)
                    if cap is not None:
                        m.gauges["tail_skipped_total"] = float(cap.skipped)
                except Exception:  # noqa: BLE001 - the live tail is best effort
                    m.errors["tail"] += 1
            self.pending.append(pend)
        t3 = time.perf_counter()
        self.processed += len(msgs)
        if random.random() < 1 / 16:
            m.stage["vault"].observe(t1 - t0)
            m.stage["route"].observe(t2 - t1)
            m.stage["sink"].observe(t3 - t2)

    def _write(self, sink: Any, events: list[dict[str, Any]]) -> None:
        if not events:
            return
        try:
            sink.write(events)
        except Exception as e:  # noqa: BLE001
            self.metrics.errors[f"sink_write:{sink.name}"] += 1
            self.stuck = True
            log.warning("sink %s write failed: %s", sink.name, e)
            spool_batch(Path(self.cfg.data_dir) / "spool", sink.name, events)

    # ------------------------------------------------------------------ group commit
    def commit(self) -> bool:
        """Flush every sink, then ack all pending batches with their ledger deltas. False if a sink refused (nothing acked)."""
        if not self.pending:
            return True
        if self.stuck:
            return False
        for s in self.sinks:
            try:
                s.flush()
            except (SinkError, Exception) as e:  # noqa: BLE001
                self.metrics.errors[f"sink_flush:{s.name}"] += 1
                log.warning("sink %s flush failed: %s", s.name, e)
                self.stuck = True
                return False
        now = time.time_ns()
        for pend in self.pending:
            self.bus.ack(pend.partition, pend.ids, pend.counts.d)
            for row in pend.counts.d.values():
                for k, v in row.items():
                    if k.startswith("sink:"):
                        self.metrics.sunk[k[5:]] += v
            if pend.recv_ns:
                self.metrics.e2e.observe(max(0.0, (now - pend.recv_ns) / 1e9))
        self.pending.clear()
        self.lane.maybe_publish()
        return True

    def retry_stuck(self) -> None:
        """A sink refused a batch earlier: its buffer was kept (sinks re-queue on failure); try flushing again."""
        if not self.stuck:
            return
        self.stuck = False
        self.commit()

    def sinks_due(self) -> bool:
        return any(getattr(s, "due", lambda: False)() for s in self.sinks) or len(self.pending) >= 20

    # ------------------------------------------------------------------ loop
    def recover(self, partitions: list[int] | None = None) -> int:
        """Take over everything left pending by a previous incarnation (or a dead peer) on these partitions (at-least-once)."""
        n = 0
        parts = self.partitions if partitions is None else partitions
        while True:
            msgs = self.bus.claim_stale(parts, self.consumer, 0, self.cfg.pipeline.read_batch)
            if not msgs:
                break
            self._process(msgs)
            n += len(msgs)
            if not self.commit():          # ack what we took over, otherwise the same pending entries are claimed again forever
                break
        self._recovered = True
        return n

    def _manage_leases(self) -> None:
        assert self.leases is not None
        gained, lost = self.leases.refresh(before_release=lambda _ps: self.commit())
        if gained or lost:
            self.commit()
            self.partitions = sorted(self.leases.owned)
        if gained:
            self.recover(sorted(gained))

    def _poll_packs(self) -> None:
        if self.cfg.packs.hot_reload and time.monotonic() - self._pack_poll >= 1.0:
            self._pack_poll = time.monotonic()
            try:
                self.registry.poll()
            except Exception:  # noqa: BLE001 - a half-written pack file must never stop the worker; the last good version stays live
                self.metrics.errors["pack_reload"] += 1

    def step(self, block_ms: int = 100) -> int:
        if self.leases is not None:
            self._manage_leases()
            if not self.partitions:
                time.sleep(min(block_ms, 200) / 1000)
                return 0
        elif not self._recovered:
            self.recover()
        self._poll_packs()
        if self.stuck:
            self.retry_stuck()
            if self.stuck:
                time.sleep(min(block_ms, 200) / 1000)
                return 0
        msgs = self.bus.consume(self.partitions, self.consumer, self.cfg.pipeline.read_batch, block_ms)
        if msgs:
            self._process(msgs)
            if self.sinks_due():
                self.commit()
        else:
            self.vault.tick()
            self.commit()
            self.lane.maybe_publish(force=True)
        if self.metrics.due() and self.metrics_client is not None:
            try:
                self.metrics.gauges["vault_block_fill"] = float(self.vault.stats()["buffered"])
                self.metrics.publish(self.metrics_client)
            except Exception:  # noqa: BLE001
                pass
        return len(msgs)

    def drain(self, idle_rounds: int = 3) -> int:
        """Process until the bus is quiet (replay/tests)."""
        total = idle = 0
        while idle < idle_rounds:
            n = self.step(20)
            total += n
            idle = idle + 1 if n == 0 else 0
        self.commit()
        return total

    def run_forever(self, stop: Any) -> None:
        while not stop.is_set():
            self.step(100)
        self.close()

    def close(self) -> None:
        self.commit()
        self.lane.maybe_publish(force=True)
        if self.leases is not None:
            try:
                self.leases.release_all()
            except Exception:  # noqa: BLE001
                pass
        for s in self.sinks:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        self.vault.close()
        if self.metrics_client is not None:
            try:
                self.metrics.publish(self.metrics_client)
            except Exception:  # noqa: BLE001
                pass


def make_tail(bus: Any) -> Any:
    r = getattr(bus, "r", None)
    return RedisTail(r) if r is not None else MemoryTail()
