import hashlib
from pathlib import Path

import duckdb
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tools.loggen import generator
from ulpf.bus import MemoryBus, RedisBus
from ulpf.config import Config
from ulpf.ingest import Publisher
from ulpf.normalize.validate import validate_event
from ulpf.packs import PackRegistry
from ulpf.pipeline import MemoryClusterStore, Worker, backlog, make_tail, report
from ulpf.vault import VaultReader, verify_all

PACKS = Path(__file__).resolve().parents[2] / "packs"
MIX = "fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5"


def mkcfg(tmp_path, **kw) -> Config:
    c = Config().rebase(tmp_path)
    c.vault.signing_key = None
    c.sinks.jsonl.enabled = True
    c.sinks.parquet.flush_secs = 0.2
    c.pipeline.sample_validate = 1
    c.bus.partitions = 4
    for k, v in kw.items():
        setattr(c.pipeline, k, v)
    return c


def build(tmp_path, bus=None, **kw):
    cfg = mkcfg(tmp_path, **kw)
    bus = bus or MemoryBus(4)
    reg = PackRegistry([PACKS])
    store = MemoryClusterStore()
    w = Worker(cfg, bus, reg, 0, 1, tail=make_tail(bus), cluster_store=store, shard=False)
    pub = Publisher(bus, cfg.node_id)
    return cfg, bus, w, pub, store


def lines(n, seed=1):
    return [ln.encode() for _d, ln, _r in generator.generate(mix=MIX, seed=seed, count=n)]


def test_conservation_and_everything_queryable(tmp_path):
    cfg, bus, w, pub, store = build(tmp_path)
    data = lines(3000) + [b"totally unknown garbage line 10.1.1.1 port 99", b"\xff\xfe\x00bin", b"", b"{not json"]
    for i, d in enumerate(data):
        pub.ingest(d, "udp", f"10.0.0.{i % 5}", 514)
    pub.flush()
    w.drain()
    w.close()
    led = report(bus.ledger.snapshot(), backlog(bus), 0)
    t = led["totals"]
    assert t["ingested"] == t["vaulted"] == t["sunk"] == len(data)
    assert t["normalized_parsed"] + t["normalized_partial"] + t["unparsed"] == len(data)
    assert t["unparsed"] >= 3 and led["conserved"] and led["lost"] == 0 and led["sunk_by_sink"]["parquet"] == len(data)
    # lake + vault + jsonl agree
    n = duckdb.sql(f"select count(*), count(distinct event_id) from read_parquet('{tmp_path}/lake/**/*.parquet', hive_partitioning=false)").fetchone()
    assert n == (len(data), len(data))
    lines_out = sum(len(p.read_text().splitlines()) for p in (tmp_path / "out").glob("*.jsonl"))
    assert lines_out == len(data)
    assert all(r.ok and r.sealed for r in verify_all(cfg.vault.dir))
    # every event's raw_ref resolves and hashes to its raw_sha256
    rd = VaultReader(cfg.vault.dir)
    rows = duckdb.sql(f"select raw_ref, raw_sha256, status from read_parquet('{tmp_path}/lake/**/*.parquet', hive_partitioning=false)").fetchall()
    assert len(rows) == len(data)
    for ref, sha, _s in rows[:500]:
        assert hashlib.sha256(rd.read(ref)).hexdigest() == sha
    # unparsed lane produced template ids
    assert store.list() and any(c["count"] >= 1 for c in store.list())


def test_all_generated_events_validate(tmp_path):
    cfg, bus, w, pub, _ = build(tmp_path)
    for d in lines(1500, 7):
        pub.ingest(d, "udp", "10.0.0.1", 1)
    pub.flush()
    w.drain()
    w.close()
    import json

    bad = []
    for p in (tmp_path / "out").glob("*.jsonl"):
        for ln in p.read_text().splitlines():
            ev = json.loads(ln)
            v = validate_event(ev)
            if v:
                bad.append((ev["ulpf"]["source_id"], [str(x) for x in v][:2]))
    assert bad == []


def test_raw_first_vault_flushed_before_sink(tmp_path):
    cfg, bus, w, pub, _ = build(tmp_path)
    order = []
    orig_flush = w.vault.flush
    w.vault.flush = lambda: (order.append("vault_flush"), orig_flush())[1]

    class Spy:
        name = "spy"

        def write(self, evs):
            order.append("sink_write")

        def flush(self):
            pass

        def close(self):
            pass

    w.sinks.append(Spy())
    for d in lines(50):
        pub.ingest(d, "udp", "1.1.1.1", 1)
    pub.flush()
    w.drain()
    assert order.index("vault_flush") < order.index("sink_write")


def test_drop_unparsed_is_explicit_and_counted(tmp_path):
    cfg, bus, w, pub, _ = build(tmp_path, drop_unparsed=True)
    for d in [b"junk one", b"junk two"] + lines(10):
        pub.ingest(d, "udp", "1.1.1.1", 1)
    pub.flush()
    w.drain()
    led = report(bus.ledger.snapshot(), backlog(bus), 0)
    assert led["totals"]["dropped"] == 2 and led["dropped_by_reason"] == {"unparsed_dropped": 2} and led["conserved"]
    # the raw is still in the vault
    assert sum(r.n_events for r in verify_all(cfg.vault.dir)) == 12


def test_redelivery_after_worker_kill_loses_nothing(tmp_path):
    cfg, bus, w, pub, _ = build(tmp_path)
    data = lines(400)
    for d in data:
        pub.ingest(d, "udp", "2.2.2.2", 1)
    pub.flush()
    # worker 1 reads+processes a batch but dies before commit (no ack, sinks never flushed)
    msgs = bus.consume(w.partitions, w.consumer, 150, 100)
    w._process(msgs)
    w.pending.clear()
    w.vault.close(seal=False)
    cfg2 = cfg
    w2 = Worker(cfg2, bus, PackRegistry([PACKS]), 0, 1, shard=False)
    w2.drain()
    w2.close()
    led = report(bus.ledger.snapshot(), backlog(bus), 0)
    assert led["totals"]["ingested"] == led["totals"]["sunk"] == 400 and led["conserved"]    # counted once
    ids = duckdb.sql(f"select count(*), count(distinct event_id) from read_parquet('{tmp_path}/lake/**/*.parquet', hive_partitioning=false)").fetchone()
    assert ids[1] == 400   # every event present; duplicates (if any) collapse by event_id
    assert all(r.ok for r in verify_all(cfg.vault.dir))


def test_redis_bus_pipeline_and_ledger(tmp_path, redis_url):
    import uuid

    import redis

    r = redis.Redis.from_url(redis_url)
    bus = RedisBus(redis_url, 4, client=r, prefix="p" + uuid.uuid4().hex[:6])
    bus.ledger.prefix = "lp" + uuid.uuid4().hex[:6] + ":"
    bus.ledger.index = bus.ledger.prefix + "sources"
    cfg, bus, w, pub, _ = build(tmp_path, bus=bus)
    for d in lines(1000):
        pub.ingest(d, "tcp", "3.3.3.3", 1)
    pub.flush()
    w.drain()
    w.close()
    led = report(bus.ledger.snapshot(), backlog(bus), 0)
    assert led["totals"]["ingested"] == led["totals"]["sunk"] == 1000 and led["conserved"]


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(st.binary(max_size=300), min_size=1, max_size=12))
def test_arbitrary_bytes_always_terminal_state_with_raw_ref(tmp_path_factory, blobs):
    tmp = tmp_path_factory.mktemp("prop")
    cfg, bus, w, pub, _ = build(tmp)
    for b in blobs:
        pub.ingest(b, "udp", "9.9.9.9", 1)
    pub.flush()
    w.drain()
    w.close()
    led = report(bus.ledger.snapshot(), backlog(bus), 0)
    t = led["totals"]
    assert t["ingested"] == t["vaulted"] == t["sunk"] == len(blobs) and led["conserved"]
    rd = VaultReader(cfg.vault.dir)
    rows = duckdb.sql(f"select raw_ref, status from read_parquet('{tmp}/lake/**/*.parquet', hive_partitioning=false)").fetchall()
    assert len(rows) == len(blobs) and all(s in ("parsed", "partial", "unparsed") for _r, s in rows)
    assert sorted(rd.read(r) for r, _s in rows) == sorted(blobs)


def mutate(b: bytes, rnd) -> bytes:
    b = bytearray(b)
    k = rnd.randrange(4)
    if k == 0 and b:
        b[rnd.randrange(len(b))] ^= 0xFF
    elif k == 1 and b:
        del b[rnd.randrange(len(b)):]
    elif k == 2 and b:
        i = rnd.randrange(len(b))
        b[i:i] = bytes(b[i:i + 1]) * 3
    else:
        b[:0] = b"\x00"
    return bytes(b)


def test_mutated_logs_never_crash_never_vanish(tmp_path):
    import random

    rnd = random.Random(3)
    cfg, bus, w, pub, _ = build(tmp_path)
    data = [mutate(d, rnd) for d in lines(1500, 11)]
    for d in data:
        pub.ingest(d, "udp", "8.8.8.8", 1)
    pub.flush()
    w.drain()
    w.close()
    led = report(bus.ledger.snapshot(), backlog(bus), 0)
    assert led["totals"]["sunk"] == len(data) and led["conserved"]
