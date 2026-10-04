"""Scale-out pieces: partition leases, lease-mode workers (rebalance, crash takeover), key bootstrap race, worker pool, bus budget."""
import threading
import time
import uuid
from pathlib import Path

import duckdb
import pytest
import redis

from tools.loggen import generator
from ulpf.bus import RedisBus
from ulpf.config import Config
from ulpf.ingest import Publisher
from ulpf.packs import PackRegistry
from ulpf.pipeline import MemoryClusterStore, Worker, backlog, make_tail, report
from ulpf.pipeline.leases import LeaseManager
from ulpf.pipeline.runtime import ensure_signing_key
from ulpf.vault import load_signing_key

PACKS = Path(__file__).resolve().parents[2] / "packs"
MIX = "fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10"


@pytest.fixture
def rclient(redis_url):
    """A private Redis database: lease keys have fixed names, so tests must not share them."""
    url = redis_url.rsplit("/", 1)[0] + "/5"
    c = redis.Redis.from_url(url)
    c.flushdb()
    yield c, url
    c.flushdb()


def test_leases_fair_share_rebalance_and_release(rclient):
    c, _ = rclient
    a, b = LeaseManager(c, 16, "a", ttl_s=5), LeaseManager(c, 16, "b", ttl_s=5)
    a.refresh(force=True)
    assert a.owned == set(range(16))                      # alone: everything
    b.refresh(force=True)                                 # b registers; a is above its share and releases on its next refresh
    assert b.owned == set()
    gained, lost = a.refresh(force=True)
    assert len(a.owned) == 8 and len(lost) == 8
    b.refresh(force=True)
    assert len(b.owned) == 8 and not (a.owned & b.owned) and a.owned | b.owned == set(range(16))
    a.release_all()
    b.refresh(force=True)
    b.refresh(force=True)
    assert b.owned == set(range(16))


def test_lease_expiry_is_crash_takeover(rclient):
    c, _ = rclient
    a, b = LeaseManager(c, 8, "a", ttl_s=1), LeaseManager(c, 8, "b", ttl_s=1)
    a.refresh(force=True)
    assert len(a.owned) == 8
    time.sleep(1.3)                                       # a "crashes": no renewal, no release
    b.refresh(force=True)
    assert b.owned == set(range(8))


def _mk(tmp_path, bus, name, url):
    cfg = Config().rebase(tmp_path)
    cfg.vault.signing_key = None
    cfg.sinks.parquet.flush_secs = 0.2
    cfg.bus.partitions = 4
    c = redis.Redis.from_url(url)
    leases = LeaseManager(c, 4, name, ttl_s=1, every_s=0.05)
    return cfg, Worker(cfg, bus, PackRegistry([PACKS]), 0, 1, tail=make_tail(bus), cluster_store=MemoryClusterStore(), name=name, leases=leases)


def _lines(n):
    return [ln.encode() for _d, ln, _r in generator.generate(mix=MIX, seed=3, count=n)]


def test_two_lease_workers_share_work_and_survive_a_crash(tmp_path, rclient):
    c, url = rclient
    bus = RedisBus(url, partitions=4, client=c, prefix="lw" + uuid.uuid4().hex[:6])
    cfg, w1 = _mk(tmp_path / "n", bus, "w1", url)
    _, w2 = _mk(tmp_path / "n", bus, "w2", url)
    data = _lines(4000)
    pub = Publisher(bus, "n1")
    for i, d in enumerate(data):
        pub.ingest(d, "udp", f"10.0.{i % 4}.{(i // 4) % 12}", 514)
    pub.flush()
    for _ in range(6):                                    # both register, split the partitions, start consuming
        w1.step(10)
        w2.step(10)
    assert w1.leases.owned and w2.leases.owned and not (w1.leases.owned & w2.leases.owned)
    assert w1.processed > 0 and w2.processed > 0
    w1.vault.close()                                      # w1 "crashes": no commit, no lease release; un-acked messages stay pending
    t0 = time.time()
    while time.time() - t0 < 30 and (backlog(bus) > 0 or _sunk(bus) < len(data)):
        w2.step(20)
    w2.commit()
    w2.close()
    led = report(bus.ledger.snapshot(), backlog(bus), 0)
    assert led["totals"]["ingested"] == len(data) and led["lost"] == 0
    ids = duckdb.sql(f"SELECT count(*), count(DISTINCT event_id) FROM read_parquet('{cfg.lake_dir}/**/*.parquet')").fetchone()
    assert ids is not None and ids[1] == len(data)        # at-least-once: duplicates are possible, loss is not; they collapse by event_id


def _sunk(bus):
    return sum(r.get("sunk", 0) + r.get("dropped", 0) for r in bus.ledger.snapshot().values())


def test_ensure_signing_key_race_yields_one_key(tmp_path):
    cfgs = []
    for _ in range(8):
        c = Config().rebase(tmp_path)
        c.vault.signing_key = "/nonexistent/secret"
        cfgs.append(c)
    out: list[str | None] = []
    barrier = threading.Barrier(8)

    def go(c):
        barrier.wait()
        out.append(ensure_signing_key(c))

    ts = [threading.Thread(target=go, args=(c,)) for c in cfgs]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(set(out)) == 1 and out[0] is not None
    sk = load_signing_key(out[0])
    assert sk is not None
    assert Path(out[0] + ".pub").read_text().strip() == bytes(sk.verify_key).hex()
    assert not [p for p in Path(out[0]).parent.iterdir() if p.name.startswith(".gen-")]
    assert ensure_signing_key(cfgs[0]) == out[0]          # idempotent


def test_ensure_signing_key_keeps_a_configured_secret(tmp_path):
    from ulpf.vault import generate_keypair

    k, _ = generate_keypair(tmp_path / "secret")
    c = Config().rebase(tmp_path)
    c.vault.signing_key = str(k)
    assert ensure_signing_key(c) == str(k) and not (tmp_path / "keys").exists()
    c.vault.signing_key = None
    assert ensure_signing_key(c) is None


def test_replay_with_worker_processes(tmp_path, rclient):
    from ulpf.cli import run_replay
    from ulpf.vault import verify_all

    _, url = rclient
    f = tmp_path / "in.log"
    f.write_bytes(b"\n".join(_lines(1500)) + b"\n")
    cfg = Config().rebase(tmp_path / "d")
    cfg.bus.kind, cfg.bus.url, cfg.bus.partitions = "redis", url, 4
    cfg.packs.dirs = [str(PACKS)]
    cfg.vault.signing_key = None
    cfg.sinks.jsonl.enabled = False
    res = run_replay(cfg, f, None, None, None, workers=2)
    led = res["ledger"]
    assert res["lines"] == 1500 and led["conserved"] and led["totals"]["sunk"] == 1500 and led["totals"]["normalized_parsed"] >= 1400
    assert all(r.ok for r in verify_all(cfg.vault.dir))
    n = duckdb.sql(f"SELECT count(DISTINCT event_id) FROM read_parquet('{cfg.lake_dir}/**/*.parquet')").fetchone()
    assert n == (1500,)


def test_tail_rate_cap_samples_but_never_blocks():
    from ulpf.sinks import MemoryTail
    from ulpf.sinks.tail import RateCap

    cap = RateCap(100)
    assert cap.take(60) == 60 and cap.take(60) == 40 and cap.skipped == 20
    assert RateCap(0).take(10**6) == 10**6
    t = MemoryTail(max_eps=10)
    evs = [{"time": i, "class_uid": 4001, "ulpf": {"event_id": str(i)}} for i in range(1000)]
    t.write(evs)
    assert 0 < len(t.q) <= 10 and t.cap.skipped >= 990
    rows = [r["event_id"] for _, r in t.q]
    assert rows == sorted(rows, key=int)                  # the sample keeps arrival order
