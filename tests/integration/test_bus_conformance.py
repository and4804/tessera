import threading
import time

from ulpf.bus import partition_for


def test_publish_consume_ack_roundtrip(bus):
    bus.publish(1, [b"a", b"b", b"c"])
    got = bus.consume([1], "w1", 10, 200)
    assert [g[2] for g in got] == [b"a", b"b", b"c"] and all(g[0] == 1 for g in got)
    assert bus.lag(1) == 3
    bus.ack(1, [g[1] for g in got])
    assert bus.lag(1) == 0
    assert bus.consume([1], "w1", 10, 0) == []


def test_order_preserved_within_partition(bus):
    payloads = [str(i).encode() for i in range(500)]
    bus.publish(2, payloads)
    got = []
    while len(got) < 500:
        got += bus.consume([2], "w1", 128, 100)
    assert [g[2] for g in got] == payloads


def test_max_n_and_multi_partition(bus):
    bus.publish(0, [b"x"] * 5)
    bus.publish(3, [b"y"] * 5)
    got = bus.consume([0, 3], "w", 4, 100)
    assert len(got) == 4
    rest = bus.consume([0, 3], "w", 100, 100)
    assert len(got) + len(rest) == 10


def test_consumer_group_delivers_each_message_once(bus):
    bus.publish(0, [str(i).encode() for i in range(100)])
    a = bus.consume([0], "A", 60, 100)
    b = bus.consume([0], "B", 60, 100)
    assert len(a) + len(b) == 100
    assert {x[2] for x in a}.isdisjoint({x[2] for x in b})


def test_block_ms_waits_for_publish(bus):
    t = threading.Timer(0.15, lambda: bus.publish(0, [b"late"]))
    t.start()
    t0 = time.time()
    got = bus.consume([0], "w", 5, 2000)
    t.join()
    assert [g[2] for g in got] == [b"late"] and 0.1 < time.time() - t0 < 1.5


def test_redelivery_after_worker_death_loses_nothing(bus):
    payloads = [str(i).encode() for i in range(50)]
    bus.publish(0, payloads)
    delivered = bus.consume([0], "dead-worker", 30, 100)
    bus.ack(0, [m[1] for m in delivered[:10]])  # 10 acked, 20 in flight when it "dies"
    # a young pending entry is NOT stolen while its owner may still be working on it
    assert bus.claim_stale([0], "w2", 60_000, 100) == []
    claimed = bus.claim_stale([0], "w2", 0, 100)
    assert [c[2] for c in claimed] == payloads[10:30]
    fresh = bus.consume([0], "w2", 100, 100)
    assert [f[2] for f in fresh] == payloads[30:]
    bus.ack(0, [m[1] for m in claimed + fresh])
    assert bus.lag(0) == 0
    seen = {d[2] for d in delivered[:10]} | {c[2] for c in claimed} | {f[2] for f in fresh}
    assert seen == set(payloads)


def test_ledger_deltas_atomic_with_publish_and_ack(bus):
    bus.publish(0, [b"a", b"b"], {"srcA": {"ingested": 2}})
    got = bus.consume([0], "w", 10, 100)
    d = {"srcA": {"vaulted": 2, "sunk": 2, "parsed": 1, "unparsed": 1}}
    bus.ack(0, [g[1] for g in got], d)
    snap = bus.ledger.snapshot()
    assert snap["srcA"] == {"ingested": 2, "vaulted": 2, "sunk": 2, "parsed": 1, "unparsed": 1}
    # an un-acked batch contributes nothing (counted iff acked) and a redelivered batch is counted exactly once
    bus.publish(0, [b"c"], {"srcA": {"ingested": 1}})
    got = bus.consume([0], "w", 10, 100)
    redo = bus.claim_stale([0], "w2", 0, 10)
    assert len(redo) == 1
    bus.ack(0, [redo[0][1]], {"srcA": {"vaulted": 1}})
    assert bus.ledger.snapshot()["srcA"]["vaulted"] == 3
    bus.ledger.reset()
    assert bus.ledger.snapshot() == {}


def test_partition_for_stable_and_in_range():
    assert partition_for("10.0.0.1", 16) == partition_for("10.0.0.1", 16)
    assert all(0 <= partition_for(f"h{i}", 7) < 7 for i in range(100))


def test_consume_budget_is_filled_from_a_single_busy_partition(bus):
    """A one-source (one-partition) backlog must still come back in max_n slices, not max_n / partitions."""
    bus.publish(2, [b"z"] * 300)
    got = bus.consume([0, 1, 2, 3], "w", 100, 100)
    assert len(got) == 100 and {p for p, _, _ in got} == {2}
    assert len(bus.consume([0, 1, 2, 3], "w", 1000, 100)) == 200
