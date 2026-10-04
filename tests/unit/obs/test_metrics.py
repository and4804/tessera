from ulpf.obs.metrics import METRICS_KEY, LocalHistogram, Metrics, read_snapshots, render


class FakeRedis:
    def __init__(self):
        self.h = {}

    def hset(self, key, field, value):
        self.h.setdefault(key, {})[field.encode()] = value.encode()

    def hgetall(self, key):
        return self.h.get(key, {})


def test_histogram_buckets():
    h = LocalHistogram((1.0, 2.0))
    for v in (0.5, 1.0, 1.5, 9):
        h.observe(v)
    assert h.data()["c"] == [2, 1, 1] and h.n == 4 and h.sum == 12.0


def test_publish_and_render_roundtrip():
    r = FakeRedis()
    a, b = Metrics("w0"), Metrics("w1")
    for m, n in ((a, 5), (b, 7)):
        m.vaulted += n
        m.normalized[("parsed", "fortinet.fortigate")] += n
        m.sunk["parquet"] += n
        m.dropped["unparsed_dropped"] += 1
        m.violations[("p", "time")] += 1
        m.errors["tail"] += 1
        m.e2e.observe(0.2)
        m.publish(r)
    snaps = list(read_snapshots(r))
    assert len(snaps) == 2 and METRICS_KEY in r.h
    text = render(lambda: snaps, lambda: [("ulpf_stream_lag", "lag", {"partition": "0"}, 3)]).decode()
    assert 'ulpf_vaulted_total{worker="w0"} 5.0' in text
    assert 'ulpf_normalized_total{source="fortinet.fortigate",status="parsed",worker="w1"} 7.0' in text
    assert 'ulpf_dropped_total{reason="unparsed_dropped",worker="w0"} 1.0' in text
    assert "ulpf_e2e_latency_seconds_bucket" in text and 'ulpf_stream_lag{partition="0"} 3.0' in text
    assert "ulpf_worker_rss_bytes" in text


def test_read_snapshots_skips_garbage():
    r = FakeRedis()
    r.h[METRICS_KEY] = {b"a": b"not json", b"b": b'{"worker": "x"}'}
    assert [s["worker"] for s in read_snapshots(r)] == ["x"]
    assert Metrics().due(0.0) and not Metrics().due(1e9)
