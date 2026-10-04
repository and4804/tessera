import json
import socket
import time

import duckdb
import httpx
import pyarrow.parquet as pq
import pytest

from ulpf.normalize.lake_schema import COLUMN_NAMES, SCHEMA, project, tail_row
from ulpf.sinks import (
    Compactor,
    JsonlSink,
    MemoryTail,
    OpenSearchSink,
    ParquetSink,
    SinkError,
    SplunkHecSink,
    SyslogOutSink,
    spool_batch,
    with_retry,
)


def ev(i, t=1790000000000, cls=4001, **kw):
    e = {"class_uid": cls, "category_uid": 4, "activity_id": 6, "type_uid": cls * 100 + 6, "time": t + i, "severity_id": 1,
         "src_endpoint": {"ip": "10.0.0.1", "port": 1000 + i}, "dst_endpoint": {"ip": "8.8.8.8", "port": 53},
         "connection_info": {"protocol_name": "udp", "protocol_num": 17}, "traffic": {"bytes_in": i, "bytes_out": 2 * i},
         "device": {"hostname": "fw"}, "unmapped": {"k": "v"}, "message": "m",
         "ulpf": {"event_id": f"id{i}:0", "raw_ref": f"s/0/{i}", "raw_sha256": "ab", "recv_time": t, "source_id": "x.y",
                  "status": "parsed", "coverage": 0.5}}
    e.update(kw)
    return e


def test_project_matches_schema_and_handles_junk():
    r = project(ev(1))
    assert len(r) == len(COLUMN_NAMES) == len(SCHEMA)
    bad = ev(2)
    bad["src_endpoint"]["port"] = "x"
    bad["dst_endpoint"]["ip"] = "\udcff\udcfe"                      # surrogate-escaped invalid UTF-8 must not break the row
    pq_rows = ParquetSink.__new__(ParquetSink)  # noqa: F841
    from ulpf.normalize.lake_schema import rows_to_table

    t = rows_to_table([project(bad), project(ev(3))])
    assert t.num_rows == 2 and t.column("src_port").to_pylist() == [None, 1003]
    row = tail_row(ev(1), "hello")
    assert row["message"] == "hello" and "event" not in row and row["coverage"] == 0.5 and row["time"] == 1790000000001


def test_parquet_layout_flush_rules_and_roundtrip(tmp_path):
    s = ParquetSink(tmp_path, "7", flush_rows=5, flush_secs=100)
    s.write([ev(i) for i in range(3)])
    assert not s.due() and s.buffered == 3 and not list(tmp_path.rglob("*.parquet"))
    s.write([ev(i, cls=4002) for i in range(3, 6)])
    assert s.due()
    s.flush()
    files = sorted(tmp_path.rglob("*.parquet"))
    assert len(files) == 2 and not list(tmp_path.rglob("*.tmp"))
    assert any("class_uid=4002" in str(f) for f in files) and all("/dt=2026-" in str(f) and "/hour=" in str(f) for f in files)
    assert files[0].name.startswith("w7-")
    t = pq.read_table(files[0])
    assert t.schema.equals(SCHEMA)
    assert json.loads(t.column("event")[0].as_py())["ulpf"]["event_id"].startswith("id")
    n = duckdb.sql(f"select count(*) from read_parquet('{tmp_path}/**/*.parquet')").fetchone()[0]
    assert n == 6
    s2 = ParquetSink(tmp_path, "7", flush_rows=100, flush_secs=0.01)
    s2.write([ev(9)])
    time.sleep(0.03)
    assert s2.due()
    s2.close()


def test_parquet_flush_failure_keeps_rows(tmp_path, monkeypatch):
    s = ParquetSink(tmp_path, "0")
    s.write([ev(i) for i in range(4)])
    monkeypatch.setattr(pq, "write_table", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        s.flush()
    assert s.buffered == 4
    monkeypatch.undo()
    s.flush()
    assert s.rows_written == 4


def test_compactor_merges_and_dedups(tmp_path):
    s = ParquetSink(tmp_path, "0", flush_rows=10**9)
    for _ in range(3):                                   # the same 5 events delivered 3 times (at-least-once redelivery)
        s.write([ev(i) for i in range(5)])
        s.flush()
    s.write([ev(100)])
    s.flush()
    assert len(list(tmp_path.rglob("*.parquet"))) == 4
    c = Compactor(tmp_path, min_files=4, settle_s=0)
    assert c.compact_once() == 4
    files = list(tmp_path.rglob("*.parquet"))
    assert len(files) == 1 and files[0].name.startswith("c-")
    ids = [r[0] for r in duckdb.sql(f"select event_id from read_parquet('{files[0]}')").fetchall()]
    assert len(ids) == len(set(ids)) == 6 and c.duplicates_removed == 10
    assert c.compact_once() == 0
    c.start(0.05)
    c.stop()


def test_jsonl_rotation_and_fsync(tmp_path):
    s = JsonlSink(tmp_path, "1", rotate_mb=0.0005)
    for i in range(30):
        s.write([ev(i)])
    s.close()
    files = sorted(tmp_path.glob("*.jsonl"))
    assert len(files) > 1
    docs = [json.loads(line) for f in files for line in f.read_text().splitlines()]
    assert len(docs) == 30 and {d["ulpf"]["event_id"] for d in docs} == {f"id{i}:0" for i in range(30)}
    s2 = JsonlSink(tmp_path / "x")
    s2.write([ev(1, **{"message": "\udcff"})])      # invalid utf-8 survives as an escape, not an exception
    s2.close()


def test_with_retry_and_spool(tmp_path):
    calls = []
    sleeps = []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError("boom")

    with_retry(flaky, attempts=3, sleep=sleeps.append)
    assert len(calls) == 3 and len(sleeps) == 2 and sleeps[1] > sleeps[0]
    with pytest.raises(SinkError):
        with_retry(lambda: 1 / 0, attempts=2, sleep=lambda s: None)
    p = spool_batch(tmp_path, "opensearch", [ev(1), ev(2, message="\udcff")])
    assert len(p.read_text().splitlines()) == 2 and p.parent.name == "opensearch"


def test_opensearch_bulk_and_error_handling():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, req.content.decode()))
        if req.url.path == "/_bulk" and "FAIL" in req.content.decode():
            return httpx.Response(200, json={"errors": True, "items": [{"index": {"error": {"type": "x"}}}]})
        return httpx.Response(200, json={"errors": False, "items": []})

    s = OpenSearchSink("http://os:9200", "ulpf-%Y.%m.%d", 2, client=httpx.Client(transport=httpx.MockTransport(handler)))
    s.write([ev(1)])
    assert not seen
    s.write([ev(2)])
    assert [m for m, _p, _b in seen] == ["PUT", "POST"]
    bulk = seen[1][2].splitlines()
    assert json.loads(bulk[0])["index"] == {"_index": "ulpf-2026.09.21", "_id": "id1:0"} and len(bulk) == 4
    assert s.rows_written == 2
    s.write([ev(3, message="FAIL")])
    with pytest.raises(SinkError):
        s.flush()
    assert len(s._buf) == 1          # retained for the caller's retry/spool decision
    s._buf.clear()
    s.close()


def test_splunk_hec(monkeypatch):
    got = []

    def handler(req):
        got.append((req.headers["authorization"], req.content.decode()))
        return httpx.Response(200) if len(got) > 1 else httpx.Response(503)

    s = SplunkHecSink("http://splunk/x", "tok", 2, client=httpx.Client(transport=httpx.MockTransport(handler)))
    import ulpf.sinks.splunk_hec as m

    monkeypatch.setattr(m, "with_retry", lambda fn, **k: fn())     # no real sleeping in unit tests
    s.write([ev(1)])
    with pytest.raises(httpx.HTTPStatusError):
        s.write([ev(2)])
    assert len(s._buf) == 2
    s.flush()
    assert got[-1][0] == "Splunk tok" and len(got[-1][1].splitlines()) == 2
    d = json.loads(got[-1][1].splitlines()[0])
    assert d["host"] == "fw" and d["time"] == 1790000000.001 and d["event"]["ulpf"]["event_id"] == "id1:0"
    s.close()


def test_syslog_out_udp():
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(2)
    s = SyslogOutSink("127.0.0.1", rx.getsockname()[1])
    s.write([ev(1)])
    data = rx.recv(70000).decode()
    assert data.startswith("<134>1 2026-") and "ulpf - - - {" in data
    big = s.format(ev(1, message="x" * 100_000))
    assert len(big) <= 60_000
    s.close()
    rx.close()


def test_memory_tail_bounded_and_resumable():
    t = MemoryTail(maxlen=5)
    t.write([ev(i) for i in range(8)])
    last, rows = t.read_after(0)
    assert len(rows) == 5 and rows[0]["time"] == 1790000000003 and last == t.head() == 8
    assert t.read_after(last) == (last, [])


def test_redis_tail(redis_url):
    import redis

    from ulpf.sinks import RedisTail

    r = redis.Redis.from_url(redis_url)
    t = RedisTail(r, maxlen=100, stream="tail." + str(time.time_ns()))
    t.write([ev(i) for i in range(3)], ["a", "b", "c"])
    last, rows = t.read_after("0-0")
    assert [x["message"] for x in rows] == ["a", "b", "c"] and t.head() == last
    assert t.read_after(last)[1] == []
