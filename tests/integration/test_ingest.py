import asyncio
import socket

import httpx
import pytest
from fastapi import FastAPI

from ulpf.bus import MemoryBus
from ulpf.ingest import FileTailer, Publisher, SyslogServers, replay_file
from ulpf.ingest.http import make_ingest_router
from ulpf.model.envelope import decode_envelope
from ulpf.model.ids import is_uuid7


def drain(bus):
    out = []
    for p in range(bus.partitions):
        out += [decode_envelope(m[2]) for m in bus.consume([p], "t", 100000, 0)]
    return out


def mk(max_event_bytes=65536):
    bus = MemoryBus(partitions=4)
    return bus, Publisher(bus, "n1", max_event_bytes=max_event_bytes)


async def _settle(pub, n_expected, bus, timeout=3.0):
    got = []
    for _ in range(int(timeout / 0.02)):
        got += drain(bus)
        if len(got) >= n_expected:
            break
        await asyncio.sleep(0.02)
    return got


async def test_udp_one_datagram_one_event_oversize_flagged():
    bus, pub = mk(max_event_bytes=100)
    srv = SyslogServers(pub)
    port = await srv.start_udp("127.0.0.1:0")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"<13>hello \xff\xfe", ("127.0.0.1", port))
    s.sendto(b"<13>" + b"A" * 500, ("127.0.0.1", port))
    envs = await _settle(pub, 2, bus)
    await srv.close()
    s.close()
    assert len(envs) == 2
    by_len = sorted(envs, key=lambda e: len(e.data))
    assert by_len[0].data == b"<13>hello \xff\xfe" and not by_len[0].truncated and by_len[0].transport == "udp"
    assert by_len[0].peer_ip == "127.0.0.1" and is_uuid7(by_len[0].raw_id) and by_len[0].recv_ns > 0
    assert len(by_len[1].data) == 100 and by_len[1].truncated
    assert bus.ledger.snapshot()["127.0.0.1"]["ingested"] == 2


@pytest.mark.parametrize("framing", ["newline", "octet"])
async def test_tcp_framings_with_partial_writes(framing):
    bus, pub = mk()
    srv = SyslogServers(pub)
    port = await srv.start_tcp("127.0.0.1:0")
    msgs = [b"<13>one", b"<13>two with space", b"<13>caf\xc3\xa9 \xff", b"<13>" + b"z" * 1000]
    wire = b"".join((b"%d %s" % (len(m), m)) if framing == "octet" else m + b"\n" for m in msgs)
    r, w = await asyncio.open_connection("127.0.0.1", port)
    for i in range(0, len(wire), 7):  # tiny writes force partial reads
        w.write(wire[i : i + 7])
        await w.drain()
        if i % 70 == 0:
            await asyncio.sleep(0.001)
    w.close()
    await w.wait_closed()
    envs = await _settle(pub, 4, bus)
    await srv.close()
    assert sorted(e.data for e in envs) == sorted(msgs)
    assert all(e.transport == "tcp" and e.peer_ip == "127.0.0.1" for e in envs)


async def test_tcp_connection_reuse_and_unterminated_tail():
    bus, pub = mk()
    srv = SyslogServers(pub)
    port = await srv.start_tcp("127.0.0.1:0")
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"a1\n")
    await w.drain()
    await asyncio.sleep(0.05)
    w.write(b"a2\na3")  # no final newline, then close
    await w.drain()
    w.close()
    await w.wait_closed()
    envs = await _settle(pub, 3, bus)
    await srv.close()
    assert sorted(e.data for e in envs) == [b"a1", b"a2", b"a3"]


async def test_http_single_ndjson_and_token():
    bus, pub = mk()
    app = FastAPI()
    app.include_router(make_ingest_router(pub, "/ingest/raw", token="tok"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.post("/ingest/raw", content=b"x")).status_code == 401
        h = {"Authorization": "Bearer tok"}
        r = await c.post("/ingest/raw", content=b"<13>single \xff", headers=h)
        assert r.json() == {"accepted": 1}
        r = await c.post("/ingest/raw?hint=fortinet.fortigate", content=b"l1\nl2\n\nl3\n", headers={**h, "content-type": "application/x-ndjson"})
        assert r.json() == {"accepted": 3}
    envs = drain(bus)
    assert sorted(e.data for e in envs) == [b"<13>single \xff", b"l1", b"l2", b"l3"]
    assert {e.hint for e in envs} == {None, "fortinet.fortigate"} and all(e.transport == "http" for e in envs)
    assert bus.ledger.snapshot()["fortinet.fortigate"]["ingested"] == 3


def test_file_replay_bytes_exact(tmp_path):
    f = tmp_path / "x.log"
    f.write_bytes(b"line1\r\n\xff\xfe\x00\nlast-no-newline")
    bus, pub = mk()
    assert replay_file(pub, f, hint="h") == 3
    envs = sorted(drain(bus), key=lambda e: e.raw_id)
    assert [e.data for e in envs] == [b"line1", b"\xff\xfe\x00", b"last-no-newline"]
    assert all(e.transport == "replay" and e.hint == "h" and e.peer_ip == "" for e in envs)
    assert bus.ledger.snapshot()["h"]["ingested"] == 3
    # same source key -> same partition (I5): order preserved
    assert len({e.raw_id for e in envs}) == 3


def test_file_replay_rate_limit(tmp_path):
    import time

    f = tmp_path / "x.log"
    f.write_bytes(b"a\n" * 50)
    bus, pub = mk()
    t = time.time()
    replay_file(pub, f, rate=250)
    assert time.time() - t >= 0.15


def test_file_tail_new_file_partial_lines_and_rotation(tmp_path):
    bus, pub = mk()
    t = FileTailer(pub, [(str(tmp_path / "*.log"), "fortinet.fortigate")])
    assert t.poll() == 0
    f = tmp_path / "a.log"
    f.write_bytes(b"one\ntwo\npart")
    assert t.poll() == 2
    with open(f, "ab") as fh:
        fh.write(b"ial\n")
    assert t.poll() == 1
    f.write_bytes(b"fresh\n")  # truncated/rotated
    assert t.poll() == 1
    assert [e.data for e in sorted(drain(bus), key=lambda e: e.raw_id)] == [b"one", b"two", b"partial", b"fresh"]
