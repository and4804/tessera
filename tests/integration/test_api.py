"""API contract tests (docs/api-contract.md) against a real pipeline run: vault + lake + ledger produced by the Worker."""
import base64
import csv
import io
import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tools.loggen import generator
from ulpf.api.app import create_app
from ulpf.bus import MemoryBus
from ulpf.config import Config
from ulpf.ingest import Publisher
from ulpf.packs import PackRegistry
from ulpf.pipeline import MemoryClusterStore, Worker
from ulpf.sinks import MemoryTail

PACKS = Path(__file__).resolve().parents[2] / "packs"
MIX = "fortigate:25,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5"
N = 3000


class Node:
    pass


def build_node(tmp: Path, token: str | None = None) -> Node:
    n = Node()
    cfg = Config().rebase(tmp)
    cfg.vault.signing_key = None
    cfg.sinks.parquet.flush_secs = 0.1
    cfg.bus.partitions = 4
    cfg.api.token = token
    custom = tmp / "packs" / "custom"
    custom.mkdir(parents=True)
    cfg.packs.dirs = [str(PACKS), str(custom)]
    n.cfg, n.tmp = cfg, tmp
    n.bus = MemoryBus(4)
    n.reg = PackRegistry(cfg.packs.dirs)
    n.clusters = MemoryClusterStore()
    n.tail = MemoryTail()
    fresh_worker(n)
    n.pub = Publisher(n.bus, cfg.node_id)
    return n


def fresh_worker(n: Node) -> None:
    n.worker = Worker(n.cfg, n.bus, n.reg, 0, 1, tail=n.tail, cluster_store=n.clusters, shard=False)


def feed(n: Node, lines: list[bytes], peer: str = "10.9.9.9", hint: str | None = None) -> None:
    for ln in lines:
        n.pub.ingest(ln, "udp", peer, 514, hint)
    n.pub.flush()
    n.worker.drain()


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    n = build_node(tmp_path_factory.mktemp("api"))
    data = [ln.encode() for _d, ln, _r in generator.generate(mix=MIX, seed=4, count=N)]
    junk = [b"unknown device chatter 10.1.1.1 id 77", b"unknown device chatter 10.1.1.2 id 78", b"\xff\xfebinary"]
    feed(n, data + junk)
    n.total = len(data) + len(junk)
    n.worker.close()          # seal the segment, flush the lake
    fresh_worker(n)           # a closed worker is finished; later tests that feed more data get a new one (new segment)
    n.app = create_app(n.cfg, bus=n.bus, registry=n.reg, tail=n.tail, clusters=n.clusters)
    n.client = TestClient(n.app)
    return n


def api(node, path, **kw):
    return node.client.get("/api/v1" + path, **kw)


def all_pages(node, **params):
    items, cur = [], None
    for _ in range(200):
        p = {"limit": 500, **params, **({"cursor": cur} if cur else {})}
        r = api(node, "/events", params=p)
        assert r.status_code == 200, r.text
        j = r.json()
        items += j["items"]
        cur = j["next_cursor"]
        if not cur:
            return items
    raise AssertionError("pagination did not terminate")


def test_health_and_headers(node):
    r = api(node, "/health")
    j = r.json()
    assert r.status_code == 200 and j["status"] == "ok" and j["node_id"] == "n1" and j["ocsf_version"] == "1.3.0"
    assert "x-ulpf-mock" not in r.headers


def test_events_pagination_conservation_and_shape(node):
    items = all_pages(node)
    assert len(items) == node.total and len({i["event_id"] for i in items}) == node.total
    times = [i["time"] for i in items]
    assert times == sorted(times, reverse=True)
    e = items[0]
    assert set(e) == {"event_id", "raw_ref", "time", "recv_time", "class_uid", "activity_id", "severity_id", "action_id", "status",
                      "source_id", "src_ip", "src_port", "dst_ip", "dst_port", "proto_name", "bytes_in", "bytes_out", "user_name", "url",
                      "dns_query", "signature", "device_host", "coverage"}
    assert isinstance(e["time"], int) and 0 <= e["coverage"] <= 1
    r = api(node, "/events", params={"limit": 7}).json()
    assert len(r["items"]) == 7 and r["next_cursor"] and r["took_ms"] >= 0


def test_filters_and_dsl(node):
    allv = all_pages(node)
    deny = all_pages(node, q="action:denied")
    assert deny and all(x["action_id"] == 2 for x in deny) and len(deny) == sum(1 for x in allv if x["action_id"] == 2)
    src = next(x["src_ip"] for x in allv if x["src_ip"])
    mine = all_pages(node, q=f"src_ip:{src}")
    assert mine and all(x["src_ip"] == src for x in mine)
    assert len(all_pages(node, q=f"-src_ip:{src}")) == len(allv) - len(mine)
    assert {x["status"] for x in all_pages(node, status="unparsed")} == {"unparsed"}
    assert all(x["class_uid"] == 4002 for x in all_pages(node, **{"class": 4002}))
    assert all(x["source_id"] == "cisco.asa" for x in all_pages(node, source="cisco.asa"))
    ports = all_pages(node, q="dst_port:22,443")
    assert ports and {x["dst_port"] for x in ports} <= {22, 443}
    rng = all_pages(node, q="dst_port:1000..2000")
    assert all(1000 <= x["dst_port"] <= 2000 for x in rng)
    big = all_pages(node, q="bytes_out:>=1000")
    assert all(x["bytes_out"] >= 1000 for x in big)
    ten = all_pages(node, q="src_ip:10.0.0.0/8")
    assert ten and all(x["src_ip"].startswith("10.") for x in ten)
    star = all_pages(node, q="src_ip:10.1.*")
    assert all(x["src_ip"].startswith("10.1.") for x in star)
    assert all_pages(node, q='"unknown device chatter"') and len(all_pages(node, q='"unknown device chatter"')) == 2
    t_mid = allv[len(allv) // 2]["time"]
    after = all_pages(node, **{"from": t_mid})
    assert after and all(x["time"] >= t_mid for x in after)
    assert all(x["time"] <= t_mid for x in all_pages(node, to=t_mid))
    assert all(x["source_id"].startswith("fortinet") for x in all_pages(node, q="source_id:fortinet.*"))
    assert all_pages(node, q="status:parsed device_host:* -action:denied")


@pytest.mark.parametrize("q", ["nope:1", "src_ip:notanip", "dst_port:abc", "action:maybe", "status:weird", "src_ip:>5", 'url:"unterminated',
                               "dst_port:", "src_ip:1.2.3.4/99", "x" * 2500])
def test_bad_queries_are_400_bad_query(node, q):
    r = api(node, "/events", params={"q": q})
    assert r.status_code == 400 and r.json()["error"]["code"] == "BAD_QUERY" and r.json()["error"]["message"]


def test_sql_injection_attempts_are_inert(node):
    before = len(all_pages(node))
    for q in ["url:\"' OR 1=1 --\"", "url:*'; DROP TABLE lake; --", "\"%' OR '1'='1\"", "device_host:\"a'); COPY x TO '/tmp/pwn'; --\"",
              "signature:\\\"", "src_ip:\"1.1.1.1' OR 1=1\""]:
        r = api(node, "/events", params={"q": q})
        assert r.status_code in (200, 400), (q, r.text)
        if r.status_code == 200:
            assert len(r.json()["items"]) <= 5 or "OR" not in q
    assert len(all_pages(node)) == before
    assert api(node, "/events", params={"cursor": "garbage"}).status_code == 400
    assert api(node, "/events", params={"limit": 501}).status_code == 400


def test_event_doc_raw_and_lineage(node):
    ev = next(x for x in all_pages(node, status="parsed"))
    d = api(node, f"/events/{ev['event_id']}").json()
    assert d["ulpf"]["event_id"] == ev["event_id"] and d["unmapped"] is not None and d["ulpf"]["raw_ref"] == ev["raw_ref"]
    raw = api(node, f"/events/{ev['event_id']}/raw").json()
    data = base64.b64decode(raw["data_b64"])
    assert raw["verified"] is True and raw["error"] is None and raw["size"] == len(data)
    import hashlib

    assert hashlib.sha256(data).hexdigest() == raw["sha256_actual"] == raw["sha256_expected"] == d["ulpf"]["raw_sha256"]
    assert api(node, "/events/nope:0").status_code == 404
    assert api(node, "/events/nope:0").json()["error"]["code"] == "NOT_FOUND"


def test_explain_spans_slice_to_values(node):
    done = 0
    for src in ("fortinet.fortigate", "cisco.asa", "pfsense.filterlog", "cef.generic_firewall", "squid.access", "zeek.conn", "leef.generic"):
        ev = next(iter(all_pages(node, source=src)), None)
        if ev is None:
            continue
        ex = api(node, f"/events/{ev['event_id']}/explain").json()
        raw = base64.b64decode(api(node, f"/events/{ev['event_id']}/raw").json()["data_b64"])
        assert ex["pack_id"] == src and ex["raw_len"] == len(raw) and ex["fields"]
        for u in ex["unmapped"]:
            for sp in u["spans"]:
                assert 0 <= sp["start"] < sp["end"] <= len(raw)
                if ex["spans_exact"] and "\\" not in str(u["value"]):
                    assert raw[sp["start"]:sp["end"]].decode("utf-8", "replace") == str(u["value"])
        done += 1
    assert done >= 6
    un = next(iter(all_pages(node, status="unparsed")))
    r = api(node, f"/events/{un['event_id']}/explain")
    assert r.status_code == 404 and r.json()["error"]["code"] == "NO_PACK"


def test_histogram_fields_values(node):
    h = api(node, "/events/histogram", params={"buckets": 30}).json()
    assert h["buckets"] and h["interval_ms"] > 0
    ts = [b["t"] for b in h["buckets"]]
    assert all(b - a == h["interval_ms"] for a, b in zip(ts, ts[1:]))
    assert sum(b["parsed"] + b["partial"] + b["unparsed"] for b in h["buckets"]) == node.total
    f = api(node, "/events/fields").json()["fields"]
    assert {"src_ip", "action", "status"} <= {x["name"] for x in f}
    v = api(node, "/events/values", params={"field": "source_id", "prefix": "fort"}).json()["values"]
    assert v == ["fortinet.fortigate"]
    assert api(node, "/events/values", params={"field": "event_id"}).status_code == 400


def test_sources_and_health(node):
    items = api(node, "/sources").json()["items"]
    by = {i["source_id"]: i for i in items}
    fg = by["fortinet.fortigate"]
    assert fg["vendor"] == "Fortinet" and fg["total_events"] > 100 and sum(fg["status_counts"].values()) == fg["total_events"]
    assert len(fg["eps_series"]) >= 2 and 0 <= fg["parse_rate"] <= 1 and fg["last_seen"] and isinstance(fg["drift"]["reasons"], list)
    assert fg["top_unmapped"] and by["unknown"]["status_counts"]["unparsed"] == 3 and by["unknown"]["total_events"] == 3
    assert fg["pack_version"] == "1.0.0" and fg["verified"] is False
    h = api(node, "/sources/fortinet.fortigate/health").json()
    assert len(h["coverage_series"]) >= 2 and h["unmapped_all"] and h["peers"][0]["ip"] == "10.9.9.9"
    assert api(node, "/sources/zzz/health").status_code == 404


def test_ledger_and_segments_and_verify(node):
    j = api(node, "/ledger").json()
    t = j["totals"]
    assert j["conserved"] is True and t["ingested"] == t["vaulted"] == t["sunk"] == node.total and t["dropped"] == 0
    assert t["normalized_parsed"] + t["normalized_partial"] + t["unparsed"] == node.total and j["sunk_by_sink"]["parquet"] == node.total
    for row in j["per_source"]:
        assert row["ingested"] == row["sunk"] + row["dropped"] + row["in_flight"]
    segs = api(node, "/vault/segments").json()["items"]
    assert segs and segs[0]["n_events"] == node.total and segs[0]["chain_status"] == "unverified" and segs[0]["sealed_ms"]
    r = node.client.post("/api/v1/vault/verify", json={"all": True})
    lines = [json.loads(x) for x in r.text.splitlines()]
    assert lines[-1]["type"] == "done" and lines[-1]["ok"] is True and lines[-1]["frames_checked"] == node.total
    assert any(x["type"] == "segment_result" and x["ok"] for x in lines) and any(x["type"] == "progress" for x in lines)
    assert api(node, "/vault/segments").json()["items"][0]["chain_status"] == "ok"
    assert node.client.post("/api/v1/vault/verify", json={}).status_code == 400
    one = node.client.post("/api/v1/vault/verify", json={"segment": segs[0]["segment"]})
    assert json.loads(one.text.splitlines()[-1])["ok"] is True


def test_export_formats(node):
    r = api(node, "/export/csv", params={"q": "status:unparsed"})
    assert r.headers["content-disposition"].startswith("attachment") and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][0] == "event_id" and len(rows) == 4
    j = api(node, "/export/json", params={"status": "unparsed"}).json()
    assert len(j) == 3
    a = api(node, "/export/arrow", params={"source": "cisco.asa"})
    import pyarrow as pa

    tbl = pa.ipc.open_stream(a.content).read_all()
    assert tbl.num_rows == len(all_pages(node, source="cisco.asa"))
    assert api(node, "/export/xml").status_code == 404


def test_onboarding_flow_and_hot_reload(node):
    from tools.loggen import heldout

    lines = [ln for ln, _r in heldout.mikrotik(seed=3, n=80)]
    before = len(all_pages(node, status="unparsed"))
    feed(node, [x.encode() for x in lines[:40]], peer="10.77.0.1")
    node.worker.commit()
    node.worker.lane.maybe_publish(force=True)
    cl = api(node, "/onboard/clusters").json()["items"]
    assert cl and sum(c["count"] for c in cl) >= 40 and cl[0]["samples"] and 0 < cl[0]["share"] <= 1
    r = node.client.post("/api/v1/onboard/analyze", json={"samples": lines, "vendor": "MikroTik", "product": "RouterOS"})
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["draft_pack_yaml"] and a["coverage"]["lines_matched_pct"] > 0.8 and a["fields"] and a["class_uid"] == 4001
    p = node.client.post("/api/v1/onboard/preview", json={"pack_yaml": a["draft_pack_yaml"], "samples": lines}).json()
    assert p["ok"] is True and p["tests"]["failed"] == 0 and p["coverage"]["lines_matched_pct"] > 0.8
    assert p["rows"][0]["line_no"] == 1 and p["rows"][0]["mapped"] and p["rows"][0]["status"] in ("parsed", "partial")
    bad = node.client.post("/api/v1/onboard/preview", json={"pack_yaml": a["draft_pack_yaml"].replace("pipe: [", "pipe: [nope, ", 1) if "pipe: [" in a["draft_pack_yaml"] else "a: [", "samples": lines}).json()
    assert bad["ok"] is False and any(x["level"] == "error" for x in bad["lint"])
    pub = node.client.post("/api/v1/onboard/publish", json={"pack_yaml": a["draft_pack_yaml"]})
    assert pub.status_code == 200, pub.text
    pj = pub.json()
    assert pj["published"] and pj["reloaded"] and Path(pj["path"]).exists() and pj["pack_id"].startswith("custom.")
    feed(node, [x.encode() for x in lines[40:60]], peer="10.77.0.2")     # same worker, no restart: new events normalize
    node.worker.commit()
    node.client.get("/api/v1/health")
    node.app.state.ulpf.lake.invalidate()
    new = [x for x in all_pages(node, source=pj["pack_id"])]
    assert len(new) >= 15 and all(x["status"] in ("parsed", "partial") for x in new)
    assert len(all_pages(node, status="unparsed")) <= before + 40
    assert node.client.post("/api/v1/onboard/publish", json={"pack_yaml": "pack: 1"}).status_code == 400
    evil = a["draft_pack_yaml"].replace(pj["pack_id"], "cisco.asa", 1)
    assert node.client.post("/api/v1/onboard/publish", json={"pack_yaml": evil}).status_code == 400   # cannot overwrite a shipped pack id


def test_metrics_benchmark_and_body_limit(node, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)        # "./bench/results.json" of a real bench run must not leak in
    t = api(node, "/metrics")
    assert t.status_code == 200 and "ulpf_stream_lag" in t.text and "ulpf_packs_loaded" in t.text
    assert api(node, "/benchmark").status_code == 404
    b = Path(node.cfg.data_dir) / "bench"
    b.mkdir()
    (b / "results.json").write_text(json.dumps({"generated_at": 1, "hardware": {"cpu": "x", "cores": 1, "ram_gb": 1, "os": "l"},
                                                "config": {"duration_s": 1}, "sustained": {"eps": 1}, "scaling": [], "latency_ms": {"p50": 1, "p99": 2}}))
    assert api(node, "/benchmark").json()["sustained"]["eps"] == 1
    big = node.client.post("/api/v1/onboard/analyze", content=b"x" * (node.cfg.api.max_body_bytes + 10),
                           headers={"content-type": "application/json"})
    assert big.status_code == 413 and big.json()["error"]["code"] == "TOO_LARGE"
    assert node.client.post("/api/v1/onboard/analyze", json={"samples": "no"}).status_code == 400


def test_http_ingest_mounted(node):
    r = node.client.post("/ingest/raw", content=b"hello from http", headers={"x-ulpf-hint": "x"})
    assert r.status_code == 200 and r.json() == {"accepted": 1}
    node.worker.drain()


def test_tamper_is_pinpointed_and_isolated(node, tmp_path):
    # work on a copy of the vault so the shared fixture stays intact
    vdir = tmp_path / "vault"
    shutil.copytree(node.cfg.vault.dir, vdir)
    seg = sorted(vdir.rglob("*.ulpfseg"))[0]
    items = all_pages(node, status="parsed")
    cfg2 = node.cfg.model_copy(deep=True)
    cfg2.vault.dir = str(vdir)
    app2 = create_app(cfg2, bus=node.bus, registry=node.reg, tail=node.tail)
    c2 = TestClient(app2)
    victim = items[len(items) // 2]
    blk = int(victim["raw_ref"].split("/")[1])
    # flip one byte inside the victim's block: find its offset via the reader's index
    from ulpf.vault import VaultReader
    from ulpf.vault import format as fmt

    rd = VaultReader(vdir)
    rd.read(victim["raw_ref"])
    with open(seg, "rb") as f:
        _, first = fmt.decode_header(f.read(1 << 16))
        blocks, _ = fmt.scan_blocks(f, first, seg.stat().st_size)
    off = blocks[blk].offset + 20
    buf = bytearray(seg.read_bytes())
    buf[off] ^= 0xFF
    seg.write_bytes(bytes(buf))
    bad = c2.get(f"/api/v1/events/{victim['event_id']}/raw")
    assert bad.status_code == 200 and bad.json()["verified"] is False and bad.json()["error"]["code"] == "IntegrityError"
    other = next(x for x in items if int(x["raw_ref"].split("/")[1]) != blk)
    ok = c2.get(f"/api/v1/events/{other['event_id']}/raw").json()
    assert ok["verified"] is True
    ex = c2.get(f"/api/v1/events/{victim['event_id']}/explain")
    assert ex.status_code == 409 and ex.json()["error"]["code"] == "IntegrityError"
    r = c2.post("/api/v1/vault/verify", json={"all": True})
    last = json.loads(r.text.splitlines()[-1])
    assert last["ok"] is False and last["first_failure"]["segment"] == seg.name[:-len(".ulpfseg")] and last["first_failure"]["block"] == blk
    segs = c2.get("/api/v1/vault/segments").json()["items"]
    assert segs[0]["chain_status"] == "broken" and segs[0]["error"]["block"] == blk


def test_auth_token_and_access_token_query(tmp_path):
    n = build_node(tmp_path, token="s3cret")
    feed(n, [ln.encode() for _d, ln, _r in generator.generate(mix="fortigate:1", seed=1, count=20)])
    n.worker.close()
    c = TestClient(create_app(n.cfg, bus=n.bus, registry=n.reg, tail=n.tail))
    assert c.get("/api/v1/health").status_code == 200
    r = c.get("/api/v1/events")
    assert r.status_code == 401 and r.json()["error"]["code"] == "UNAUTHORIZED"
    assert c.get("/api/v1/events", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/v1/events", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert c.get("/api/v1/events", params={"access_token": "s3cret"}).status_code == 401     # query token only for WS and downloads
    assert c.get("/api/v1/export/csv", params={"access_token": "s3cret"}).status_code == 200
    with pytest.raises(Exception):  # noqa: B017 - starlette raises WebSocketDisconnect on the 4401 close
        with c.websocket_connect("/api/v1/stream"):
            pass
    with c.websocket_connect("/api/v1/stream?access_token=s3cret") as ws:
        assert ws.receive_json()["type"] == "hello"


def test_websocket_tail_with_filters(tmp_path):
    n = build_node(tmp_path)
    c = TestClient(create_app(n.cfg, bus=n.bus, registry=n.reg, tail=n.tail))
    with c.websocket_connect("/api/v1/stream") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello" and hello["server_time"] > 0
        ws.send_json({"op": "filter", "q": "action:denied", "sources": [], "statuses": []})
        time.sleep(0.2)
        feed(n, [ln.encode() for _d, ln, _r in generator.generate(mix="fortigate:50,asa:50", seed=2, count=400)])
        got = []
        t0 = time.time()
        while time.time() - t0 < 5 and not got:
            m = ws.receive_json()
            if m["type"] == "batch":
                got += m["events"]
        assert got and all(e["action_id"] == 2 for e in got)
        ws.send_json({"op": "filter", "q": "", "sources": ["cisco.asa"], "statuses": ["parsed"]})
        time.sleep(0.3)
        feed(n, [ln.encode() for _d, ln, _r in generator.generate(mix="fortigate:50,asa:50", seed=3, count=400)])
        rows = []
        t0 = time.time()
        while time.time() - t0 < 5 and not rows:
            m = ws.receive_json()
            if m["type"] == "batch":
                rows += m["events"]
        assert rows and {e["source_id"] for e in rows} == {"cisco.asa"} and {e["status"] for e in rows} == {"parsed"}
        ws.send_json({"op": "filter", "q": "nofield:1"})
        assert ws.receive_json()["type"] == "error"
