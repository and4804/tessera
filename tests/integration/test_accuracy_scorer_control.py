"""Negative controls for the ground-truth scorer: if corrupted events still scored 100% the 1M accuracy number would mean nothing."""
import copy
from pathlib import Path

from tools.loggen import accuracy, generator
from ulpf.bus import MemoryBus
from ulpf.config import Config
from ulpf.ingest import Publisher
from ulpf.packs import PackRegistry
from ulpf.pipeline import MemoryClusterStore, Worker, make_tail

PACKS = Path(__file__).resolve().parents[2] / "packs"
MIX = "fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5"


def _pairs(tmp_path, n=1500):
    import json

    cfg = Config().rebase(tmp_path)
    cfg.vault.signing_key = None
    cfg.sinks.jsonl.enabled = True
    cfg.bus.partitions = 4
    bus = MemoryBus(4)
    w = Worker(cfg, bus, PackRegistry([PACKS]), 0, 1, tail=make_tail(bus), cluster_store=MemoryClusterStore(), shard=False)
    pub = Publisher(bus, cfg.node_id)
    gen = list(generator.generate(mix=MIX, seed=17, count=n))
    for i, (_d, line, _r) in enumerate(gen):
        pub.ingest(line.encode(), "udp", f"10.0.0.{i % 9}", 514)
    pub.flush()
    w.drain()
    w.close()
    import hashlib

    by_sha = {}
    for p in (tmp_path / "out").glob("*.jsonl"):
        for ln in p.read_text().splitlines():
            ev = json.loads(ln)
            by_sha[ev["ulpf"]["raw_sha256"]] = ev
    return [(rec, by_sha[hashlib.sha256(line.encode()).hexdigest()]) for _d, line, rec in gen]


def test_scorer_is_perfect_on_real_output_and_drops_on_every_kind_of_corruption(tmp_path):
    pairs = _pairs(tmp_path)
    base = accuracy.score(pairs)
    assert base["ALL"]["precision"] == base["ALL"]["recall"] == 1.0

    def corrupt(fn):
        out = []
        for i, (rec, ev) in enumerate(pairs):
            ev = copy.deepcopy(ev)
            if i % 10 == 0:
                fn(ev)
            out.append((rec, ev))
        return accuracy.score(out)["ALL"]

    def wrong_value(ev):
        ev["src_endpoint"] = {**ev.get("src_endpoint", {}), "ip": "198.51.100.200"}

    def missing_field(ev):
        ev.pop("src_endpoint", None)
        ev.pop("dst_endpoint", None)

    def extra_field(ev):
        ev["bogus"] = {"a": 1, "b": 2, "c": 3}

    w, m, e = corrupt(wrong_value), corrupt(missing_field), corrupt(extra_field)
    assert w["precision"] < 0.995 and w["recall"] < 0.995     # a wrong value costs both
    assert m["recall"] < 0.99                                   # missing fields cost recall
    assert e["precision"] < 0.99 and e["recall"] == 1.0         # extra fields cost precision only
