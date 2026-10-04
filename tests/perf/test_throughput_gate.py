"""Performance regression gate. Not a benchmark (see `ulpf bench` / bench/results.json for measured numbers): it fails when the in-process
pipeline slows by an order of magnitude (an accidental O(n^2), a per-event compile, a sync call on the hot path). The floor in
bench/baseline.json is deliberately far below the measured rate (7k+ eps on 2 shared vCPUs) so a noisy machine does not flake."""
import json
import time
from pathlib import Path

from tools.loggen import generator
from ulpf.bus import MemoryBus
from ulpf.config import Config
from ulpf.ingest import Publisher
from ulpf.packs import PackRegistry
from ulpf.pipeline import MemoryClusterStore, Worker, backlog, make_tail, report

ROOT = Path(__file__).resolve().parents[2]
MIX = "fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10"


def test_inprocess_pipeline_eps_floor(tmp_path):
    floor = json.loads((ROOT / "bench" / "baseline.json").read_text())["inprocess_eps_floor"]
    n = 20_000
    data = [ln.encode() for _d, ln, _r in generator.generate(mix=MIX, seed=5, count=n)]
    cfg = Config().rebase(tmp_path)
    cfg.vault.signing_key = None
    cfg.sinks.parquet.flush_secs = 5
    bus = MemoryBus(16)
    w = Worker(cfg, bus, PackRegistry([ROOT / "packs"]), 0, 1, tail=make_tail(bus), cluster_store=MemoryClusterStore(), shard=False)
    pub = Publisher(bus, cfg.node_id)
    t0 = time.perf_counter()
    for i, d in enumerate(data):
        pub.ingest(d, "udp", f"10.0.{i % 6}.{(i // 6) % 40}", 514)
    pub.flush()
    w.drain()
    w.close()
    eps = n / (time.perf_counter() - t0)
    led = report(bus.ledger.snapshot(), backlog(bus), 0)
    assert led["conserved"] and led["totals"]["sunk"] == n and led["totals"]["normalized_parsed"] >= 0.99 * n
    assert eps >= floor, f"{eps:,.0f} eps is below the regression floor {floor:,.0f}"
