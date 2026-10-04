"""In-process pipeline throughput (memory bus, one worker, vault + Parquet + tail, no Redis): the quantity the perf regression gate checks.

  python -m tools.bench.inprocess --record      # measure 3x on this machine and write the median into bench/baseline.json
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIX = "fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10"


def measure(tmp: Path, n: int = 20_000, seed: int = 5) -> tuple[float, dict]:
    """Returns (events per CPU-second, ledger report). CPU time (process_time), not wall time: the gate must not flake when another process
    shares the core, and one in-process worker is CPU-bound so the two agree on an idle machine."""
    from tools.loggen import generator
    from ulpf.bus import MemoryBus
    from ulpf.config import Config
    from ulpf.ingest import Publisher
    from ulpf.packs import PackRegistry
    from ulpf.pipeline import MemoryClusterStore, Worker, backlog, make_tail, report

    data = [ln.encode() for _d, ln, _r in generator.generate(mix=MIX, seed=seed, count=n)]
    cfg = Config().rebase(tmp)
    cfg.vault.signing_key = None
    cfg.sinks.parquet.flush_secs = 5
    bus = MemoryBus(16)
    w = Worker(cfg, bus, PackRegistry([ROOT / "packs"]), 0, 1, tail=make_tail(bus), cluster_store=MemoryClusterStore(), shard=False)
    pub = Publisher(bus, cfg.node_id)
    t0 = time.process_time()
    for i, d in enumerate(data):
        pub.ingest(d, "udp", f"10.0.{i % 6}.{(i // 6) % 40}", 514)
    pub.flush()
    w.drain()
    w.close()
    eps = n / (time.process_time() - t0)
    return eps, report(bus.ledger.snapshot(), backlog(bus), 0)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--runs", type=int, default=3)
    a = ap.parse_args(argv)
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
    from ulpf.pipeline.bench import hardware

    runs = []
    for _ in range(a.runs):
        with tempfile.TemporaryDirectory() as td:
            eps, led = measure(Path(td))
        assert led["conserved"], led
        runs.append(round(eps))
    med = round(statistics.median(runs))
    print(json.dumps({"runs_eps": runs, "median_eps": med}))
    if a.record:
        p = ROOT / "bench" / "baseline.json"
        base = json.loads(p.read_text())
        base["inprocess_eps_measured"] = {"unit": "events per CPU-second (process_time), one in-process worker", "median": med, "runs": runs, "events": 20_000, "mix": MIX, "hardware": hardware(),
                                          "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        base["strict_max_drop"] = 0.20
        p.write_text(json.dumps(base, indent=2) + "\n")
        print(f"recorded in {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
