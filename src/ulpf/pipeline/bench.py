"""``ulpf bench``: measured throughput, scaling and ingest->queryable latency of the real pipeline (§9).

Nothing here is estimated. The harness starts a throwaway ``redis-server`` (or uses ``--redis-url``), generates a deterministic
multi-vendor corpus with ``tools.loggen``, and for each worker count W:

* **throughput**: the whole corpus is published to the bus first, then W worker processes (static partition assignment) are started
  and the conservation ledger's ``sunk`` counter is sampled every 100 ms. ``eps`` is the slope between 10 % and 90 % of the corpus, so
  process start-up and the final partial Parquet flush are excluded; ``wall_eps`` (corpus / first-to-last sample) is recorded as well.
  The publisher is idle while workers run, so the number is worker capacity, not ingest capacity.
* **latency**: with W=1 workers ready, a paced publisher sends ~50 % of the measured single-worker rate for ``--latency-secs``; for every
  event the time from receive (``recv_time``) until its Parquet file was renamed into the lake (file mtime) is its ingest->queryable
  latency (this includes the group-commit window ``sinks.parquet.flush_secs``).
* **resources**: CPU % (utime+stime of the worker processes over the measured slope, 100 % = one core) and summed RSS.

Hardware is read from ``/proc``; results go to ``bench/results.json`` in the shape of ``GET /api/v1/benchmark``."""
from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..config import Config
from .runtime import WorkerPool, ensure_signing_key

DEFAULT_MIX = "fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10"
CLK = os.sysconf("SC_CLK_TCK")


def hardware() -> dict[str, Any]:
    cpu = platform.processor() or "unknown"
    try:
        for ln in Path("/proc/cpuinfo").read_text().splitlines():
            if ln.startswith("model name"):
                cpu = ln.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    ram = 0.0
    try:
        for ln in Path("/proc/meminfo").read_text().splitlines():
            if ln.startswith("MemTotal"):
                ram = round(int(ln.split()[1]) / 1048576, 1)
                break
    except OSError:
        pass
    return {"cpu": cpu, "cores": os.cpu_count() or 1, "ram_gb": ram, "os": platform.platform(), "python": platform.python_version()}


def _proc_cpu_s(pid: int) -> float:
    try:
        f = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / CLK
    except (OSError, IndexError, ValueError):
        return 0.0


def _proc_rss_mb(pid: int) -> float:
    try:
        for ln in Path(f"/proc/{pid}/status").read_text().splitlines():
            if ln.startswith("VmRSS"):
                return int(ln.split()[1]) / 1024
    except (OSError, ValueError):
        pass
    return 0.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class ThrowawayRedis:
    def __init__(self, workdir: Path) -> None:
        exe = shutil.which("redis-server")
        if not exe:
            raise RuntimeError("redis-server not found: install Redis or pass --redis-url")
        self.port = _free_port()
        self.proc = subprocess.Popen([exe, "--port", str(self.port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no",
                                      "--dir", str(workdir), "--maxmemory-policy", "noeviction"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.url = f"redis://127.0.0.1:{self.port}/0"
        import redis

        r = redis.Redis.from_url(self.url)
        for _ in range(100):
            try:
                r.ping()
                return
            except redis.ConnectionError:
                time.sleep(0.05)
        raise RuntimeError("redis-server did not start")

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


DEVICES_PER_FORMAT = 40


def generate_corpus(path: Path, n: int, mix: str, seed: int) -> float:
    root = Path(__file__).resolve().parents[3]
    if not (root / "tools" / "loggen").is_dir():
        raise RuntimeError("tools/loggen not found next to the package; run bench from a source checkout")
    t = time.perf_counter()
    subprocess.run([sys.executable, "-m", "tools.loggen", "--seed", str(seed), "--mix", mix, "--count", str(n), "--out", str(path), "--no-truth",
                    "--split", str(path.parent / "split")],
                   check=True, cwd=root, env={**os.environ, "PYTHONPATH": f"{root / 'src'}:{root}"}, capture_output=True)
    return time.perf_counter() - t


def load_corpus(path: Path, devices: int = DEVICES_PER_FORMAT) -> list[tuple[str, bytes]]:
    """``(peer_ip, line)`` in proportional interleave of the per-format files. Each format is spread over ``devices`` simulated devices
    (contiguous runs of 20 lines each, as a collector would send), so the bus partitions by source the way a real fleet does: a
    single-source corpus would land in ONE partition and could never use more than one worker (I5 per-source ordering)."""
    files = sorted((path.parent / "split").glob("*.log"))
    per: list[list[tuple[str, bytes]]] = []
    for fi, f in enumerate(files):
        ls = [ln for ln in f.read_bytes().split(b"\n") if ln]
        per.append([(f"10.{fi + 1}.0.{(j // 20) % devices + 1}", ln) for j, ln in enumerate(ls)])
    keyed = [((j + 0.5) / len(rows), fi, j) for fi, rows in enumerate(per) for j in range(len(rows))]
    keyed.sort()
    return [per[fi][j] for _, fi, j in keyed]


def _dir_bytes(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())


def _bench_cfg(base: Config, run_dir: Path, url: str, partitions: int) -> Config:
    cfg = base.rebase(run_dir)
    cfg.bus.kind = "redis"
    cfg.bus.url = url
    cfg.bus.partitions = partitions
    cfg.sinks.jsonl.enabled = False
    cfg.analytics.enabled = False
    cfg.pipeline.workers = 1
    cfg.vault.signing_key = str(run_dir / "keys" / "ulpf_ed25519")
    ensure_signing_key(cfg)
    return cfg


def _publish_all(bus: Any, cfg: Config, lines: list[tuple[str, bytes]], rate: float | None = None, stop_at: float | None = None) -> int:
    from ..ingest import Publisher

    pub = Publisher(bus, cfg.node_id, max_event_bytes=cfg.ingest.max_event_bytes, batch_max=cfg.ingest.batch_max)
    t0 = time.perf_counter()
    n = 0
    for ip, ln in lines:
        pub.ingest(ln, "bench", ip, 0, None)
        n += 1
        if rate:
            lag = n / rate - (time.perf_counter() - t0)
            if lag > 0.002:
                pub.flush()
                time.sleep(lag)
            if stop_at is not None and time.perf_counter() >= stop_at:
                break
    pub.flush()
    return n


def _sunk(bus: Any) -> int:
    return sum(r.get("sunk", 0) + r.get("dropped", 0) for r in bus.ledger.snapshot().values())


def run_throughput(base: Config, url: str, run_dir: Path, lines: list[tuple[str, bytes]], workers: int, partitions: int,
                   log: Callable[[str], None]) -> dict[str, Any]:
    from ..bus import make_bus
    from .ledger import backlog, report

    cfg = _bench_cfg(base, run_dir, url, partitions)
    bus = make_bus("redis", url, partitions, cfg.bus.maxlen)
    bus.r.flushall()
    n = _publish_all(bus, cfg, lines)
    pool = WorkerPool(cfg, workers)
    samples: list[tuple[float, int]] = []
    cpu0: dict[int, float] = {}
    try:
        pool.start()
        cpu_t0 = time.perf_counter()
        for pid in pool.pids:
            cpu0[pid] = _proc_cpu_s(pid)
        rss = 0.0
        deadline = time.monotonic() + max(120.0, n / 500)
        while time.monotonic() < deadline:
            done = _sunk(bus)
            samples.append((time.perf_counter(), done))
            if len(samples) % 10 == 0:
                rss = max(rss, sum(_proc_rss_mb(p) for p in pool.pids))
            if done >= n:
                break
            time.sleep(0.1)
        cpu1 = {pid: _proc_cpu_s(pid) for pid in pool.pids}
        cpu_t1 = time.perf_counter()
        rss = max(rss, sum(_proc_rss_mb(p) for p in pool.pids))
    finally:
        pool.stop()
    lo, hi = int(n * 0.10), int(n * 0.90)
    a = next((s for s in samples if s[1] >= lo), None)
    b = next((s for s in samples if s[1] >= hi), None)
    if a is None or b is None or b[0] <= a[0]:
        raise RuntimeError(f"workers={workers}: no usable throughput window ({len(samples)} samples, sunk {samples[-1][1] if samples else 0}/{n})")
    eps = (b[1] - a[1]) / (b[0] - a[0])
    first = next((s for s in samples if s[1] > 0), samples[0])
    wall_eps = samples[-1][1] / max(samples[-1][0] - first[0], 1e-9)
    cpu_pct = 100.0 * sum(cpu1[p] - cpu0.get(p, 0.0) for p in cpu1) / max(cpu_t1 - cpu_t0, 1e-9)
    rep = report(bus.ledger.snapshot(), backlog(bus), int(time.time() * 1000))
    tot = rep["totals"]
    if tot["normalized_parsed"] < 0.5 * tot["ingested"]:
        raise RuntimeError(f"only {tot['normalized_parsed']}/{tot['ingested']} events parsed: packs not loaded (packs.dirs={cfg.packs.dirs}); "
                           "a throughput number over the unparsed lane would be meaningless")
    raw = sum(len(x) for _, x in lines)
    out = {"workers": workers, "eps": round(eps, 1), "wall_eps": round(wall_eps, 1), "events": n, "cpu_pct": round(cpu_pct, 1), "rss_mb": round(rss, 1),
           "ledger": rep, "vault_bytes": _dir_bytes(Path(cfg.vault.dir)), "lake_bytes": _dir_bytes(cfg.lake_dir), "raw_bytes": raw}
    log(f"  workers={workers}: {eps:,.0f} eps (window 10-90%), {wall_eps:,.0f} eps wall, cpu {cpu_pct:.0f}%, rss {rss:.0f} MB, "
        f"conserved={rep['conserved']}")
    bus.close()
    return out


def run_latency(base: Config, url: str, run_dir: Path, lines: list[tuple[str, bytes]], rate: float, secs: float, partitions: int,
                log: Callable[[str], None]) -> dict[str, float] | None:
    import duckdb

    from ..bus import make_bus

    cfg = _bench_cfg(base, run_dir, url, partitions)
    bus = make_bus("redis", url, partitions, cfg.bus.maxlen)
    bus.r.flushall()
    pool = WorkerPool(cfg, 1)
    try:
        pool.start()
        t_end = time.perf_counter() + secs
        sent = _publish_all(bus, cfg, lines, rate=rate, stop_at=t_end)
        deadline = time.monotonic() + 60
        while _sunk(bus) < sent and time.monotonic() < deadline:
            time.sleep(0.2)
    finally:
        pool.stop()
    files = sorted(str(p) for p in cfg.lake_dir.rglob("*.parquet"))
    if not files:
        return None
    mt = {f: os.stat(f).st_mtime * 1000 for f in files}
    con = duckdb.connect()
    rows = con.execute("SELECT filename, epoch_ms(recv_time) FROM read_parquet(?, filename=true)", [files]).fetchall()
    lat = sorted(max(0.0, mt[f] - r) for f, r in rows if f in mt)
    if not lat:
        return None

    def q(p: float) -> float:
        return float(round(lat[min(len(lat) - 1, int(p * len(lat)))], 1))

    res = {"p50": q(0.50), "p95": q(0.95), "p99": q(0.99), "max": round(lat[-1], 1), "events": float(len(lat)), "rate_eps": round(rate, 1)}
    log(f"  latency at {rate:,.0f} eps ({len(lat)} events): p50 {res['p50']:.0f} ms, p95 {res['p95']:.0f} ms, p99 {res['p99']:.0f} ms")
    return res


def run_bench(base: Config, *, events: int, workers_list: list[int], mix: str, seed: int, latency_secs: float, partitions: int,
              out: Path, redis_url: str | None, log: Callable[[str], None]) -> dict[str, Any]:
    tmp = Path(tempfile.mkdtemp(prefix="ulpf-bench-"))
    rd = None if redis_url else ThrowawayRedis(tmp)
    url = redis_url or (rd.url if rd else "")
    try:
        corpus = tmp / "corpus.log"
        log(f"generating {events:,} lines ({mix}, seed {seed})")
        t = generate_corpus(corpus, events, mix, seed)
        lines = load_corpus(corpus)
        log(f"  corpus {len(lines):,} lines, {corpus.stat().st_size / 1e6:.1f} MB in {t:.1f}s")
        runs = []
        for w in workers_list:
            rdir = tmp / f"run-w{w}"
            rdir.mkdir()
            runs.append(run_throughput(base, url, rdir, lines, w, partitions, log))
            shutil.rmtree(rdir, ignore_errors=True)
        single = next((r for r in runs if r["workers"] == 1), runs[0])
        lat = None
        if latency_secs > 0:
            ldir = tmp / "run-latency"
            ldir.mkdir()
            lat = run_latency(base, url, ldir, lines, max(100.0, 0.5 * single["eps"] / single["workers"]), latency_secs, partitions, log)
        best = max(runs, key=lambda r: r["eps"])
        led = best["ledger"]["totals"]
        res: dict[str, Any] = {
            "generated_at": int(time.time() * 1000),
            "hardware": hardware(),
            "config": {"mix": mix, "duration_s": round(single["events"] / single["eps"], 1), "events": len(lines), "workers_list": workers_list,
                       "partitions": partitions, "seed": seed, "method": "pre-published corpus, ledger slope 10-90%, static partitions, "
                       f"{DEVICES_PER_FORMAT} simulated devices per format, real Redis Streams bus, vault fsync per block, Parquet+tail sinks"},
            "sustained": {"eps": best["eps"], "per_worker_eps": round(best["eps"] / best["workers"], 1),
                          "projected_daily_events": int(best["eps"] * 86400)},
            "scaling": [{"workers": r["workers"], "eps": r["eps"]} for r in runs],
            "resources": {"cpu_pct": best["cpu_pct"], "rss_mb": best["rss_mb"]},
            "vault": {"compression_ratio": round(best["raw_bytes"] / max(best["vault_bytes"], 1), 2)},
            "lake": {"bytes_per_event": round(best["lake_bytes"] / max(best["events"], 1), 1)},
            "ledger": {"ingested": led["ingested"], "lost": best["ledger"]["lost"], "conserved": all(r["ledger"]["conserved"] for r in runs)},
            "parse_rate": round(led["normalized_parsed"] / max(led["ingested"], 1), 4),
            "runs": [{k: v for k, v in r.items() if k != "ledger"} for r in runs],
        }
        if lat:
            res["latency_ms"] = {k: lat[k] for k in ("p50", "p95", "p99", "max")}
            res["config"]["latency_at_eps"] = lat["rate_eps"]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res, indent=2) + "\n")
        log(f"wrote {out}")
        return res
    finally:
        if rd:
            rd.stop()
        shutil.rmtree(tmp, ignore_errors=True)
