"""Benchmark runner (§9). Measures; never invents numbers. Writes bench-results.json.

Engines:
  ulpf   the real pipeline via `ulpf bench` (needs the backend and redis-server; this is what bench/results.json is made of).
  ref    the slow reference interpreter in ulpf.onboard.refengine. It is NOT the product hot path; numbers are labelled
         engine=reference and exist only so the harness can be exercised without the backend.
Environment (cpu, python, platform) is recorded with every run.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def env_info() -> dict:
    cpu = "unknown"
    try:
        for ln in open("/proc/cpuinfo"):
            if ln.startswith("model name"):
                cpu = ln.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {"python": platform.python_version(), "platform": platform.platform(), "cpu": cpu, "cores": os.cpu_count()}


def gen(path: Path, n: int, mix: str, seed: int) -> float:
    t = time.perf_counter()
    subprocess.run([sys.executable, "-m", "tools.loggen", "--seed", str(seed), "--mix", mix, "--count", str(n), "--out", str(path), "--no-truth"],
                   check=True, cwd=ROOT, env={**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}"}, capture_output=True)
    return time.perf_counter() - t


def run_ref(path: Path) -> dict:
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
    from ulpf.onboard import refengine
    packs = refengine.load_packs(ROOT / "packs")
    lines = path.read_bytes().split(b"\n")
    lines = [ln for ln in lines if ln]
    ok = 0
    t = time.perf_counter()
    for ln in lines:
        ev = refengine.process_raw(packs, ln)
        ok += ev["ulpf"]["status"] != "unparsed" if ev else 0
    dt = time.perf_counter() - t
    return {"engine": "reference", "events": len(lines), "parsed": ok, "seconds": round(dt, 3), "eps": round(len(lines) / dt)}


def run_ulpf(count: int, mix: str, seed: int, workers: str, out: Path, latency_secs: float) -> dict:
    """Delegate to the real harness (`ulpf bench`, src/ulpf/pipeline/bench.py): Redis Streams bus, worker processes, vault fsync, Parquet.
    There is no `ulpf replay --json`; `ulpf bench` generates its own corpus, measures, and writes the results file itself."""
    exe = shutil.which("ulpf") or str(Path(sys.executable).with_name("ulpf"))
    if not Path(exe).exists():
        raise SystemExit("`ulpf` CLI not found; install the backend (pip install -e .) or use --engine ref")
    cmd = [exe, "bench", "--events", str(count), "--workers", workers, "--mix", mix, "--seed", str(seed), "--latency-secs", str(latency_secs),
           "--out", str(out)]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    sys.stderr.write(p.stdout[-3000:])
    if p.returncode:
        raise SystemExit(f"ulpf bench failed (exit {p.returncode}; a non-zero exit also means the ledger was NOT conserved): {p.stderr[-600:]}")
    res = json.loads(out.read_text())
    res["engine"] = "ulpf"
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--engine", choices=["ulpf", "ref"], default="ulpf")
    ap.add_argument("--count", type=int, default=200_000)
    ap.add_argument("--mix", default="fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--workers", default="1,2,4", help="engine=ulpf: worker counts")
    ap.add_argument("--latency-secs", type=float, default=20.0)
    ap.add_argument("--out", default=None, help="engine=ulpf default bench/results.json; engine=ref default bench-results.json")
    a = ap.parse_args(argv)
    if a.engine == "ulpf":
        res = run_ulpf(a.count, a.mix, a.seed, a.workers, Path(a.out or ROOT / "bench" / "results.json"), a.latency_secs)
        print(json.dumps({"hardware": res["hardware"], "scaling": res["scaling"], "latency_ms": res.get("latency_ms"), "ledger": res["ledger"]}, indent=2))
        return 0
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "bench.log"
        gsec = gen(f, a.count, a.mix, a.seed)
        res = run_ref(f)
    res.update({"mix": a.mix, "seed": a.seed, "generator_seconds": round(gsec, 3), "env": env_info(), "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    Path(a.out or "bench-results.json").write_text(json.dumps(res, indent=2))
    print(json.dumps({k: v for k, v in res.items() if k != "env"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
