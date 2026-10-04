"""Render bench results to Markdown (docs/benchmarks.md fragment). Only prints what was measured.

Accepts the product results file (bench/results.json, written by `ulpf bench`) and/or reference-engine files (bench-results.json)."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def render_product(r: dict) -> str:
    hw, cfg = r["hardware"], r["config"]
    out = [f"Hardware: {hw['cpu']}, {hw['cores']} vCPU, {hw['ram_gb']} GB RAM, {hw['os']}, Python {hw.get('python', '?')}.",
           f"Corpus: {cfg.get('events')} lines, mix `{cfg.get('mix')}`, seed {cfg.get('seed')}.", "",
           "| workers | sustained eps | wall eps | worker CPU % | RSS MB |", "|---|---|---|---|---|"]
    for run in r.get("runs", []):
        out.append(f"| {run['workers']} | {run['eps']:,.0f} | {run.get('wall_eps', 0):,.0f} | {run.get('cpu_pct', 0):.0f} | {run.get('rss_mb', 0):.0f} |")
    if "latency_ms" in r:
        lm = r["latency_ms"]
        out += ["", "Ingest to queryable latency (ms): " + ", ".join(f"{k} {v:g}" for k, v in lm.items())]
    out.append(f"Ledger: ingested {r['ledger']['ingested']}, lost {r['ledger']['lost']}, conserved {r['ledger']['conserved']}.")
    return "\n".join(out) + "\n"


def render_ref(paths: list[str]) -> str:
    out = ["| engine | events | seconds | events/s | cpu | python | measured_at |", "|---|---|---|---|---|---|---|"]
    for p in paths:
        r = json.loads(Path(p).read_text())
        e = r.get("env", {})
        out.append(f"| {r['engine']} | {r['events']} | {r['seconds']} | {r['eps']} | {e.get('cpu', '?')} ({e.get('cores', '?')} cores) | {e.get('python', '?')} | {r.get('measured_at', '?')} |")
    return "\n".join(out) + "\n"


def render(paths: list[str]) -> str:
    parts, ref = [], []
    for p in paths:
        r = json.loads(Path(p).read_text())
        (parts.append(render_product(r)) if "scaling" in r else ref.append(p))
    if ref:
        parts.append(render_ref(ref))
    return "\n".join(parts)


if __name__ == "__main__":
    sys.stdout.write(render(sys.argv[1:] or ["bench/results.json"]))
