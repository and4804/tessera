"""Guide section 9: fail if sustained eps drops more than 20% below bench/baseline.json.

The recorded baseline (`python -m tools.bench.inprocess --record`) is a measurement of ONE machine, so this strict gate applies only on the
same CPU model and core count; elsewhere it is skipped (tests/perf/test_throughput_gate.py, the order-of-magnitude floor, always runs).
Best of 3 runs is compared, which absorbs the +/-15% run-to-run noise measured on the shared 2-vCPU VM."""
import json
import tempfile
from pathlib import Path

import pytest

from tools.bench.inprocess import measure
from ulpf.pipeline.bench import hardware

BASE = json.loads((Path(__file__).resolve().parents[2] / "bench" / "baseline.json").read_text())


def test_inprocess_eps_within_20pct_of_recorded_baseline():
    rec = BASE.get("inprocess_eps_measured")
    if not rec:
        pytest.skip("no recorded baseline (python -m tools.bench.inprocess --record)")
    hw, now = rec["hardware"], hardware()
    if (hw["cpu"], hw["cores"]) != (now["cpu"], now["cores"]):
        pytest.skip(f"baseline was measured on {hw['cpu']} x{hw['cores']}, this is {now['cpu']} x{now['cores']}")
    floor = rec["median"] * (1 - BASE.get("strict_max_drop", 0.20))
    best = 0.0
    for _ in range(3):
        with tempfile.TemporaryDirectory() as td:
            eps, led = measure(Path(td))
        assert led["conserved"]
        best = max(best, eps)
        if best >= floor:
            break
    assert best >= floor, f"best of 3 runs {best:,.0f} eps is more than 20% below the recorded baseline {rec['median']:,} eps"


def test_floor_in_baseline_was_not_loosened():
    assert BASE["inprocess_eps_floor"] >= 2500        # the original regression floor; raise it, never lower it
