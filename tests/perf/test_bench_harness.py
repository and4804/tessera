"""tools/bench works against the real CLI: `python -m tools.bench.run --engine ulpf` delegates to `ulpf bench` (there is no `ulpf replay --json`)."""
import json
import shutil
import sys

import pytest

from tools.bench import report, run


@pytest.mark.skipif(not shutil.which("redis-server"), reason="redis-server not installed")
def test_run_py_delegates_to_ulpf_bench_and_reports_conservation(tmp_path):
    out = tmp_path / "res.json"
    assert run.main(["--engine", "ulpf", "--count", "6000", "--workers", "1", "--latency-secs", "0", "--out", str(out)]) == 0
    r = json.loads(out.read_text())
    assert r["ledger"]["conserved"] and r["ledger"]["lost"] == 0 and r["ledger"]["ingested"] == 6000
    assert r["scaling"][0]["workers"] == 1 and r["scaling"][0]["eps"] > 0 and r["hardware"]["cores"] >= 1
    md = report.render([str(out)])
    assert "| 1 |" in md and "conserved True" in md


def test_reference_engine_still_runs(tmp_path):
    out = tmp_path / "ref.json"
    assert run.main(["--engine", "ref", "--count", "500", "--out", str(out)]) == 0
    assert json.loads(out.read_text())["engine"] == "reference"
    assert "reference" in report.render([str(out)])
    assert sys.version_info >= (3, 12)
