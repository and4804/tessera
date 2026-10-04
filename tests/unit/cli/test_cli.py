"""CLI end to end through typer's runner: the M1 thin slice (replay -> vault -> packs -> OCSF JSONL + Parquet, ledger, verify), tamper
detection, keygen, validate, packs lint/test, run role errors, the standalone demo and the redis-less error message."""
import json
import re
from pathlib import Path

import duckdb
import pytest
from typer.testing import CliRunner

from tools.loggen import generator
from ulpf.cli import app

PACKS = Path(__file__).resolve().parents[3] / "packs"
MIX = "fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10"
runner = CliRunner()


@pytest.fixture
def demo_log(tmp_path):
    p = tmp_path / "demo.log"
    p.write_bytes(b"\n".join(ln.encode() for _d, ln, _r in generator.generate(mix=MIX, seed=2, count=2500)) + b"\nunparseable noise here\n")
    return p


def test_m1_thin_slice_replay_then_verify_then_tamper(tmp_path, demo_log):
    d = tmp_path / "data"
    r = runner.invoke(app, ["replay", "--file", str(demo_log), "--no-redis", "--data-dir", str(d)])
    assert r.exit_code == 0, r.output
    assert "conserved            True" in r.output and "vault verify: PASS" in r.output
    assert re.search(r"ingested\s+2501", r.output) and re.search(r"unparsed\s+[1-9]", r.output)
    jl = list((d / "out").glob("*.jsonl"))
    assert jl and sum(1 for f in jl for _ in f.open()) == 2501
    n = duckdb.sql(f"SELECT count(*) FROM read_parquet('{d}/lake/**/*.parquet')").fetchone()
    assert n == (2501,)
    v = runner.invoke(app, ["verify", "--data-dir", str(d)])
    assert v.exit_code == 0 and "PASS" in v.output
    v = runner.invoke(app, ["validate", "--events", str(jl[0])])
    assert v.exit_code == 0, v.output
    seg = sorted((d / "vault").rglob("*.ulv")) or sorted(p for p in (d / "vault").rglob("*") if p.is_file() and p.suffix not in (".pub", ".json"))
    victim = seg[0]
    b = bytearray(victim.read_bytes())
    b[len(b) // 2] ^= 0xFF
    victim.write_bytes(bytes(b))
    v = runner.invoke(app, ["verify", "--data-dir", str(d)])
    assert v.exit_code == 1 and "FAILED" in v.output and "BAD" in v.output


def test_keygen_and_pinned_pubkey(tmp_path, demo_log):
    k = tmp_path / "k" / "key"
    r = runner.invoke(app, ["keygen", str(k)])
    assert r.exit_code == 0 and k.exists() and Path(str(k) + ".pub").exists()
    assert oct(k.stat().st_mode & 0o777) == "0o600"
    cfgf = tmp_path / "c.yaml"
    cfgf.write_text(f"vault: {{signing_key: {k}}}\n")
    d = tmp_path / "data"
    assert runner.invoke(app, ["replay", "--file", str(demo_log), "--no-redis", "--data-dir", str(d), "-c", str(cfgf)]).exit_code == 0
    ok = runner.invoke(app, ["verify", "--data-dir", str(d), "-c", str(cfgf), "--pubkey", str(k) + ".pub"])
    assert ok.exit_code == 0 and "sig=ok" in ok.output
    other = tmp_path / "other"
    runner.invoke(app, ["keygen", str(other)])
    bad = runner.invoke(app, ["verify", "--data-dir", str(d), "-c", str(cfgf), "--pubkey", str(other) + ".pub"])
    assert bad.exit_code == 1


def test_validate_flags_a_bad_event(tmp_path):
    f = tmp_path / "e.jsonl"
    f.write_text(json.dumps({"class_uid": 4001}) + "\nnot json\n")
    r = runner.invoke(app, ["validate", "--events", str(f)])
    assert r.exit_code == 1 and "violations" in r.output


def test_packs_lint_and_test_on_shipped_packs():
    r = runner.invoke(app, ["packs", "test", str(PACKS)])
    assert r.exit_code == 0, r.output
    assert "FAIL" not in r.output
    r = runner.invoke(app, ["packs", "lint", str(PACKS)])
    assert r.exit_code == 0, r.output


def test_packs_lint_rejects_a_broken_pack(tmp_path):
    (tmp_path / "bad.yaml").write_text("id: x.y\nversion: '1'\nnot: a pack\n")
    assert runner.invoke(app, ["packs", "lint", str(tmp_path)]).exit_code == 1


def test_run_rejects_unknown_role(tmp_path):
    r = runner.invoke(app, ["run", "--role", "nope", "--no-redis", "--data-dir", str(tmp_path)])
    assert r.exit_code == 2 and "unknown role" in r.output


def test_replay_without_redis_server_says_so(tmp_path, demo_log, monkeypatch):
    monkeypatch.setenv("ULPF_BUS_URL", "redis://127.0.0.1:1/0")
    r = runner.invoke(app, ["replay", "--file", str(demo_log), "--data-dir", str(tmp_path / "d")])
    assert r.exit_code == 3 and "cannot reach Redis" in r.output


def test_demo_standalone_runs_detector(tmp_path):
    r = runner.invoke(app, ["demo", "--eps", "6", "--no-serve", "--data-dir", str(tmp_path / "d")])
    assert r.exit_code == 0, r.output
    assert "conserved=True" in r.output and "analytics:" in r.output
