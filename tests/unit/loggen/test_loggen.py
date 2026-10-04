import json
import subprocess
import sys
from pathlib import Path

from tools.loggen import generator, heldout
from tools.loggen.formats import REGISTRY

ROOT = Path(__file__).resolve().parents[3]
DEMO = ROOT / "tools" / "loggen" / "scenarios" / "demo.yaml"


def _run(*args):
    return subprocess.run([sys.executable, "-m", "tools.loggen", *args], cwd=ROOT, capture_output=True, text=True,
                          env={"PYTHONPATH": f"{ROOT / 'src'}:{ROOT}", "PATH": "/usr/bin:/usr/local/bin"})


def test_deterministic_same_seed_same_bytes(tmp_path):
    a, b, c = tmp_path / "a.log", tmp_path / "b.log", tmp_path / "c.log"
    for f, seed in ((a, "5"), (b, "5"), (c, "6")):
        assert _run("--seed", seed, "--count", "500", "--out", str(f)).returncode == 0
    assert a.read_bytes() == b.read_bytes()
    assert a.read_bytes() != c.read_bytes()
    assert (tmp_path / "a.log.truth.jsonl").read_bytes() == (tmp_path / "b.log.truth.jsonl").read_bytes()


def test_truth_is_line_aligned_and_shaped(tmp_path):
    f = tmp_path / "m.log"
    assert _run("--seed", "2", "--count", "600", "--mix", "fortigate:1,asa:1,suricata:1,cef:1,pfsense:1,squid:1,zeek:1,windows:1,leef:1,dnsmasq:1", "--out", str(f)).returncode == 0
    lines = f.read_bytes().split(b"\n")[:-1]
    truth = [json.loads(x) for x in (tmp_path / "m.log.truth.jsonl").read_text().splitlines()]
    assert len(lines) == len(truth) == 600
    assert {t["source"] for t in truth} == set(REGISTRY)
    for t in truth:
        assert isinstance(t["expect"], dict) and "class_uid" in t["expect"] and isinstance(t["n"], int)


def test_every_format_renders_and_has_no_embedded_newline():
    for name in REGISTRY:
        got = list(generator.generate(mix=f"{name}:1", seed=1, count=50))
        assert len(got) == 50
        assert all("\n" not in line for _d, line, _t in got), name


def test_demo_has_three_incidents_at_scheduled_times(tmp_path):
    got = list(generator.generate(scenario=str(DEMO), seed=1337, eps=20, duration_s=1800))
    tags = {}
    for _d, _l, t in got:
        if "tag" in t:
            tags.setdefault(t["tag"], []).append(t["expect"]["time"])
    start = 1791118800000
    assert {"port_scan", "ssh_bruteforce", "exfiltration"} <= set(tags)
    for tag, at in (("port_scan", 600), ("ssh_bruteforce", 1080), ("exfiltration", 1500)):
        assert min(tags[tag]) >= start + at * 1000 - 1000, tag
        assert min(tags[tag]) <= start + (at + 5) * 1000, tag


def test_heldout_generators_are_deterministic_and_have_truth():
    for g in (heldout.mikrotik, heldout.sophos_kv, heldout.juniper_srx):
        a, b = list(g(seed=3, n=20)), list(g(seed=3, n=20))
        assert a == b and len(a) == 20
        assert all(isinstance(t, dict) and "class_uid" in t for _l, t in a)


def test_no_mikrotik_in_shipped_formats():
    assert "mikrotik" not in REGISTRY
    assert not list((ROOT / "packs").rglob("*mikrotik*"))
