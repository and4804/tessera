"""R5: nothing in the slow-path tooling may open a non-loopback socket. A guard turns any such attempt into a test failure."""
import ipaddress
import socket
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


class Egress(AssertionError):
    pass


def _local(host) -> bool:
    if isinstance(host, bytes):
        host = host.decode()
    if host in ("localhost", ""):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


@pytest.fixture
def guard(monkeypatch):
    real_connect, real_gai = socket.socket.connect, socket.getaddrinfo

    def connect(self, address, *a, **k):
        if self.family in (socket.AF_INET, socket.AF_INET6) and not _local(address[0]):
            raise Egress(f"non-local connect to {address}")
        return real_connect(self, address, *a, **k)

    def gai(host, *a, **k):
        if not _local(host):
            raise Egress(f"DNS lookup of {host!r}")
        return real_gai(host, *a, **k)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", gai)


def test_guard_blocks_external_connect_and_dns(guard):
    s = socket.socket()
    with pytest.raises(Egress):
        s.connect(("1.1.1.1", 443))
    s.close()
    with pytest.raises(Egress):
        socket.getaddrinfo("example.com", 443)


def test_onboarding_pipeline_makes_no_network_calls(guard):
    from tools.loggen import heldout
    from ulpf.onboard import evaluator, studio
    lines = [ln for ln, _ in heldout.mikrotik(seed=7, n=40)]
    a = studio.analyze(lines, label="x")
    studio.preview(a.pack_yaml, lines)
    evaluator.evaluate_source("mikrotik", heldout.mikrotik, "MikroTik", n_train=40, n_test=40)


def test_llm_assist_cannot_reach_a_remote_host(guard):
    from tools.loggen import heldout
    from ulpf.onboard import llm, studio
    lines = [ln for ln, _ in heldout.mikrotik(seed=7, n=40)]
    pack = studio.analyze(lines, label="x").pack
    out = llm.LLMAssist(enabled=True, endpoint="http://api.example.com").assist(pack, lines)    # default urllib transport
    assert not out.accepted


def test_analytics_and_loggen_make_no_network_calls(guard):
    from tools.loggen import generator
    from ulpf.analytics import features
    ev = [rec["expect"] for _d, _l, rec in generator.generate(mix="fortigate:1", seed=1, count=500)]
    assert features.build_windows(ev, engine="python")


def test_compose_has_no_external_network_and_publishes_only_through_the_gateway():
    """App services (api, ingest, worker, redis) are internal-only and publish nothing; only `gateway` touches `edge` and publishes
    (Docker cannot publish ports of containers that sit only on an `internal: true` network)."""
    c = yaml.safe_load((ROOT / "docker" / "compose.yml").read_text())
    assert c["networks"]["internal"]["internal"] is True
    assert not c["networks"]["edge"].get("internal")
    for name, s in c["services"].items():
        nets = set(s.get("networks", c.get("x-ulpf", {}).get("networks", [])))
        if name == "gateway":
            assert nets == {"internal", "edge"}
            assert s["ports"], "gateway must publish the UI port"
        else:
            assert nets <= {"internal"}, name
            assert not s.get("ports"), name
    assert yaml.safe_load((ROOT / "configs" / "ulpf.yaml").read_text())["onboard"]["llm"]["enabled"] is False


def test_vendor_ocsf_from_dir_works_offline_and_fails_cleanly_without_source(tmp_path, guard):
    import json

    from tools import vendor_ocsf
    src = tmp_path / "dl"
    src.mkdir()
    (src / "schema.json").write_text(json.dumps({"classes": {"network_activity": {}}}))
    assert vendor_ocsf.main(["--version", "9.9.9", "--out", str(tmp_path / "out"), "--from-dir", str(src)]) == 0
    man = json.loads((tmp_path / "out" / "9.9.9" / "MANIFEST.json").read_text())
    assert man["classes"] == 1 and len(man["sha256"]) == 64
    assert vendor_ocsf.main(["--version", "9.9.9", "--out", str(tmp_path / "o2")]) == 2        # online fetch is refused by the guard -> clean error
