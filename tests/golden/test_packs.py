"""Golden vectors for every shipped pack, run through the reference engine (ulpf.onboard.refengine).

When the backend CLI (`ulpf`) is installed the same vectors also run through the product engine (`ulpf packs test`)."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from ulpf.onboard import refengine

PACKS = Path(__file__).resolve().parents[2] / "packs"
FILES = sorted(PACKS.rglob("*.yaml"))
P0 = {"fortinet.fortigate", "cisco.asa", "suricata.eve", "cef.generic_firewall", "pfsense.filterlog", "squid.access"}
P1 = {"zeek.conn", "windows.event_xml", "leef.generic", "dns.dnsmasq"}


def _all():
    return [refengine.load_pack(f) for f in FILES]


@pytest.mark.parametrize("path", FILES)
def test_pack_lints_and_passes_vectors(path):
    p = refengine.load_pack(path)
    assert refengine.lint(p, min_tests=5) == []
    assert refengine.run_tests(p) == []


def test_all_p0_and_p1_packs_present():
    ids = {p.id for p in _all()}
    assert (P0 | P1) <= ids, sorted((P0 | P1) - ids)


def test_every_pack_unverified_r12():
    for f in FILES:
        assert yaml.safe_load(f.read_text())["verified"] is False, f


def test_no_mikrotik_pack():
    """MikroTik is the held-out onboarding source; shipping a pack would invalidate the demo (§7.11)."""
    for p in _all():
        assert "mikrotik" not in p.id.lower() and "mikrotik" not in json.dumps(p.doc).lower(), p.id


def test_vector_counts_and_edge_cases():
    for p in _all():
        names = [t["name"] for t in p.doc["tests"]]
        assert len(names) >= 5 and len(set(names)) == len(names), p.id
        assert any(w in n.lower() for n in names for w in ("edge", "empty", "unicode", "missing", "malformed", "truncated", "ipv6", "unknown", "quoted", "escaped", "partial", "residual", "no_", "odd", "dash", "unset", "invalid", "bad", "heuristic", "assumed", "tz", "old")), (p.id, names)


def test_detect_routes_each_vector_to_its_own_pack():
    packs = sorted(_all(), key=lambda p: -p.priority)
    wrong = []
    for p in packs:
        for t in p.doc["tests"]:
            got = refengine.detect(packs, t["raw"].encode("utf-8", "surrogateescape"))
            if got is None or got.id != p.id:
                wrong.append((p.id, t["name"], got.id if got else None))
    assert wrong == []


def test_unknown_input_is_unparsed_not_raised():
    packs = _all()
    for raw in (b"", b"\x00\xff\xfe garbage", b"<13>Oct  4 hello world", b"{" * 1000, b"a" * 70000):
        ev = refengine.process_raw(packs, raw)
        assert ev["ulpf"]["status"] in ("unparsed", "partial", "parsed")


def test_backend_engine_agrees_if_installed():
    exe = shutil.which("ulpf")
    if not exe:
        pytest.skip("backend `ulpf` CLI not installed")
    r = subprocess.run([exe, "packs", "test", str(PACKS)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-800:] + r.stderr[-800:]
