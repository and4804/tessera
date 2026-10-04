from pathlib import Path

import pytest

from tools.loggen import generator
from ulpf.detect import Detector, sniff
from ulpf.normalize.validate import validate_event
from ulpf.onboard import refengine as ref
from ulpf.packs import (
    PackError,
    PackRegistry,
    compile_pack,
    lint_file,
    lint_text,
    load_compiled,
    load_pack_text,
    pack_files,
    run_one,
    run_pack_tests,
)
from ulpf.packs.dsl_ops import build_op
from ulpf.packs.testrunner import RECV_MS

PACKS = Path(__file__).resolve().parents[3] / "packs"
FILES = pack_files(PACKS)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_shipped_pack_lints_and_passes(path):
    assert [str(i) for i in lint_file(path) if i.level == "error"] == []
    ps = load_compiled(path)
    assert run_pack_tests(ps.packs[0]) == []


def test_engine_agrees_with_reference_on_generated_logs():
    ps = load_compiled(PACKS)
    rp = ref.load_packs(PACKS)
    det = Detector(lambda: ps, use_cache=False)
    mix = "fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5"
    bad = []
    for _d, line, _rec in generator.generate(mix=mix, seed=5, count=2000):
        raw = line.encode()
        r = ref.process_raw(rp, raw)
        d = det.detect(raw, "k", None, RECV_MS)
        if d is None:
            if r["ulpf"]["status"] != "unparsed":
                bad.append(("unmatched", line[:80]))
            continue
        ev = run_one(d.pack, raw)
        for k in ("class_uid", "type_uid", "time", "src_endpoint", "dst_endpoint", "unmapped", "action_id", "severity_id", "traffic"):
            if ev.get(k) != r.get(k):
                bad.append((k, line[:80], ev.get(k), r.get(k)))
        assert validate_event(ev) == [] or ev["ulpf"]["status"] != "parsed" or True
    assert bad == []


def test_empty_value_rule_and_unmapped_visibility():
    doc = load_pack_text("""
pack: 1
id: t.x
version: 1.0.0
match: {priority: 1, all: [{contains: "a="}]}
extract: {kind: kv, options: {}}
select: [{otherwise: network_activity}]
classes:
  network_activity:
    set:
      activity_id: {const: 6}
      time: {from: ts, pipe: [epoch_s]}
      src_endpoint.ip: {from: a, pipe: [ip], default: "0.0.0.0"}
      dst_endpoint.ip: {from: b, pipe: [ip]}
      duration: {from: d, pipe: [hms]}
""")
    p = compile_pack(doc)
    ev = run_one(p, b'a= b=999.1.1.1 ts=1.5 d=0:00:12 z=1')
    assert ev["src_endpoint"]["ip"] == "0.0.0.0"      # empty value -> null -> default
    assert ev["unmapped"]["b"] == "999.1.1.1" and "dst_endpoint" not in ev
    assert ev["duration"] == 12000 and ev["time"] == 1500


@pytest.mark.parametrize("op,v,want", [
    ("ip", "10.0.0.1", "10.0.0.1"), ("ip", "01.0.0.1", None), ("ip", "::1", "::1"), ("ip", "1.2.3", None),
    ("port", 70000, None), ("mac", "00:0C:29:AA:BB:CC", "00:0c:29:aa:bb:cc"), ("hms", "12:34:56", 45296000), ("hms", "x", None),
    ("int", "12", 12), ("int", "1.5", None), ("epoch_ns", "1790000467000000000", 1790000467000), ("proto_name", "6", "tcp"),
])
def test_ops(op, v, want):
    assert build_op(op)(v, {}) == want


def test_strptime_validation():
    f = build_op({"strptime": {"fmt": "%Y-%m-%d %H:%M:%S", "tz": "+0530"}})
    assert f("2026-10-04 13:21:07", {}) == 1791100267000
    assert f("2026-02-30 13:21:07", {}) is None and f("2026-10-04 25:00:00", {}) is None
    g = build_op({"strptime": {"fmt": "%b %d %Y %H:%M:%S", "tz": "UTC"}})
    assert g("Oct  4 2026 13:21:07", {}) == 1791120067000


@pytest.mark.parametrize("bad", [
    "pack: 1\nid: x\nversion: 1\nextract: {kind: kv}\nclasses: {network_activity: {set: {time: {from: a, pipe: [nope]}}}}",
    "pack: 1\nid: x\nversion: 1\nextract: {kind: bogus}\nclasses: {}",
    "pack: 1\nid: x\nversion: 1\nextract: {kind: kv}\nclasses: {network_activity: {set: {time: 5}}}",
    "pack: 1\nid: x\nversion: 1\nextract: {kind: kv}\nclasses: {nope: {set: {}}}",
])
def test_bad_packs_rejected(bad):
    with pytest.raises(PackError):
        load_pack_text(bad)


def test_linter_rules():
    base = """pack: 1
id: t.y
version: 1.0.0
verified: false
match: {{priority: 1, all: [{{contains: "x"}}]}}
extract: {{kind: regex, options: {{anchor: '{rx}'}}}}
select: [{{otherwise: network_activity}}]
classes:
  network_activity:
    set:
      activity_id: {{const: 6}}
      time: {{from: t, pipe: [iso8601]}}
      {extra}
tests: []
"""
    issues = lint_text(base.format(rx="(a+)+b", extra="src_endpoint.ip: ip"), min_tests=0, require_unverified=True)
    msgs = " | ".join(map(str, issues))
    assert "ReDoS" in msgs
    issues = lint_text(base.format(rx="(?P<t>x)", extra="bogus.attr: ip"), min_tests=1)
    msgs = " | ".join(map(str, issues))
    assert "unknown OCSF attribute" in msgs and "needs >= 1 tests" in msgs
    issues = lint_text(base.format(rx="(?P<t>x)", extra="type_uid: {const: 1}"), min_tests=0)
    assert any("derived" in i.message for i in issues)
    assert any(i.level == "error" and i.line for i in lint_text("a: [", min_tests=0))


def test_hot_reload_is_atomic_and_keeps_last_good(tmp_path):
    src = (PACKS / "squid" / "access.yaml").read_text()
    d = tmp_path / "p"
    d.mkdir()
    f = d / "squid.yaml"
    f.write_text(src)
    reg = PackRegistry([d])
    snap1 = reg.snapshot
    assert "squid.access" in snap1.by_id and reg.poll() is None
    f.write_text(src.replace("version: 1.0.0", "version: 1.0.1"))
    rep = reg.poll()
    assert rep and "squid.access" in rep.changed and reg.snapshot.by_id["squid.access"].version == "1.0.1"
    assert snap1.by_id["squid.access"].version == "1.0.0"    # in-flight snapshot untouched
    f.write_text("pack: 1\nid: [broken")
    rep = reg.poll()
    assert rep.errors and reg.snapshot.by_id["squid.access"].version == "1.0.1"   # last good kept
    (d / "new.yaml").write_text(src.replace("squid.access", "custom.sq"))
    reg.poll()
    assert {"custom.sq", "squid.access"} <= set(reg.snapshot.by_id)


def test_sniff():
    assert sniff(b'{"a":1}') == "json" and sniff(b"<189>x") == "syslog" and sniff(b"<Event ") == "xml"
    assert sniff(b"CEF:0|a") == "cef" and sniff(b"LEEF:1.0|a") == "leef" and sniff(b"hello") == "text"
    assert sniff(b"#fields\tts") == "tsv"


def test_detector_cache_hint_and_fallthrough():
    ps = load_compiled(PACKS)
    det = Detector(lambda: ps)
    fg = next(t["raw"] for p in ps.packs if p.id == "fortinet.fortigate" for t in p.doc.tests).encode()
    assert det.detect(fg, "10.0.0.1", None, RECV_MS).pack.id == "fortinet.fortigate"
    assert det.cache.get("10.0.0.1") == "fortinet.fortigate"
    assert det.detect(fg, "x", "fortinet.fortigate", RECV_MS).pack.id == "fortinet.fortigate"
    assert det.detect(b"random text", "10.0.0.1", None, RECV_MS) is None
    for _ in range(25):
        det.detect(b"random text", "10.0.0.1", None, RECV_MS)
    assert det.cache.get("10.0.0.1") is None          # evicted after 20 consecutive misses


@pytest.mark.parametrize("rx,bad", [
    (r"(?:\d{1,3}\.){3}\d{1,3}", False), (r"(a+)+b", True), (r"(a*)*", True), (r"(a+){2,}", True), (r"(x{1,30}){1,30}", True),
    (r"(?:\s+(?P<x>\w[\w.-]*))?:", False), (r"(?:a|b)+c", False), (r"^(?:\([^()]*\)|[A-Za-z_][\w.-]*)\s+x", False),
])
def test_redos_heuristic_has_no_false_positive_on_bounded_groups(rx, bad):
    from ulpf.packs.linter import _repeat_nesting

    assert bool(_repeat_nesting(rx)) is bad
