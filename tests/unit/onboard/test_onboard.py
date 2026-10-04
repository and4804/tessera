import json
import re
from pathlib import Path

import pytest
import yaml

from tools.loggen import heldout
from ulpf.onboard import evaluator, inferer, llm, miner, refengine, studio, suggester

ROOT = Path(__file__).resolve().parents[3]


def _mt(n=60, seed=7, syslog=False):
    return [ln for ln, _ in heldout.mikrotik(seed=seed, n=n, syslog=syslog)]


# ---------------------------------------------------------------- miner
def test_atomize_kinds():
    kinds = {k for k, _ in miner.atomize("2026-10-04 13:00:00 from 10.0.0.1 mac aa:bb:cc:dd:ee:ff port 443 (x)")}
    assert {"IP", "MAC", "NUM"} <= kinds


def test_templates_collapse_variable_parts():
    lines = [f"user u{i} logged in from 10.0.0.{i} port {1000 + i}" for i in range(30)] + [f"disk {i}% full on /dev/sda{i % 3}" for i in range(30)]
    t = miner.cluster_templates(lines)
    assert 2 <= len(t) <= 4
    assert sum(x.count for x in t) == 60


def test_synthesised_regex_matches_unseen_lines():
    train = _mt(60, 7)
    synth = miner.synthesize_regex(train)
    assert 1 <= synth.n_templates <= 6
    test = _mt(200, 99)
    hit = sum(1 for ln in test if any(miner.apply_regex(rx, ln) for rx in synth.alternatives))
    assert hit / len(test) >= 0.85


# ---------------------------------------------------------------- inferer
def test_sniff_formats():
    assert inferer.sniff(['{"a":1}'] * 5).format == "json"
    assert inferer.sniff(["CEF:0|V|P|1|1|n|3|src=1.2.3.4"] * 5).format == "cef"
    assert inferer.sniff(["a=1 b=2 c=3 d=4"] * 5).format == "kv"
    assert inferer.sniff(["<134>Oct  4 13:00:00 h a=1 b=2 c=3 d=4"] * 5).framing == "syslog"


def test_type_inference():
    assert inferer.infer_type("x", ["10.0.0.1", "8.8.8.8"])[0] == "ip"
    assert inferer.infer_type("sport", ["80", "443"])[0] == "port"
    assert inferer.infer_type("x", ["aa:bb:cc:dd:ee:ff"])[0] == "mac"
    assert inferer.infer_type("ts", ["2026-10-04T13:00:00Z"])[0:2] == ("timestamp", "iso8601")
    assert inferer.infer_type("bytes", ["10", "2000", "55"])[0] == "int"
    assert inferer.infer_type("x", [])[0] == "text"


# ---------------------------------------------------------------- suggester
def test_norm_and_aliases():
    assert suggester.norm("Source-Address") == suggester.norm("source_address") == "sourceaddress"
    al = suggester.load_aliases()
    assert "src_endpoint.ip" in al["paths"] and "action_id" in al["enums"]


def test_suggest_maps_common_names():
    lines = ["srcip=10.0.0.%d dstip=8.8.8.8 srcport=%d dstport=443 proto=tcp action=allow" % (i % 200, 40000 + i) for i in range(30)]
    a = studio.analyze(lines, label="Test Kv")
    paths = {m["ocsf_path"] for m in a.report["mapped"]}
    assert {"src_endpoint.ip", "dst_endpoint.ip", "src_endpoint.port", "dst_endpoint.port"} <= paths
    assert a.report["class"] == "network_activity"


# ---------------------------------------------------------------- studio
def test_analyze_mikrotik_draft_pack_is_valid_and_unverified():
    a = studio.analyze(_mt(), label="MikroTik RouterOS")
    doc = yaml.safe_load(a.pack_yaml)
    assert doc["verified"] is False and doc["id"].startswith("custom.")
    assert a.report["lines_matched_pct"] >= 85
    assert a.report["coverage_mean"] >= 0.8      # per-line mean; the distinct-field ratio is lower because rare variants add alt_* captures
    assert refengine.run_tests(refengine.Pack(doc)) == []
    assert "REVIEW" in a.pack_yaml.splitlines()[0]


def test_preview_reports_unparsed_lines():
    a = studio.analyze(_mt())
    pv = studio.preview(a.pack_yaml, _mt(5, 3) + ["totally different garbage line"])
    assert pv.summary["lines"] == 6 and pv.summary["status"]["unparsed"] >= 1
    with pytest.raises((ValueError, yaml.YAMLError)):
        studio.preview("{ not: [valid", ["x"])


def test_publish_is_atomic_validated_and_notifies(tmp_path):
    a = studio.analyze(_mt(), label="MikroTik RouterOS")
    seen = []
    res = studio.publish(a.pack_yaml, tmp_path, notify=lambda ch, pid: seen.append((ch, pid)))
    files = list(tmp_path.glob("*.yaml"))
    assert len(files) == 1 and not list(tmp_path.glob(".pub-*"))
    assert seen == [(studio.RELOAD_CHANNEL, yaml.safe_load(a.pack_yaml)["id"])] and res
    # the published file loads as a pack and re-passes its own tests
    p = refengine.load_pack(files[0])
    assert refengine.run_tests(p) == []


def test_publish_rejects_bad_packs(tmp_path):
    doc = yaml.safe_load(studio.analyze(_mt()).pack_yaml)
    bad = dict(doc, id="fortinet.fortigate")                       # not a custom.* id
    with pytest.raises(ValueError):
        studio.publish(yaml.safe_dump(bad), tmp_path)
    bad2 = dict(doc, id="custom.../../etc")                         # path traversal
    with pytest.raises(ValueError):
        studio.publish(yaml.safe_dump(bad2), tmp_path)
    bad3 = json.loads(json.dumps(doc))
    bad3["tests"][0]["expect"]["class_uid"] = 999                   # failing golden vector
    with pytest.raises(ValueError):
        studio.publish(yaml.safe_dump(bad3), tmp_path)
    assert not list(tmp_path.iterdir())


# ---------------------------------------------------------------- evaluator
def test_heldout_evaluation_meets_target():
    rows = []
    for name, gen, label in (("mikrotik", heldout.mikrotik, "MikroTik RouterOS"), ("sophos_kv", heldout.sophos_kv, "Sophos"),
                             ("juniper_srx", heldout.juniper_srx, "Juniper SRX")):
        r = evaluator.evaluate_source(name, gen, label, n_train=60, n_test=200)
        assert r["field_recall"] >= 0.85, (name, r["field_recall"])
        assert r["lines_matched_pct"] >= 90, name
        rows.append(r)
    assert evaluator.to_markdown(rows).count("\n") == 5


# ---------------------------------------------------------------- llm assist
def _draft():
    return studio.analyze(_mt(), label="MikroTik RouterOS")


def test_llm_disabled_by_default_and_never_calls_transport():
    called = []
    a = llm.LLMAssist(transport=lambda *x: called.append(x) or {})
    assert a.enabled is False
    out = a.assist(_draft().pack, _mt())
    assert not out.accepted and out.reason == "llm disabled" and not called
    assert llm.LLMAssist.from_config({}).enabled is False
    assert yaml.safe_load((ROOT / "configs" / "ulpf.yaml").read_text())["onboard"]["llm"]["enabled"] is False


def test_endpoint_guard():
    for ok in ("http://ollama:11434", "http://localhost:11434", "http://127.0.0.1:1", "http://10.1.2.3:11434", "http://192.168.1.5"):
        assert llm.check_endpoint(ok) == ok
    for bad in ("http://example.com", "https://api.openai.com", "http://8.8.8.8", "http://foo.bar.local", "ftp://ollama", "http://"):
        with pytest.raises(llm.EndpointError):
            llm.check_endpoint(bad)


def test_remote_endpoint_never_reaches_transport():
    called = []
    a = llm.LLMAssist(enabled=True, endpoint="http://example.com", transport=lambda *x: called.append(x) or {})
    out = a.assist(_draft().pack, _mt())
    assert not out.accepted and not called and "unavailable" in out.reason


def test_patch_rejected_when_tests_fail_or_coverage_not_raised():
    pack, lines = _draft().pack, _mt()
    cls = next(iter(pack["classes"]))
    # a no-op patch cannot raise coverage
    o = llm.evaluate_patch(pack, {"meta": {"note": "x"}}, lines)
    assert not o.accepted and "did not increase" in o.reason
    # a patch that makes golden vectors fail is rejected
    broken = {"classes": {cls: {"set": {"dst_endpoint.ip": {"const": "9.9.9.9"}}}}}
    o = llm.evaluate_patch(pack, broken, lines)
    assert not o.accepted
    # garbage patches are rejections, not crashes
    assert not llm.evaluate_patch(pack, {"extract": {"kind": "nope"}}, lines).accepted


def test_patch_cannot_rename_or_self_verify():
    pack = _draft().pack
    out = llm.apply_patch(pack, {"id": "evil", "verified": True, "meta": {"a": 1}})
    assert out["id"] == pack["id"] and out["verified"] is False


def test_accepts_patch_only_when_coverage_strictly_increases():
    pack, lines = _draft().pack, _mt()
    pv = studio.preview(pack, lines, limit=0).summary
    if not pv["unmapped_fields"]:
        pytest.skip("draft already maps everything")
    cls = next(iter(pack["classes"]))
    field = pv["unmapped_fields"][0]
    patch = {"classes": {cls: {"set": {"unmapped_probe": {"from": field}}}}}
    # an unknown OCSF path may or may not lint; the contract is: accepted implies lint+tests clean and coverage up
    o = llm.evaluate_patch(pack, patch, lines)
    if o.accepted:
        assert o.after > o.before
        assert refengine.run_tests(refengine.Pack(o.pack)) == []
    else:
        assert o.pack == pack


def test_assist_end_to_end_with_fake_transport_rejects_useless_reply():
    pack, lines = _draft().pack, _mt()
    sent = []

    def transport(url, body, timeout):
        sent.append(url)
        return {"response": '{"meta": {"note": "no change"}}'}

    out = llm.LLMAssist(enabled=True, endpoint="http://ollama:11434", transport=transport).assist(pack, lines)
    assert sent == ["http://ollama:11434/api/generate"] and not out.accepted and out.pack == pack


def test_useful_patch_is_accepted_and_applied():
    pack, lines = _draft().pack, _mt()
    cls = next(iter(pack["classes"]))
    unm = studio.preview(pack, lines, limit=0).summary["unmapped_fields"]
    assert "proto_detail" in unm
    patch = {"classes": {cls: {"set": {"message": {"from": "proto_detail"}}}}}
    o = llm.LLMAssist(enabled=True, endpoint="http://ollama:11434",
                      transport=lambda u, b, t: {"response": "Sure!\n" + json.dumps(patch)}).assist(pack, lines)
    assert o.accepted, o.reason
    assert o.after > o.before and "message" in o.pack["classes"][cls]["set"]
    assert pack["classes"][cls]["set"].get("message") is None      # original draft untouched


# ---------------------------------------------------------------- miner quality (MikroTik: rare NAT variant, optional rule prefix)
def test_rare_keyword_variant_keeps_its_keyword_literal_and_names_are_not_alt():
    """`NAT` occurs in ~5% of lines. It is structure, not a value: it must not become a variable group, and no positional `alt_N` names appear."""
    s = miner.synthesize_regex(_mt(60, 7))
    assert not [f for f in s.fields if f.startswith("alt_")], s.fields
    assert any("NAT" in rx for rx in s.alternatives)


def test_optional_rule_prefix_does_not_swallow_the_chain():
    """`firewall,info [RULE] forward:`: the optional token is the rule, the token before ':' is always the chain."""
    a = studio.analyze(_mt(60, 7), label="MikroTik RouterOS")
    pv = studio.preview(a.pack, _mt(200, 1007), limit=200)
    with_dir = sum(1 for it in pv.events if it.get("event") and it["event"].get("connection_info", {}).get("direction_id") in (1, 2, 3))
    assert with_dir >= 190, with_dir


def test_mikrotik_held_out_quality_floor():
    """Floors set just under the measured values (before the miner fixes: matched 94.5, recall 90.6, coverage 83.2, fields mapped 52.6).
    The 85% *fields mapped* target is NOT met: the NAT clause, the rule name and TCP flags have no OCSF mapping in the draft."""
    r = evaluator.evaluate_source("mikrotik", heldout.mikrotik, "MikroTik RouterOS", n_train=60, n_test=400)
    assert r["lines_matched_pct"] >= 97, r["lines_matched_pct"]
    assert r["field_recall"] >= 0.96, r["field_recall"]
    assert r["coverage_mean"] >= 0.85, r["coverage_mean"]
    assert r["fields_mapped_pct"] >= 55, r["fields_mapped_pct"]
    assert not [f for f in r["unmapped_fields"] if f.startswith("alt_")]


def test_variable_slots_are_not_promoted_to_keywords():
    """`proto UDP`, rule names and chains share their slot with other words and must stay variables."""
    s = miner.synthesize_regex(_mt(200, 7))
    joined = " ".join(s.alternatives)
    for w in ("UDP", "TCP", "ICMP", "forward", "input", "output"):
        assert not re.search(rf"\\s+{w}[\\s:,)]", joined), w
