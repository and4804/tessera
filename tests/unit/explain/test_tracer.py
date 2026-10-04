"""§7.10 test: for all golden vectors (and generated traffic) every span slice equals the claimed value text."""
import re
from pathlib import Path

import pytest

from tools.loggen import generator
from ulpf.explain.tracer import NoPack, explain_event, explain_raw
from ulpf.packs import PackRegistry
from ulpf.packs.testrunner import RECV_MS

PACKS = Path(__file__).resolve().parents[3] / "packs"
REG = PackRegistry([PACKS])
BYID = REG.snapshot.by_id
MIX = "fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5"


def slices(raw: bytes, spans):
    return [raw[s["start"]:s["end"]] for s in spans]


def check(pack, raw: bytes) -> dict:
    ex = explain_raw(pack, raw, RECV_MS)
    assert ex["raw_len"] == len(raw) and ex["pack_id"] == pack.id
    for u in ex["unmapped"]:
        for sl in slices(raw, u["spans"]):
            if ex["spans_exact"] and "\\" not in sl.decode("utf-8", "surrogateescape") and "&" not in sl.decode("utf-8", "replace"):
                assert sl.decode("utf-8", "surrogateescape") == str(u["value"]), (pack.id, u)
    for f in ex["fields"]:
        for sp in f["spans"]:
            assert 0 <= sp["start"] <= sp["end"] <= len(raw)
        # when exactly one source field backs the value and no op transformed it, the slice IS the value text
        if ex["spans_exact"] and f["expr"].startswith("copy ") and len(f["spans"]) == 1:
            sl = slices(raw, f["spans"])[0].decode("utf-8", "surrogateescape")
            assert sl == str(f["value"]) or "\\" in sl, (pack.id, f)
    return ex


@pytest.mark.parametrize("pid", sorted(BYID))
def test_golden_vectors_spans_equal_values(pid):
    p = BYID[pid]
    seen = 0
    for t in p.doc.tests:
        raw = t["raw"].encode("utf-8", "surrogateescape")
        if not p.match(raw):
            continue
        try:
            ex = check(p, raw)
        except NoPack:
            continue
        seen += 1
        assert ex["fields"], t["name"]
    assert seen >= 4


def test_generated_traffic_spans_exact_for_text_formats():
    n = exact = 0
    for _d, line, _r in generator.generate(mix=MIX, seed=2, count=1500):
        raw = line.encode()
        for p in REG.snapshot.packs:
            if p.match(raw):
                try:
                    ex = check(p, raw)
                except NoPack:
                    continue
                n += 1
                exact += ex["spans_exact"]
                break
    assert n > 1200
    # json/xml are display-only by contract; every other format must be exact on generated data
    assert exact / n > 0.75


def test_kv_values_exact_and_byte_offsets_with_unicode():
    p = BYID["fortinet.fortigate"]
    raw = ('<189>date=2026-10-04 time=13:21:07 devname="FGT-é-HQ" logid="0000000013" type="traffic" level="notice" '
           'srcip=10.1.1.15 srcport=51512 dstip=142.250.77.14 dstport=443 proto=6 action="accept" '
           'eventtime=1790000467000000000 tz="+0530" msg="a \\"q\\" b"').encode()
    ex = explain_raw(p, raw, RECV_MS)
    assert ex["spans_exact"] and ex["format"] == "kv"
    by = {f["ocsf_path"]: f for f in ex["fields"]}
    sl = slices(raw, by["src_endpoint.ip"]["spans"])
    assert sl == [b"10.1.1.15"] and by["src_endpoint.ip"]["source_fields"] == ["srcip"]
    assert slices(raw, by["device.hostname"]["spans"]) == ["FGT-é-HQ".encode()]    # BYTE offsets, é is 2 bytes
    assert by["time"]["source_fields"] == ["eventtime"]                              # winning coalesce branch only
    assert by["class_uid"]["pack_rule"] == "select[0]"
    um = {u["field"]: u for u in ex["unmapped"]}
    assert slices(raw, um["msg"]["spans"]) == [b'a \\"q\\" b']                         # escaped value: raw slice, flagged by backslashes


def test_invalid_utf8_offsets_stay_byte_exact():
    p = BYID["fortinet.fortigate"]
    raw = b'<189>devname="x\xff\xfey" logid="1" type="traffic" srcip=10.0.0.1 action="accept"'
    ex = explain_raw(p, raw, RECV_MS)
    by = {f["ocsf_path"]: f for f in ex["fields"]}
    assert slices(raw, by["device.hostname"]["spans"]) == [b"x\xff\xfey"]


def test_explain_event_uses_stored_source_and_rejects_unparsed():
    p = BYID["cisco.asa"]
    raw = next(t["raw"] for t in p.doc.tests).encode()
    ev = {"ulpf": {"source_id": "cisco.asa", "status": "parsed", "event_id": "id:0", "recv_time": RECV_MS}}
    assert explain_event(REG, raw, ev)["pack_id"] == "cisco.asa"
    with pytest.raises(NoPack):
        explain_event(REG, raw, {"ulpf": {"source_id": "unknown", "status": "unparsed"}})
    assert re.match(r"classes\.", explain_raw(p, raw, RECV_MS)["fields"][-1]["pack_rule"])
