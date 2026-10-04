"""loggen ground truth vs the reference engine. SELF-CONSISTENCY only: both sides encode the same reading of each vendor format (R12)."""
import json
from pathlib import Path

from tools.loggen import accuracy, generator
from ulpf.onboard import refengine

PACKS = Path(__file__).resolve().parents[2] / "packs"


def test_field_precision_recall_at_least_99pct():
    packs = refengine.load_packs(PACKS)
    mix = "fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5"
    pairs = [(rec, refengine.process_raw(packs, line.encode())) for _dev, line, rec in generator.generate(mix=mix, seed=3, count=3000)]
    res = accuracy.score(pairs)
    assert set(res) >= {"fortigate", "asa", "suricata", "cef", "pfsense", "squid", "zeek", "leef", "dnsmasq", "ALL"}
    for k, r in res.items():
        assert r["precision"] >= 0.99 and r["recall"] >= 0.99, (k, json.dumps(r))
