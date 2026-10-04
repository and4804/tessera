"""Production engine (ulpf.packs/detect/normalize) vs the reference interpreter (ulpf.onboard.refengine) vs loggen ground truth.

Agreement is checked on every golden vector and on generated traffic from all nine loggen formats. Known, documented divergences
(docs/pack-dsl.md "Reconciliation") are normalised away explicitly below; anything else is a failure."""
import hashlib
import json
from pathlib import Path

import pytest

from tools.loggen import accuracy, generator
from ulpf.detect import Detector
from ulpf.model.envelope import RawEnvelope
from ulpf.model.lineage import VaultRef
from ulpf.onboard import refengine
from ulpf.packs import PackRegistry
from ulpf.packs.testrunner import RECV_MS
from ulpf.pipeline import Router, UnparsedLane

PACKS = Path(__file__).resolve().parents[2] / "packs"
MIX = "fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5"


@pytest.fixture(scope="module")
def prod():
    reg = PackRegistry([PACKS])
    assert not reg.errors
    return Router(Detector(lambda: reg.snapshot), UnparsedLane("t"))


def run_prod(router: Router, data: bytes, key: str = "k") -> dict:
    env = RawEnvelope("00000000-0000-7000-8000-000000000000", RECV_MS * 1_000_000, "n1", "replay", key, 0, data)
    ref = VaultRef("n1-000001", 0, 0, hashlib.sha256(data).hexdigest())
    return router.route(env, ref)[0]


def body(ev: dict) -> dict:
    d = {k: v for k, v in ev.items() if k not in ("ulpf", "metadata", "message")}
    d["original_time"] = ev.get("metadata", {}).get("original_time")
    u = ev["ulpf"]
    d["_status"], d["_tq"] = u["status"], u.get("time_quality")
    return d


def test_every_golden_vector_agrees(prod):
    ref = refengine.load_packs(PACKS)
    bad = []
    n = 0
    for p in ref:
        for t in p.doc["tests"]:
            raw = t["raw"].encode("utf-8", "surrogateescape")
            a, b = refengine.process_raw(ref, raw), run_prod(prod, raw, p.id)
            n += 1
            if a["ulpf"]["status"] == "unparsed":
                continue
            if body(a) != body(b) or a["ulpf"]["source_id"] != b["ulpf"]["source_id"]:
                bad.append((p.id, t["name"], body(a), body(b)))
    assert n > 50 and bad == []


def test_generated_traffic_agrees_and_meets_accuracy(prod):
    ref = refengine.load_packs(PACKS)
    pairs, diffs = [], []
    for _dev, line, rec in generator.generate(mix=MIX, seed=5, count=4000):
        raw = line.encode()
        b = run_prod(prod, raw, rec["source"])
        a = refengine.process_raw(ref, raw)
        if body(a) != body(b):
            diffs.append((line, body(a), body(b)))
        pairs.append((rec, b))
    assert diffs == [], diffs[:2]
    res = accuracy.score(pairs)
    for k, r in res.items():
        assert r["precision"] >= 0.99 and r["recall"] >= 0.99, (k, json.dumps(r))
