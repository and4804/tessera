"""Property tests for the pack engine: arbitrary and mutated input never raises, and the lossless-mapping invariant holds."""
import hashlib
import random
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tools.loggen import generator
from ulpf.packs import PackRegistry
from ulpf.packs.testrunner import RECV_MS, make_env

PACKS = Path(__file__).resolve().parents[2] / "packs"
REG = PackRegistry([PACKS])
GOLDEN = [t["raw"].encode() for p in REG.snapshot.packs for t in p.doc.tests]


def leaves(d, prefix=""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from leaves(v, f"{prefix}{k}.")
        else:
            yield f"{prefix}{k}"


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=400))
def test_every_pack_survives_arbitrary_bytes(data):
    for p in REG.snapshot.packs:
        ctx = {"_recv_ms": RECV_MS}
        try:
            f = p.extract(data, ctx)
        except Exception as e:                       # noqa: BLE001
            raise AssertionError(f"{p.id} extract raised {e!r} on {data!r}") from e
        if f is not None:
            env, ref = make_env(data)
            for ev in p.normalize(f, env, ref, ctx):
                assert ev["ulpf"]["status"] in ("parsed", "partial")


def _mutate(b: bytes, rnd: random.Random) -> bytes:
    b = bytearray(b)
    for _ in range(rnd.randint(1, 4)):
        k = rnd.randrange(5)
        if not b:
            break
        i = rnd.randrange(len(b))
        if k == 0:
            b[i] ^= 1 << rnd.randrange(8)
        elif k == 1:
            del b[i:]
        elif k == 2:
            b[i:i] = bytes(b[i:i + 1]) * 3
        elif k == 3:
            del b[i]
        else:
            b[i:i] = b'"= '
    return bytes(b)


def test_mutated_golden_vectors_never_raise_and_stay_lossless():
    rnd = random.Random(42)
    n = 0
    for raw in GOLDEN:
        for _ in range(40):
            m = _mutate(raw, rnd)
            for p in REG.snapshot.packs:
                if not p.match(m):
                    continue
                ctx = {"_recv_ms": RECV_MS}
                f = p.extract(m, ctx)
                if f is None:
                    continue
                keys = set(f)
                env, ref = make_env(m)
                ev = p.normalize(f, env, ref, ctx)[0]
                n += 1
                assert set(ev["unmapped"]) <= keys
                assert ev["ulpf"]["coverage"] <= 1.0 and ev["ulpf"]["raw_sha256"] == hashlib.sha256(m).hexdigest()
    assert n > 200


def test_unmapped_union_consumed_ignored_equals_extracted():
    """§11 property 4: unmapped U consumed-sources U ignored == extracted, for every golden vector and generated line."""
    lines = GOLDEN + [ln.encode() for _d, ln, _r in generator.generate(
        mix="fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5", seed=9, count=1500)]
    checked = 0
    for raw in lines:
        for p in REG.snapshot.packs:
            if not p.match(raw):
                continue
            ctx = {"_recv_ms": RECV_MS}
            f = p.extract(raw, ctx)
            if f is None or not p.post_match(f):
                continue
            extracted = set(f)
            env, ref = make_env(raw)
            ev = p.normalize(dict(f), env, ref, ctx)[0]
            un, ign = set(ev["unmapped"]), set(ev["ulpf"].get("ignored", {}))
            consumed = extracted - un - ign
            assert not (un & ign)
            cls = p.classes[p.select_class({**f, **{k: v for k, v in ctx.items() if k[:1] != "_"}})]
            refs = set().union(*(s.refs for s in cls.setters)) if cls.setters else set()
            assert consumed <= refs, (p.id, consumed - refs)       # nothing vanishes without an expression that consumed it
            checked += 1
            break
    assert checked > 1000
