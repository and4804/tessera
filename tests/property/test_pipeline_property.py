"""Guide section 11 properties 1 and 3 through the FULL pipeline (publisher -> bus -> worker -> vault -> detect/extract/normalize -> sinks):

(1) arbitrary bytes never raise and every input ends in exactly one terminal state with a raw ref that resolves to those exact bytes;
(3) valid logs mutated by byte flips, truncation, duplicated delimiters and splices never crash and never silently disappear.
"""
import collections
import hashlib
from pathlib import Path

import duckdb
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tools.loggen import generator
from ulpf.bus import MemoryBus
from ulpf.config import Config
from ulpf.ingest import Publisher
from ulpf.packs import PackRegistry
from ulpf.pipeline import MemoryClusterStore, Worker, backlog, make_tail, report
from ulpf.vault import VaultReader, verify_all

PACKS = Path(__file__).resolve().parents[2] / "packs"
REG = PackRegistry([PACKS])
VALID = [ln.encode() for _d, ln, _r in generator.generate(
    mix="fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5", seed=21, count=300)]
GOLDEN = [t["raw"].encode() for p in REG.snapshot.packs for t in p.doc.tests]
SEEDS = VALID + GOLDEN
DELIMS = [b" ", b"=", b'"', b",", b"|", b"\t", b":", b"{", b"}", b"<", b">", b"\\", b"\x00", b"\n", b"\r", b"%ASA-", b"CEF:0|", b"devname="]


def run_pipeline(tmp: Path, blobs: list[bytes]):
    cfg = Config().rebase(tmp)
    cfg.vault.signing_key = None
    cfg.sinks.parquet.flush_secs = 0.1
    cfg.sinks.jsonl.enabled = True
    cfg.pipeline.sample_validate = 1
    cfg.bus.partitions = 4
    bus = MemoryBus(4)
    w = Worker(cfg, bus, REG, 0, 1, tail=make_tail(bus), cluster_store=MemoryClusterStore(), shard=False)
    pub = Publisher(bus, cfg.node_id)
    for i, b in enumerate(blobs):
        pub.ingest(b, "udp", f"10.0.0.{i % 7}", 514)
    pub.flush()
    w.drain()                     # must not raise
    w.close()
    return cfg, bus


def assert_terminal_and_durable(tmp: Path, cfg, bus, blobs: list[bytes]) -> None:
    led = report(bus.ledger.snapshot(), backlog(bus), 0)
    t = led["totals"]
    assert t["ingested"] == t["vaulted"] == t["sunk"] == len(blobs) and led["conserved"] and t["dropped"] == 0
    assert t["normalized_parsed"] + t["normalized_partial"] + t["unparsed"] == len(blobs)
    rows = duckdb.sql(f"select raw_ref, raw_sha256, status, event_id from read_parquet('{tmp}/lake/**/*.parquet', hive_partitioning=false)").fetchall()
    assert len(rows) == len(blobs) and len({r[3] for r in rows}) == len(blobs)
    assert {r[2] for r in rows} <= {"parsed", "partial", "unparsed"}
    rd = VaultReader(cfg.vault.dir)
    got = collections.Counter()
    for ref, sha, _s, _e in rows:
        data = rd.read(ref)                           # raises IntegrityError on a hash mismatch
        assert hashlib.sha256(data).hexdigest() == sha
        got[data] += 1
    assert got == collections.Counter(blobs)          # byte-exact: nothing lost, nothing altered
    assert all(r.ok for r in verify_all(cfg.vault.dir))
    n_jsonl = sum(len(p.read_bytes().splitlines()) for p in (tmp / "out").glob("*.jsonl"))
    assert n_jsonl == len(blobs)


SETTINGS = settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])


@SETTINGS
@given(st.lists(st.binary(max_size=400), min_size=1, max_size=15))
def test_arbitrary_bytes_terminal_state_and_byte_exact_raw(tmp_path_factory, blobs):
    tmp = tmp_path_factory.mktemp("arb")
    cfg, bus = run_pipeline(tmp, blobs)
    assert_terminal_and_durable(tmp, cfg, bus, blobs)


@SETTINGS
@given(st.lists(st.sampled_from(DELIMS + [b"10.1.1.1", b"-1", b"99999999999999999999", b"\xff\xfe", b"\xc3("]), min_size=1, max_size=40).map(b"".join))
def test_delimiter_soup_never_crashes(tmp_path_factory, blob):
    tmp = tmp_path_factory.mktemp("soup")
    cfg, bus = run_pipeline(tmp, [blob])
    assert_terminal_and_durable(tmp, cfg, bus, [blob])


@st.composite
def mutated(draw):
    base = bytearray(draw(st.sampled_from(SEEDS)))
    for _ in range(draw(st.integers(1, 5))):
        op = draw(st.sampled_from(["flip", "truncate", "dup_delim", "insert", "delete", "splice", "swap_case"]))
        if not base:
            break
        i = draw(st.integers(0, len(base) - 1))
        if op == "flip":
            base[i] ^= 1 << draw(st.integers(0, 7))
        elif op == "truncate":
            del base[i:]
        elif op == "dup_delim":
            d = draw(st.sampled_from(DELIMS))
            base[i:i] = d * draw(st.integers(2, 6))
        elif op == "insert":
            base[i:i] = draw(st.binary(min_size=1, max_size=8))
        elif op == "delete":
            del base[i:i + draw(st.integers(1, 10))]
        elif op == "splice":
            other = draw(st.sampled_from(SEEDS))
            base[i:] = other[draw(st.integers(0, len(other) - 1)):]
        else:
            base[i:i + 12] = bytes(base[i:i + 12]).swapcase()
    return bytes(base)


@SETTINGS
@given(st.lists(mutated(), min_size=1, max_size=12))
def test_mutated_valid_logs_never_crash_never_vanish(tmp_path_factory, blobs):
    tmp = tmp_path_factory.mktemp("mut")
    cfg, bus = run_pipeline(tmp, blobs)
    assert_terminal_and_durable(tmp, cfg, bus, blobs)


def test_valid_logs_stay_parsed_and_unmutated_seed_corpus_is_conserved(tmp_path):
    """Control: the unmutated seeds are conserved and overwhelmingly parsed, so the mutation tests are meaningful."""
    cfg, bus = run_pipeline(tmp_path, VALID)
    assert_terminal_and_durable(tmp_path, cfg, bus, VALID)
    t = report(bus.ledger.snapshot(), backlog(bus), 0)["totals"]
    assert t["normalized_parsed"] >= 0.99 * len(VALID)
