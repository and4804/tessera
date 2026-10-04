"""Conservation, ground-truth accuracy and tamper detection through the real pipeline (Redis Streams, worker processes, vault, Parquet).

Default 100k events (guide section 11 "Integration"); set ULPF_SCALE_N=1000000 for the section 1.2 run:
    ULPF_SCALE_N=1000000 pytest tests/integration/test_scale.py -s
The harness lives in tools/bench/scale.py and can also be run directly (python -m tools.bench.scale --n 1000000).
Worker processes are spawned, so the in-process egress guard does not cover them; they only talk to the loopback Redis.
"""
import os

import pytest

from tools.bench.scale import run_scale

N = int(os.environ.get("ULPF_SCALE_N", "100000"))


@pytest.fixture(scope="module")
def scale(redis_url, tmp_path_factory):
    return run_scale(N, 2, redis_url, tmp_path_factory.mktemp("scale"), seed=1, junk_every=500, jsonl=N <= 200_000, tamper=True)


def test_conservation_every_stage_zero_lost(scale):
    c, t = scale["conservation"], scale["ledger"]["totals"]
    assert t["ingested"] == t["vaulted"] == t["sunk"] == N
    assert t["normalized_parsed"] + t["normalized_partial"] + t["unparsed"] == N
    assert t["dropped"] == 0 and scale["ledger"]["lost"] == 0 and scale["ledger"]["conserved"] and scale["ledger"]["drained"]
    assert c["lake_rows"] == c["lake_distinct_event_id"] == c["lake_distinct_raw_ref"] == c["vault_frames"] == N
    assert c["vault_all_ok"] and c["vault_refs_equal_lake_refs"]
    assert c["lake_sha_multiset_equals_input"] and c["vault_sha_multiset_equals_input"]
    assert scale["conservation_ok"]


def test_parse_rate_on_clean_lines_at_least_99pct(scale):
    assert scale["clean_parse_rate"] >= 0.99, scale["clean_status_by_source"]


def test_ground_truth_precision_and_recall_at_least_99pct_per_vendor_and_overall(scale):
    acc = scale["accuracy"]
    assert set(acc) >= {"fortigate", "asa", "suricata", "cef", "pfsense", "squid", "zeek", "leef", "dnsmasq", "ALL"}
    for k, r in acc.items():
        assert r["precision"] >= 0.99 and r["recall"] >= 0.99, (k, r)


def test_tamper_pinpointed_and_error_confined_to_the_tampered_block(scale):
    t = scale["tamper"]
    assert scale["tamper_ok"], t
    assert t["cli_exit"] == 1 and t["verify_error"]["segment"] == t["flipped"]["segment"] and t["verify_error"]["block"] == t["flipped"]["block"]
    assert t["reads_failed"] <= t["flipped"]["n_frames"] and t["reads_ok"] + t["reads_failed"] == N
    if t["flipped"]["kind"] != "metadata_only":          # raw bytes changed or block undecodable: those events (only) fail their raw read
        assert t["reads_failed"] > 0
        assert t["http"]["victim_raw"][1] is False and t["http"]["victim_explain"][0] == 409
    assert t["http"]["bystander_raw"][1] is True
