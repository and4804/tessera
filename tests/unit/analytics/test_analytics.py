import pytest

from tools.loggen import generator
from ulpf.analytics import anomaly, features, findings

START = 1791118800000
WIN = 60_000


def _events():
    from pathlib import Path
    demo = Path(__file__).resolve().parents[3] / "tools" / "loggen" / "scenarios" / "demo.yaml"
    out = []
    for i, (_d, _line, rec) in enumerate(generator.generate(scenario=str(demo), seed=1337, eps=20, duration_s=1800)):
        e = dict(rec["expect"])
        e["ulpf.source_id"] = rec["source"]
        e["ulpf.raw_ref"] = f"seg1:{i}"
        out.append((e, rec.get("tag")))
    return out


def test_feature_values_on_synthetic_rows():
    ev = [{"src_endpoint.ip": "1.1.1.1", "time": START + i * 100, "class_uid": 4001, "action_id": 2, "dst_endpoint.ip": f"10.0.0.{i % 3}",
           "dst_endpoint.port": 20 + i, "traffic.bytes_out": 10} for i in range(10)]
    ev.append({"src_endpoint.ip": "1.1.1.1", "time": START + 5, "class_uid": 3002, "status_id": 2})
    ev.append({"src_endpoint.ip": "1.1.1.1", "time": START + WIN + 1, "class_uid": 4001, "action_id": 1, "dst_endpoint.ip": "9.9.9.9", "dst_endpoint.port": 53})
    w = features.build_windows(ev, engine="python")
    assert [x.window_start_ms for x in w] == [START, START + WIN]
    f = w[0].features
    assert f["conn_count"] == 10 and f["uniq_dst_ip"] == 3 and f["uniq_dst_port"] == 10
    assert f["bytes_out_sum"] == 100 and f["auth_fail_count"] == 1
    assert abs(f["deny_ratio"] - 10 / (10 + features.SMOOTH)) < 1e-9
    assert w[1].features["deny_ratio"] == 0.0


def test_nested_events_are_supported():
    nested = {"class_uid": 4001, "time": START, "src_endpoint": {"ip": "2.2.2.2"}, "dst_endpoint": {"ip": "3.3.3.3", "port": 80}, "action_id": 2}
    (w,) = features.build_windows([nested], engine="python")
    assert w.src_ip == "2.2.2.2" and w.features["uniq_dst_port"] == 1


def test_duckdb_engine_matches_python_when_available():
    pytest.importorskip("duckdb")
    evs = [e for e, _ in _events()][:5000]
    a = features.build_windows(evs, engine="python")
    b = features.build_windows(evs, engine="duckdb")
    key = lambda w: (w.src_ip, w.window_start_ms)  # noqa: E731
    assert [(key(x), x.features) for x in sorted(a, key=key)] == [(key(x), x.features) for x in sorted(b, key=key)]


def test_all_three_incidents_flagged_within_two_windows_and_baseline_fp_reported():
    pytest.importorskip("sklearn")
    evs = _events()
    W = features.build_windows([e for e, _ in evs], engine="python")
    base = [w for w in W if w.window_start_ms < START + 600_000]          # the first 10 simulated minutes are incident-free
    scored = [w for w in W if w.window_start_ms >= START + 600_000]
    flagged = [s for s in anomaly.Detector().fit(base).score(scored) if s.flagged]
    incidents = {"port_scan": ("203.0.113.50", 600), "ssh_bruteforce": ("198.51.100.77", 1080), "exfiltration": ("10.1.1.42", 1500)}
    for name, (ip, at) in incidents.items():
        hits = [s for s in flagged if s.window.src_ip == ip and START + at * 1000 - WIN <= s.window.window_start_ms <= START + at * 1000 + WIN]
        assert hits, f"{name} not flagged"
    attackers = {ip for ip, _ in incidents.values()}
    fp = [s for s in flagged if s.window.src_ip not in attackers]
    n_base = sum(1 for w in scored if w.src_ip not in attackers)
    print(f"false positives on unseen baseline windows: {len(fp)} of {n_base}")
    assert len(fp) / n_base <= 0.005


def test_findings_are_ocsf_2004_with_raw_ref_evidence():
    pytest.importorskip("sklearn")
    evs = _events()
    W = features.build_windows([e for e, _ in evs], engine="python")
    top = max(anomaly.Detector().fit(W).score(W), key=lambda s: s.score)
    f = findings.to_finding(top)
    assert f["class_uid"] == 2004 and f["type_uid"] == 200401 and f["finding_info"]["uid"]
    assert f["src_endpoint"]["ip"] == top.window.src_ip
    assert f["evidences"] and all(set(e) == {"raw_ref"} and e["raw_ref"].startswith("seg1:") for e in f["evidences"])
    assert f["finding_info"]["desc"] and f["unmapped"]["zscores"]
    assert findings.to_finding(top)["finding_info"]["uid"] == f["finding_info"]["uid"]     # stable id
