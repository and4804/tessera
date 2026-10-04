import random

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ulpf.vault import VaultReader, VaultWriter, verify_all


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(st.binary(max_size=2000), min_size=1, max_size=120), st.integers(1, 20))
def test_roundtrip_any_bytes(tmp_path_factory, items, block_events):
    root = tmp_path_factory.mktemp("v")
    w = VaultWriter(root, "n1", block_events=block_events, block_max_ms=10_000, fsync=False)
    refs = [w.append(f"id{i}", i, "tcp", "1.2.3.4", 1, d) for i, d in enumerate(items)]
    w.close()
    r = VaultReader(root)
    assert [r.read(x) for x in refs] == items
    reps = list(verify_all(root))
    assert all(x.ok for x in reps) and sum(x.n_events for x in reps) == len(items)


def test_roundtrip_100k_random_including_invalid_utf8(tmp_path):
    rnd = random.Random(7)
    items = [rnd.randbytes(rnd.choice((0, 1, 7, 40, 200, 900))) for _ in range(100_000)]
    w = VaultWriter(tmp_path / "v", "n1", block_events=1000, block_max_ms=10_000, fsync=False, segment_max_mb=8)
    refs = [w.append("i", i, "udp", "", 0, d) for i, d in enumerate(items)]
    w.close()
    r = VaultReader(tmp_path / "v")
    for ref, d in zip(refs, items):
        assert r.read(ref) == d
    reps = list(verify_all(tmp_path / "v"))
    assert len(reps) > 1 and all(x.ok and x.sealed for x in reps)
    assert sum(x.frames_checked for x in reps) == 100_000
