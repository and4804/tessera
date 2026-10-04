"""Per-stage micro-benchmarks as regression gates (section 9 budgets, section 11 'Perf').

Each stage must stay above a floor set at roughly 20-40% of what this class of machine measures when idle (2 shared vCPUs, see docs/benchmarks.md), so
an accidental per-event compile, O(n^2) or sync call fails the gate while ordinary VM noise does not. Rates are best-of-3 to cut noise."""
import time
from pathlib import Path

from tools.loggen import generator
from ulpf.detect import Detector
from ulpf.packs import PackRegistry
from ulpf.packs.testrunner import make_env
from ulpf.vault import VaultWriter

ROOT = Path(__file__).resolve().parents[2]
MIX = "fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10"
N = 15_000
FLOORS = {"vault_append": 100_000, "detect_extract": 8_000, "normalize": 8_000}      # events/s; vault floor is the WP-A acceptance criterion
LINES = [(f"10.0.{i % 6}.{(i // 6) % 40}", ln.encode()) for i, (_d, ln, _r) in enumerate(generator.generate(mix=MIX, seed=5, count=N))]


def best_of(fn, runs=3):
    best = 0.0
    for _ in range(runs):
        t0 = time.perf_counter()
        n = fn()
        best = max(best, n / (time.perf_counter() - t0))
    return best


def test_vault_append_rate(tmp_path):
    k = [0]

    def run():
        k[0] += 1
        w = VaultWriter(tmp_path / f"v{k[0]}", "n1", block_events=1000, block_max_ms=10_000, fsync=True)
        for i, (_p, d) in enumerate(LINES):
            w.append("id", i, "udp", "1.1.1.1", 1, d)
        w.flush()
        w.close()
        return len(LINES)

    eps = best_of(run)
    assert eps >= FLOORS["vault_append"], f"vault append {eps:,.0f}/s < {FLOORS['vault_append']:,}/s"


def test_detect_and_extract_rate():
    reg = PackRegistry([ROOT / "packs"])

    def run():
        det = Detector(lambda: reg.snapshot)
        hit = 0
        for key, d in LINES:
            hit += det.detect(d, key, None, 1_790_000_000_000) is not None
        assert hit >= 0.99 * len(LINES)
        return len(LINES)

    eps = best_of(run)
    assert eps >= FLOORS["detect_extract"], f"detect+extract {eps:,.0f}/s < {FLOORS['detect_extract']:,}/s"


def test_normalize_rate():
    reg = PackRegistry([ROOT / "packs"])
    det = Detector(lambda: reg.snapshot)
    dets = [(d, det.detect(d, k, None, 1_790_000_000_000)) for k, d in LINES]
    assert all(x for _d, x in dets)
    envs = [make_env(d) for d, _x in dets]

    def run():
        for (_d, x), (env, ref) in zip(dets, envs):
            x.pack.normalize(dict(x.fields), env, ref, x.ctx)
        return len(dets)

    eps = best_of(run)
    assert eps >= FLOORS["normalize"], f"normalize {eps:,.0f}/s < {FLOORS['normalize']:,}/s"
