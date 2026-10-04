"""Held-out-source evaluator (step 10 of §7.11): how well does the Studio onboard sources it has never seen?

For each held-out source (MikroTik free text, Sophos-style key=value, Juniper SRX-style structured syslog) the evaluator
  1. draws N training lines from the generator (tools/loggen/heldout.py, NO shipped pack exists for any of them),
  2. runs the Studio pipeline (sniff -> mine -> infer -> suggest -> draft pack),
  3. applies the draft to N *different* lines whose true OCSF mapping is known (the hand-written truth mapping,
     verified against truth packs in tests/unit/onboard/test_heldout_truth.py),
  4. reports lines matched, field-level precision/recall against the truth, mean coverage and wall-clock time.

    python -m ulpf.onboard.evaluator [--json out.json] [--markdown out.md] [--n-train 60] [--n-test 400]

The numbers it prints are measured, not promised; they are what goes on the results slide (docs/onboarding.md).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from . import studio

SOURCES = {  # name -> (generator attr, label shown to the Studio)
    "mikrotik": ("mikrotik", "MikroTik RouterOS"),
    "sophos_kv": ("sophos_kv", "Sophos XGS"),
    "juniper_srx": ("juniper_srx", "Juniper SRX"),
}
IGNORE_TOP = {"unmapped", "ulpf", "metadata", "type_uid", "category_uid"}


def _load_generators() -> Any:
    try:
        from tools.loggen import heldout  # type: ignore[import-not-found]
        return heldout
    except ImportError:
        here = Path(__file__).resolve()
        for parent in here.parents:
            if (parent / "tools" / "loggen" / "heldout.py").exists():
                sys.path.insert(0, str(parent))
                from tools.loggen import heldout  # type: ignore[import-not-found]
                return heldout
        raise RuntimeError("held-out generators not found: run the evaluator from a repository checkout (tools/loggen/heldout.py)") from None


def _leaves(d: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(d, dict):
        for k, v in d.items():
            if not prefix and k in IGNORE_TOP:
                continue
            yield from _leaves(v, f"{prefix}.{k}" if prefix else k)
    elif d is not None:
        yield prefix, d


def evaluate_source(name: str, gen: Callable[..., Iterator[tuple[str, dict]]], label: str, n_train: int = 60, n_test: int = 400,
                    train_seed: int = 7, test_seed: int = 1007) -> dict[str, Any]:
    train = [ln for ln, _ in gen(seed=train_seed, n=n_train)]
    t0 = time.perf_counter()
    a = studio.analyze(train, label=label)
    elapsed = time.perf_counter() - t0
    test = list(gen(seed=test_seed, n=n_test))
    pv = studio.preview(a.pack, [ln for ln, _ in test], limit=n_test)
    tp = produced = truth_n = perfect = 0
    for (_ln, truth), item in zip(test, pv.events, strict=True):
        want = dict(truth)
        ev = item.get("event")
        got = dict(_leaves(ev)) if ev else {}
        if ev and ev["ulpf"]["time_quality"] == "recv_time":
            got.pop("time", None)                    # receive time is not a source timestamp
        hit = sum(1 for k, v in want.items() if k in got and got[k] == v and type(got[k]) is type(v))
        tp += hit
        produced += len(got)
        truth_n += len(want)
        perfect += int(hit == len(want) == len(got))
    prec = tp / produced if produced else 0.0
    rec = tp / truth_n if truth_n else 0.0
    return {
        "source": name, "label": label, "format": a.report["format"], "extractor": a.report["extractor"], "class": a.report["class"],
        "train_lines": n_train, "test_lines": n_test, "lines_matched_pct": pv.summary["matched_pct"],
        "field_precision": round(prec, 4), "field_recall": round(rec, 4),
        "field_f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
        "perfect_lines_pct": round(100 * perfect / n_test, 1), "coverage_mean": pv.summary["coverage_mean"],
        "fields_mapped_pct": pv.summary["fields_mapped_pct"], "unmapped_fields": pv.summary["unmapped_fields"],
        "templates": a.report["templates"], "analysis_seconds": round(elapsed, 3), "estimated_minutes": a.report["estimated_minutes"],
        "engine": "ulpf.onboard.refengine (reference interpreter)",
    }


def run_all(n_train: int = 60, n_test: int = 400) -> list[dict[str, Any]]:
    gens = _load_generators()
    return [evaluate_source(n, getattr(gens, attr), label, n_train, n_test) for n, (attr, label) in SOURCES.items()]


def to_markdown(rows: list[dict[str, Any]]) -> str:
    out = ["| Source | Format | Lines matched | Field recall | Field precision | Mean coverage | Analysis time | Est. review (min) |",
           "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['label']} | {r['format']}/{r['extractor']} | {r['lines_matched_pct']}% | {r['field_recall']:.1%} | "
                   f"{r['field_precision']:.1%} | {r['coverage_mean']:.1%} | {r['analysis_seconds']} s | {r['estimated_minutes']} |")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n-train", type=int, default=60)
    ap.add_argument("--n-test", type=int, default=400)
    ap.add_argument("--json", default=None)
    ap.add_argument("--markdown", default=None)
    a = ap.parse_args(argv)
    rows = run_all(a.n_train, a.n_test)
    md = to_markdown(rows)
    print(md)
    for r in rows:
        print(f"{r['source']}: unmapped={r['unmapped_fields']}")
    if a.json:
        Path(a.json).write_text(json.dumps(rows, indent=2))
    if a.markdown:
        Path(a.markdown).write_text(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
