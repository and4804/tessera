"""Field-level precision/recall of normalized events vs loggen ground truth.

  python -m tools.loggen.accuracy --log demo.log --events normalized.jsonl      # events produced by ulpf (OCSF JSONL, same order)
  python -m tools.loggen.accuracy --log demo.log --reference-engine --packs packs  # use tools/packref (no ulpf needed)

Comparison rules: leaf (dotted path, value) pairs; derived/lineage fields are ignored (type_uid, category_uid, metadata.* except
metadata.original_time, unmapped.*, ulpf.*); `time` is skipped for sources whose timestamp has no year/zone (truth flag assumed_time).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from collections.abc import Iterable, Iterator
from typing import Any

IGNORE_PREFIX = ("unmapped", "ulpf", "metadata", "message")
IGNORE_EXACT = {"type_uid", "category_uid"}
KEEP = {"metadata.original_time"}


def flatten(d: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(d, dict):
        for k, v in d.items():
            yield from flatten(v, f"{prefix}.{k}" if prefix else k)
    else:
        yield prefix, d


def comparable(ev: dict) -> dict[str, Any]:
    out = {}
    for p, v in flatten(ev):
        if p in IGNORE_EXACT or (p not in KEEP and p.split(".")[0] in IGNORE_PREFIX) or v is None:
            continue
        out[p] = v
    return out


def score(pairs: Iterable[tuple[dict, dict]]) -> dict[str, dict[str, float]]:
    """pairs: (truth_record, event). Returns per-source and 'ALL' precision/recall/f1 + counts."""
    acc: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0, 0])  # tp, produced, truth, lines, perfect_lines
    for rec, ev in pairs:
        want = dict(rec["expect"])
        got = comparable(ev)
        if rec.get("assumed_time"):
            want.pop("time", None)
            got.pop("time", None)
        tp = sum(1 for k, v in want.items() if k in got and got[k] == v and type(got[k]) is type(v))
        for key in (rec["source"], "ALL"):
            a = acc[key]
            a[0] += tp
            a[1] += len(got)
            a[2] += len(want)
            a[3] += 1
            a[4] += int(tp == len(want) == len(got))
    out = {}
    for k, (tp, prod, tru, n, perfect) in acc.items():
        p = tp / prod if prod else 1.0
        r = tp / tru if tru else 1.0
        out[k] = {"precision": p, "recall": r, "f1": (2 * p * r / (p + r)) if p + r else 0.0, "lines": n, "perfect_lines": perfect}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--truth", default=None)
    ap.add_argument("--events", default=None, help="normalized OCSF JSONL in the same order as the log")
    ap.add_argument("--reference-engine", action="store_true")
    ap.add_argument("--packs", default="packs")
    ap.add_argument("--min", type=float, default=0.99)
    a = ap.parse_args(argv)
    truth_path = a.truth or a.log + ".truth.jsonl"

    def pairs():
        with open(truth_path) as tf, open(a.log, "rb") as lf:
            evs = open(a.events) if a.events else None
            packs = None
            if a.reference_engine:
                from tools import packref
                packs = packref.load_packs(a.packs)
            for t, line in zip(tf, lf, strict=True):
                rec = json.loads(t)
                if packs is not None:
                    ev = packref.process_raw(packs, line.rstrip(b"\n"))
                else:
                    ev = json.loads(next(evs))
                yield rec, ev

    res = score(pairs())
    ok = True
    for k in sorted(res, key=lambda x: (x != "ALL", x)):
        r = res[k]
        flag = "" if min(r["precision"], r["recall"]) >= a.min else "  <-- below target"
        ok &= not flag
        print(f"{k:10s} lines={r['lines']:8d} precision={r['precision']:.4f} recall={r['recall']:.4f} f1={r['f1']:.4f} perfect={r['perfect_lines']}{flag}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
