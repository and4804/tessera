"""IsolationForest over per-(src_ip, window) features with per-feature z-score explanations (§7.12)."""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field

from .features import FEATURES, Window


@dataclass
class Scored:
    window: Window
    score: float                       # higher = more anomalous, in [0, 1]
    flagged: bool
    zscores: dict[str, float] = field(default_factory=dict)
    top: list[tuple[str, float]] = field(default_factory=list)


def _vec(w: Window) -> list[float]:
    # log1p tames heavy tails (bytes, counts) so a few giant windows do not dominate the splits.
    return [math.log1p(w.features[f]) if f != "deny_ratio" else w.features[f] for f in FEATURES]


_FLOOR = [0.5, 0.5, 0.5, 0.15, 0.75, 0.5, 0.5]     # per-feature scale floors, same order as FEATURES


class Detector:
    def __init__(self, contamination: float = 0.005, n_estimators: int = 200, seed: int = 7, z_min: float = 4.0, z_hard: float = 7.0) -> None:
        self.contamination, self.n_estimators, self.seed, self.z_min, self.z_hard = contamination, n_estimators, seed, z_min, z_hard
        self.model = None
        self.mu: list[float] = []
        self.sd: list[float] = []
        self.threshold = 0.0

    def fit(self, windows: list[Window]) -> Detector:
        from sklearn.ensemble import IsolationForest  # allowlisted dependency (§4)
        X = [_vec(w) for w in windows]
        # robust centre/scale (median, 1.4826*MAD) with a floor so a near-constant baseline cannot make 1 event look huge
        cols = list(zip(*X, strict=True))
        self.mu = [statistics.median(c) for c in cols]
        self.sd = [max(1.4826 * statistics.median([abs(v - m) for v in c]), fl) for c, m, fl in zip(cols, self.mu, _FLOOR, strict=True)]
        self.model = IsolationForest(n_estimators=self.n_estimators, contamination="auto", random_state=self.seed).fit(X)
        s = sorted(-self.model.score_samples(X))
        k = max(0, min(len(s) - 1, int(len(s) * (1 - self.contamination))))
        self.threshold = s[k]
        return self

    def score(self, windows: list[Window]) -> list[Scored]:
        if self.model is None:
            raise RuntimeError("fit() first")
        X = [_vec(w) for w in windows]
        raw = -self.model.score_samples(X)
        out = []
        for w, x, s in zip(windows, X, raw, strict=True):
            z = {f: (v - m) / d for f, v, m, d in zip(FEATURES, x, self.mu, self.sd, strict=True)}
            top = sorted(z.items(), key=lambda kv: -kv[1])[:3]
            # Hybrid rule: forest outlier AND a moderately large robust z, OR an extreme robust z on its own
            # (IsolationForest alone under-scores a window that is extreme on only one of seven features).
            zmax = top[0][1]
            out.append(Scored(w, float(s), bool((s >= self.threshold and zmax >= self.z_min) or zmax >= self.z_hard), z, top))
        return out
