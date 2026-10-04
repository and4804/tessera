"""Per-envelope routing: detect -> extract -> normalize, with the terminal-state guarantee (never raises, always yields an event)."""
from __future__ import annotations

from typing import Any

from ..detect import Detector
from ..ingest.publisher import source_key
from ..model.envelope import RawEnvelope
from ..model.lineage import VaultRef
from .unparsed import UnparsedLane


class Router:
    def __init__(self, detector: Detector, lane: UnparsedLane) -> None:
        self.detector = detector
        self.lane = lane
        self.normalize_errors = 0

    def route(self, env: RawEnvelope, ref: VaultRef) -> list[dict[str, Any]]:
        """Return >=1 events. ``unparsed`` covers: no pack matched, extraction failed, normalize raised, control lines."""
        data = env.data
        key = env.peer_ip or env.hint or "unknown"
        reason = "no_pack"
        try:
            if data[:1] == b"#" and self.detector.control_line(key, data):
                return [self.lane.event(env, ref, "control_line")]
            d = self.detector.detect(data, key, env.hint, env.recv_ns // 1_000_000)
            if d is not None:
                try:
                    return d.pack.normalize(d.fields, env, ref, d.ctx)
                except Exception:  # noqa: BLE001
                    self.normalize_errors += 1
                    reason = "normalize_error"
        except Exception:  # noqa: BLE001
            reason = "detect_error"
        return [self.lane.event(env, ref, reason)]


__all__ = ["Router", "source_key"]
