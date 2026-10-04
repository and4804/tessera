"""Golden-vector runner (`ulpf packs test`). Same comparison rules as the reference runner: dotted paths into the normalized event,
and types matter (``6`` is not ``"6"``). The receive clock is fixed at 2026-10-04T13:30:00Z so RFC 3164 year inference is deterministic."""
from __future__ import annotations

import calendar
import hashlib
from dataclasses import dataclass
from typing import Any

from ..model.envelope import RawEnvelope
from ..model.event import get_path
from ..model.lineage import VaultRef
from .compiler import CompiledPackImpl

RECV_MS = calendar.timegm((2026, 10, 4, 13, 30, 0)) * 1000


@dataclass(frozen=True, slots=True)
class TestFailure:
    __test__ = False
    pack: str
    test: str
    message: str

    def __str__(self) -> str:
        return f"{self.pack}::{self.test}: {self.message}"


def make_env(data: bytes, recv_ms: int = RECV_MS, raw_id: str = "00000000-0000-7000-8000-000000000000") -> tuple[RawEnvelope, VaultRef]:
    env = RawEnvelope(raw_id, recv_ms * 1_000_000, "test", "replay", "", 0, data)
    return env, VaultRef("test-000001", 0, 0, hashlib.sha256(data).hexdigest())


def run_one(pack: CompiledPackImpl, data: bytes, recv_ms: int = RECV_MS) -> dict[str, Any] | None:
    """extract + normalize with one pack; None when extraction yields nothing."""
    ctx: dict[str, Any] = {"_recv_ms": recv_ms}
    fields = pack.extract(data, ctx)
    if fields is None:
        return None
    env, ref = make_env(data, recv_ms)
    return pack.normalize(fields, env, ref, ctx)[0]


def check_expect(ev: dict[str, Any], expect: dict[str, Any]) -> list[str]:
    fails: list[str] = []
    for path, want in expect.items():
        got = get_path(ev, str(path))
        if got != want or (type(got) is not type(want) and not (got is None and want is None)):
            fails.append(f"{path}: expected {want!r} got {got!r}")
    return fails


def run_pack_tests(pack: CompiledPackImpl, recv_ms: int = RECV_MS) -> list[TestFailure]:
    out: list[TestFailure] = []
    for t in pack.doc.tests:
        name = str(t.get("name", "?"))
        raw = str(t.get("raw", "")).encode("utf-8", "surrogateescape")
        if not pack.match(raw):
            out.append(TestFailure(pack.id, name, "pack.match() is False"))
            continue
        try:
            ev = run_one(pack, raw, recv_ms)
        except Exception as e:  # noqa: BLE001 - a test must report, not crash the run
            out.append(TestFailure(pack.id, name, f"exception {type(e).__name__}: {e}"))
            continue
        if ev is None:
            ev = {"ulpf": {"status": "unparsed"}}
        for m in check_expect(ev, t.get("expect") or {}):
            out.append(TestFailure(pack.id, name, m))
    return out
