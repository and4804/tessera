"""Pack detection + extraction (§7.4): hint -> source cache -> format-sniffed candidates (priority order) -> every other pack.

Detection and extraction are one step: a pack whose prefilter matches but whose extractor yields nothing (or whose ``field_eq``
post-conditions fail) is skipped and the next candidate is tried, so "extraction failed" falls through to the unparsed lane only
when no pack can take the event."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..extract.tsv_zeek import ZeekState
from ..packs.compiler import CompiledPackImpl
from ..packs.loader import PackSet
from .sniffer import sniff
from .source_cache import SourceCache


@dataclass(slots=True)
class Detection:
    pack: CompiledPackImpl
    fields: dict[str, Any]
    ctx: dict[str, Any]


class Detector:
    """``packset`` is read through ``get_packset`` on every call so a hot-reload swap is picked up atomically."""

    def __init__(self, get_packset: Callable[[], PackSet], use_cache: bool = True, max_zeek_states: int = 1024) -> None:
        self._get = get_packset
        self.cache = SourceCache() if use_cache else None
        self._zeek: dict[str, ZeekState] = {}
        self._max_zeek = max_zeek_states
        self.extract_errors = 0

    def control_line(self, key: str, data: bytes) -> bool:
        """Zeek-style ``#...`` header lines update per-source state and carry no event fields."""
        if data[:1] != b"#":
            return False
        st = self._zeek.get(key)
        if st is None:
            if len(self._zeek) >= self._max_zeek:
                self._zeek.pop(next(iter(self._zeek)))
            st = self._zeek[key] = ZeekState()
        return st.update(data.decode("utf-8", "surrogateescape"))

    def detect(self, data: bytes, key: str, hint: str | None, recv_ms: int) -> Detection | None:
        ps = self._get()
        tried: set[str] = set()
        cache = self.cache
        zst = self._zeek.get(key)

        def attempt(p: CompiledPackImpl) -> Detection | None:
            tried.add(p.id)
            if not p.match(data):
                return None
            ctx: dict[str, Any] = {"_recv_ms": recv_ms}
            if zst is not None:
                ctx["_zeek"] = zst
            try:
                fields = p.extract(data, ctx)
            except Exception:  # noqa: BLE001 - a pack bug must never lose the event; it falls to the next candidate / unparsed
                self.extract_errors += 1
                return None
            if fields is None or not p.post_match(fields):
                return None
            return Detection(p, fields, ctx)

        if hint:
            hp = ps.by_id.get(hint)
            if hp is not None:
                d = attempt(hp)
                if d is not None:
                    return d
        if cache is not None:
            cid = cache.get(key)
            if cid is not None and cid not in tried:
                cp = ps.by_id.get(cid)
                if cp is not None:
                    d = attempt(cp)
                    if d is not None:
                        cache.hit(key, cp.id)
                        return d
                cache.miss(key)
        fmt = sniff(data)
        for p in ps.by_format.get(fmt, ()):
            if p.id in tried:
                continue
            d = attempt(p)
            if d is not None:
                if cache is not None:
                    cache.hit(key, p.id)
                return d
        for p in ps.packs:   # last resort: packs that do not advertise this sniffed format
            if p.id in tried:
                continue
            d = attempt(p)
            if d is not None:
                if cache is not None:
                    cache.hit(key, p.id)
                return d
        return None
