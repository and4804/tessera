"""Extractors (§7.5): pure functions, no I/O. Each returns EVERY field it found; mapped-vs-unmapped is the mapper's job.

The ``text`` form takes a ``str`` decoded with ``surrogateescape`` (so invalid UTF-8 round-trips into ``unmapped``).
:func:`make_extractor` wraps one as the ``bytes -> dict | None`` contract extractor of §6.3.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .cef import build_cef
from .csv_ import build_csv
from .json_ import build_json
from .kv import build_kv, dedup_set
from .leef import build_leef
from .regex_ import build_regex
from .syslog_hdr import parse_syslog
from .tsv_zeek import ZeekState, build_tsv_zeek
from .xml_ import build_xml

BUILDERS: dict[str, Callable[[dict[str, Any]], Callable[..., dict[str, Any] | None]]] = {
    "kv": build_kv, "regex": build_regex, "json": build_json, "csv": build_csv, "cef": build_cef, "leef": build_leef,
    "xml": build_xml, "tsv_zeek": build_tsv_zeek,
}
MAX_INPUT = 1 << 16

Extractor = Callable[[bytes], dict[str, Any] | None]


def build_text_extractor(kind: str, options: dict[str, Any] | None) -> Callable[..., dict[str, Any] | None]:
    try:
        b = BUILDERS[kind]
    except KeyError:
        raise ValueError(f"unknown extractor kind {kind!r}") from None
    return b(options or {})


def make_extractor(kind: str, options: dict[str, Any] | None = None) -> Extractor:
    fn = build_text_extractor(kind, options)

    def run(data: bytes) -> dict[str, Any] | None:
        return fn(data[:MAX_INPUT].decode("utf-8", "surrogateescape"))

    return run


__all__ = [
    "BUILDERS", "Extractor", "ZeekState", "build_text_extractor", "dedup_set", "make_extractor", "parse_syslog",
]
