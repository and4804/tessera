"""JSON extractor: ``orjson.loads`` then flatten nested objects to dotted paths; arrays are kept as lists."""
from __future__ import annotations

import json as _stdjson
import re
from collections.abc import Callable
from typing import Any

import orjson

_BIGINT_RE = re.compile(r"\d{19,}")


def _flat(prefix: str, v: Any, out: dict[str, Any]) -> None:
    if isinstance(v, dict):
        for k, x in v.items():
            _flat(f"{prefix}.{k}" if prefix else k, x, out)
    else:
        out[prefix] = v


def flatten(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            _flat(k, v, out)
        else:
            out[k] = v
    return out


def build_json(options: dict[str, Any] | None = None) -> Callable[[str | bytes], dict[str, Any] | None]:
    def extract(text: str | bytes) -> dict[str, Any] | None:
        if _BIGINT_RE.search(text if isinstance(text, str) else text.decode("latin-1")):  # orjson turns integers beyond 64 bits into floats (lossy); the stdlib parser keeps them exact
            try:
                d = _stdjson.loads(text if isinstance(text, str) else text.decode("utf-8", "surrogateescape"))
            except ValueError:
                return None
            return flatten(d) if isinstance(d, dict) else None
        try:
            d = orjson.loads(text.encode("utf-8", "surrogateescape") if isinstance(text, str) else text)
        except (orjson.JSONDecodeError, UnicodeEncodeError):
            try:  # orjson is strict (64-bit ints, no NaN); the stdlib parser is the lenient fallback
                d = _stdjson.loads(text if isinstance(text, str) else text.decode("utf-8", "surrogateescape"))
            except ValueError:
                return None
        if not isinstance(d, dict):
            return None
        return flatten(d)

    return extract
