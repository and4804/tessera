"""Positional CSV with layout branches (e.g. pfSense filterlog: the columns after ``ip_version`` depend on IP version and protocol)."""
from __future__ import annotations

import csv
from collections.abc import Callable
from typing import Any


def _layout(row: list[str], layout: dict[str, Any], out: dict[str, Any], pos: int) -> int:
    for name in layout.get("columns", []):
        if pos >= len(row):
            return pos
        if row[pos] != "":
            out[name] = row[pos]
        pos += 1
    br = layout.get("branch")
    if br:
        key = str(out.get(br["field"], "")).lower()
        sub = (br.get("cases") or {}).get(key, br.get("default"))
        if sub:
            pos = _layout(row, sub, out, pos)
    return pos


def build_csv(options: dict[str, Any]) -> Callable[[str], dict[str, Any] | None]:
    sep: str = options.get("sep", ",")

    def extract(text: str) -> dict[str, Any] | None:
        if sep not in text:
            return None
        try:
            row = next(csv.reader([text], delimiter=sep), [])
        except csv.Error:         # e.g. a bare CR inside an unquoted cell: not a CSV record (never raise on the hot path, R3)
            return None
        if len(row) < 2:
            return None
        out: dict[str, Any] = {}
        end = _layout(row, options, out, 0)
        if end < len(row):
            out["_extra"] = sep.join(row[end:])
        return out or None

    return extract
