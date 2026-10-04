"""Zeek TSV. Headers (``#separator``, ``#fields``, ``#types``, ``#unset_field``, ``#empty_field``) are tracked per connection/source
in :class:`ZeekState`; without a header the pack's ``fields`` option is used."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any


class ZeekState:
    """Per-source header state. ``update(line)`` returns True when ``line`` was a header/comment line (no event fields)."""

    __slots__ = ("fields", "types", "unset", "empty", "sep")

    def __init__(self) -> None:
        self.fields: list[str] | None = None
        self.types: list[str] | None = None
        self.unset = "-"
        self.empty = "(empty)"
        self.sep = "\t"

    def update(self, line: str) -> bool:
        if not line.startswith("#"):
            return False
        if line.startswith("#separator"):
            v = line.split(" ", 1)[1].strip() if " " in line else ""
            if v.startswith("\\x") and len(v) == 4:
                self.sep = chr(int(v[2:], 16))
            return True
        key, _, rest = line.partition(self.sep)
        if key == "#fields":
            self.fields = rest.split(self.sep)
        elif key == "#types":
            self.types = rest.split(self.sep)
        elif key == "#unset_field":
            self.unset = rest
        elif key == "#empty_field":
            self.empty = rest
        return True


def build_tsv_zeek(options: dict[str, Any]) -> Callable[..., dict[str, Any] | None]:
    default_fields: list[str] = list(options.get("fields") or [])
    unset0: str = options.get("unset", "-")
    empty0: str = options.get("empty", "(empty)")

    def extract(text: str, state: ZeekState | None = None) -> dict[str, Any] | None:
        if text.startswith("#"):
            return None
        fields, unset, empty, sep = default_fields, unset0, empty0, "\t"
        if state is not None and state.fields:
            fields, unset, empty, sep = state.fields, state.unset, state.empty, state.sep
        cols = text.split(sep)
        out: dict[str, Any] = {}
        for name, v in zip(fields, cols):
            if v != unset and v != empty and v != "":
                out[name] = v
        if len(cols) > len(fields):
            out["_extra"] = sep.join(cols[len(fields):])
        return out or None

    return extract
