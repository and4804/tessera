"""IBM LEEF 1.0 (tab-delimited extension) and 2.0 (custom delimiter field, e.g. ``^`` or ``x09``)."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from .kv import dedup_set

_HEXDELIM = re.compile(r"(?:0?x|\\x)([0-9a-fA-F]{2})")


def build_leef(options: dict[str, Any] | None = None) -> Callable[[str], dict[str, Any] | None]:
    def extract(text: str) -> dict[str, Any] | None:
        i = text.find("LEEF:")
        if i < 0:
            return None
        text = text[i + 5 :]
        ver = text.split("|", 1)[0]
        two = ver.startswith("2")
        parts = text.split("|", 5 if two else 4)
        if len(parts) < (6 if two else 5):
            return None
        delim = "\t"
        if two:
            vendor, product, pver, eid, rest = parts[1], parts[2], parts[3], parts[4], parts[5]
            dl, _, ext = rest.partition("|")
            if dl:
                m = _HEXDELIM.fullmatch(dl)
                delim = chr(int(m.group(1), 16)) if m else dl
        else:
            vendor, product, pver, ext = parts[1], parts[2], parts[3], parts[4]
            eid, _, ext = ext.partition("|")
        out: dict[str, Any] = {"leef.version": ver, "leef.vendor": vendor, "leef.product": product, "leef.product_version": pver,
                               "leef.event_id": eid}
        for tok in ext.split(delim):
            k, _, v = tok.partition("=")
            if k:
                dedup_set(out, k.strip(), v)
        return out

    return extract
