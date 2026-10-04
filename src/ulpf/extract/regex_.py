"""Regex extractor with ``alternatives`` and message-id ``dispatch`` (O(1) pattern selection instead of trying every pattern)."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

MAX_INPUT = 1 << 16


def build_regex(options: dict[str, Any]) -> Callable[[str], dict[str, Any] | None]:
    """``anchor`` (+ ``alternatives``, tried in order, first match wins). ``dispatch_on`` names an extracted field whose value
    selects ``patterns[value]``, applied (prefix match) to the field named by ``dispatch_text`` (default ``body``); text the
    dispatched pattern did not cover is returned as ``_residual``. A named group ``_residual`` in any pattern behaves alike.
    Every pattern is compiled once, here. Anchored patterns (``^...``) use ``match``; others use ``search``."""
    compiled: list[tuple[re.Pattern[str], bool]] = []
    for rx in [options["anchor"], *(options.get("alternatives") or [])]:
        compiled.append((re.compile(rx), rx.startswith("^")))
    disp: str | None = options.get("dispatch_on")
    disp_text: str = options.get("dispatch_text", "body")
    patterns = {str(k): re.compile(v) for k, v in (options.get("patterns") or {}).items()}

    def extract(text: str) -> dict[str, Any] | None:
        m = None
        for cr, anchored in compiled:
            m = cr.match(text) if anchored else cr.search(text)
            if m:
                break
        if m is None:
            return None
        out = {k: v for k, v in m.groupdict().items() if v is not None}
        if out.get("_residual") == "":
            del out["_residual"]
        if disp:
            pat = patterns.get(str(out.get(disp)))
            body = out.get(disp_text, "")
            if pat is not None:
                m2 = pat.match(body)
                if m2:
                    for k, v in m2.groupdict().items():
                        if v is not None:
                            out[k] = v
                    if m2.end() < len(body):
                        out["_residual"] = body[m2.end():]
        return out

    return extract


def pattern_texts(options: dict[str, Any]) -> list[str]:
    """Every regex source in an extract block (for the linter)."""
    pats = [options.get("anchor", ""), *(options.get("alternatives") or []), *((options.get("patterns") or {}).values())]
    return [p for p in pats if isinstance(p, str) and p]
