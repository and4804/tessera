"""ArcSight CEF: ``CEF:v|vendor|product|ver|sigid|name|sev|ext`` with ``\\|`` / ``\\\\`` header escapes and ``\\=`` in the extension."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from .kv import dedup_set

_EXT_SPLIT = re.compile(r"\s(?=\w+=)")


def split_escaped(s: str, sep: str, maxsplit: int) -> list[str]:
    """Split on unescaped ``sep`` at most ``maxsplit`` times; backslash pairs are kept verbatim (unescape afterwards)."""
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    while i < len(s) and len(parts) < maxsplit:
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            buf.append(s[i : i + 2])
            i += 2
            continue
        if c == sep:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    parts.append("".join(buf) + s[i:])
    return parts


def _unesc(s: str) -> str:
    return s.replace("\\|", "|").replace("\\\\", "\\")


def build_cef(options: dict[str, Any] | None = None) -> Callable[[str], dict[str, Any] | None]:
    def extract(text: str) -> dict[str, Any] | None:
        i = text.find("CEF:")
        if i < 0:
            return None
        parts = split_escaped(text[i + 4 :], "|", 7)
        if len(parts) < 8:
            return None
        ver, vendor, product, dver, sig, name, sev, ext = parts
        out: dict[str, Any] = {
            "cef.version": ver, "cef.vendor": _unesc(vendor), "cef.product": _unesc(product), "cef.device_version": _unesc(dver),
            "cef.signature_id": _unesc(sig), "cef.name": _unesc(name), "cef.severity": sev,
        }
        for tok in _EXT_SPLIT.split(ext):
            k, _, v = tok.partition("=")
            if k:
                dedup_set(out, k, v.replace("\\=", "=").replace("\\\\", "\\").replace("\\n", "\n"))
        return out

    return extract
