"""key=value extractor: configurable separators and quote, quoted values with spaces and escaped quotes, duplicate keys kept."""
from __future__ import annotations

from typing import Any


def dedup_set(out: dict[str, Any], k: str, v: Any) -> None:
    """Never overwrite: second occurrence of ``k`` becomes ``k_2``, then ``k_3`` ..."""
    if k not in out:
        out[k] = v
        return
    i = 2
    while f"{k}_{i}" in out:
        i += 1
    out[f"{k}_{i}"] = v


def build_kv(options: dict[str, Any] | None = None):  # type: ignore[no-untyped-def]
    o = options or {}
    ps: str = o.get("pair_sep", " ")
    ks: str = o.get("kv_sep", "=")
    q: str = o.get("quote", '"')
    lks = len(ks)

    def extract(text: str) -> dict[str, Any] | None:
        out: dict[str, Any] = {}
        i, n = 0, len(text)
        find = text.find
        while i < n:
            while i < n and text[i] == ps:
                i += 1
            j = find(ks, i)
            if j < 0:
                break
            key = text[i:j]
            if not key or ps in key:  # token without a separator: skip it (it stays visible in the raw)
                k2 = find(ps, i)
                if k2 < 0:
                    break
                i = k2 + 1
                continue
            i = j + lks
            if i < n and text[i] == q:
                i += 1
                start = i
                while True:
                    e = find(q, i)
                    if e < 0:
                        seg = text[start:]
                        i = n
                        val = seg if "\\" not in seg else _unescape(seg)
                        break
                    if text[e - 1] == "\\" and _odd_backslashes(text, e):
                        i = e + 1
                        continue
                    seg = text[start:e]
                    val = seg if "\\" not in seg else _unescape(seg)
                    i = e + 1
                    break
            else:
                e = find(ps, i)
                if e < 0:
                    e = n
                val = text[i:e]
                i = e
            if key in out:
                dedup_set(out, key, val)
            else:
                out[key] = val
        return out or None

    return extract


def _odd_backslashes(text: str, pos: int) -> bool:
    """True when the quote at ``pos`` is escaped, i.e. preceded by an odd number of backslashes (scanning from the open quote
    is what the reference does; equivalent because backslash-escape pairs consume left to right)."""
    n = 0
    k = pos - 1
    while k >= 0 and text[k] == "\\":
        n += 1
        k -= 1
    return n % 2 == 1


def _unescape(seg: str) -> str:
    """``\\x`` -> ``x`` for any x (a lone trailing backslash is kept, like the reference)."""
    buf: list[str] = []
    i, n = 0, len(seg)
    while i < n:
        c = seg[i]
        if c == "\\" and i + 1 < n:
            buf.append(seg[i + 1])
            i += 2
            continue
        buf.append(c)
        i += 1
    return "".join(buf)
