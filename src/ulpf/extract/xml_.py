"""Hardened XML extractor: DOCTYPE/ENTITY are rejected before parsing (no DTD, no entity expansion, no external resources)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from typing import Any

from .kv import dedup_set

_FORBIDDEN = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)|<\?xml-stylesheet", re.I)
MAX_DEPTH = 64


def build_xml(options: dict[str, Any] | None = None) -> Callable[[str], dict[str, Any] | None]:
    o = options or {}
    strip: bool = o.get("strip_namespaces", True)
    named: dict[str, str] = o.get("named_children", {}) or {}

    def tag(t: str) -> str:
        return t.split("}", 1)[1] if strip and t.startswith("{") else t

    def extract(text: str) -> dict[str, Any] | None:
        if _FORBIDDEN.search(text):
            return None
        try:
            root = ET.fromstring(text)
        except (ET.ParseError, ValueError):
            return None
        out: dict[str, Any] = {}

        def walk(el: ET.Element, path: str, depth: int) -> None:
            if depth > MAX_DEPTH:
                return
            t = tag(el.tag)
            p = f"{path}.{t}" if path else t
            nm = named.get(t)
            if nm and nm in el.attrib:
                p = f"{path}.{el.attrib[nm]}" if path else el.attrib[nm]
            for k, v in el.attrib.items():
                if nm and k == nm:
                    continue
                dedup_set(out, f"{p}.@{tag(k)}", v)
            txt = (el.text or "").strip()
            if txt and len(el) == 0:
                dedup_set(out, p, txt)
            for c in el:
                walk(c, p, depth + 1)

        for c in root:
            walk(c, "", 0)
        for k, v in root.attrib.items():
            out[f"@{k}"] = v
        return out or None

    return extract
