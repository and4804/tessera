"""Format sniffing on the first bytes only (§7.4). Returns one of: json xml cef leef syslog tsv text."""
from __future__ import annotations


def sniff(data: bytes) -> str:
    c = data[:1]
    if c == b"{":
        return "json"
    if c == b"<":
        if data.startswith(b"<?xml") or data.startswith(b"<Event"):
            return "xml"
        j = data.find(b">", 1, 6)
        if j > 1 and data[1:j].isdigit():
            return "syslog"
        return "xml" if data[1:2].isalpha() else "text"
    if c == b"C" and data.startswith(b"CEF:"):
        return "cef"
    if c == b"L" and data.startswith(b"LEEF:"):
        return "leef"
    if c == b"#" and (data.startswith(b"#fields") or data.startswith(b"#separator") or data.startswith(b"#types")):
        return "tsv"
    if c.isdigit() and data.count(b"\t", 0, 256) >= 5:
        return "tsv"
    return "text"
