"""Format sniffing, field extraction and per-field type inference (steps 2 and 4 of §7.11). Slow path only."""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from . import miner, refengine

_KV_RX = re.compile(r"""(?:^|[\s,;|])([A-Za-z_][\w.\-@]*)=("(?:[^"\\]|\\.)*"|[^\s,;]*)""")
_TS_FORMATS = [
    ("iso8601", re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?$"), None),
    ("datetime", re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:[.,]\d+)?$"), "%Y-%m-%d %H:%M:%S"),
    ("syslog_ts", re.compile(r"^[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d$"), "%b %d %H:%M:%S"),
    ("syslog_ts_year", re.compile(r"^[A-Z][a-z]{2} +\d{1,2} \d{4} \d\d:\d\d:\d\d$"), "%b %d %Y %H:%M:%S"),
    ("date", re.compile(r"^\d{4}-\d\d-\d\d$"), "%Y-%m-%d"),
    ("time", re.compile(r"^\d\d:\d\d:\d\d$"), "%H:%M:%S"),
]
_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_INT = re.compile(r"^-?\d+$")
_FLOAT = re.compile(r"^-?\d+\.\d+$")
_URL = re.compile(r"^(?:[a-z][a-z0-9+.-]*://|www\.)\S+$", re.I)


@dataclass
class Sniff:
    format: str                      # json | cef | leef | xml | tsv | kv | csv | text
    framing: str                     # none | syslog
    syslog_style: str = "none"       # none | pri | rfc3164 | rfc5424
    confidence: float = 1.0
    votes: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class FieldInfo:
    name: str
    type: str                        # ip port int float mac timestamp url enum bool text
    ts_kind: str | None = None       # iso8601 | datetime | syslog_ts | epoch_s | epoch_ms | epoch_ns | date | time
    ts_fmt: str | None = None
    support: float = 0.0             # fraction of lines in which the field is present
    distinct: int = 0
    examples: list[str] = field(default_factory=list)
    values: list[str] = field(default_factory=list)   # capped list of observed values (for enum maps)


def split_syslog(line: str, recv_ms: int = refengine.RECV_MS) -> tuple[str, dict[str, Any], str]:
    msg, ctx = refengine.parse_syslog(line, recv_ms)
    style = "none"
    if "syslog.ts" in ctx:
        style = "rfc5424" if re.match(r"^(?:<\d+>)?1 ", line) else "rfc3164"
    elif "syslog.pri" in ctx:
        style = "pri"
    return msg, ctx, style


def _line_format(msg: str) -> str:
    s = msg.lstrip()
    if s.startswith("{"):
        return "json"
    if "CEF:" in s[:200] and re.search(r"CEF:\d\|", s):
        return "cef"
    if "LEEF:" in s[:200] and re.search(r"LEEF:[12]\.\d\|", s):
        return "leef"
    if s.startswith("<?xml") or s.startswith("<Event") or re.match(r"^<\w[\w:.-]*[\s>]", s) and s.rstrip().endswith(">"):
        return "xml"
    if s.count("\t") >= 4:
        return "tsv"
    kvs = _KV_RX.findall(msg)
    if len(kvs) >= 3:
        toks = max(1, len(msg.split()))
        if len(kvs) / toks >= 0.4:
            return "kv"
    if msg.count(",") >= 6 and not re.search(r"[A-Za-z]{4,}\s+[A-Za-z]{4,}", msg):
        return "csv"
    return "text"


def sniff(lines: list[str]) -> Sniff:
    """Majority vote over lines: framing (syslog header or not) and payload format."""
    fmt_votes: Counter[str] = Counter()
    style_votes: Counter[str] = Counter()
    for ln in lines:
        msg, _ctx, style = split_syslog(ln)
        style_votes[style] += 1
        fmt_votes[_line_format(msg)] += 1
    fmt, c = fmt_votes.most_common(1)[0]
    style = style_votes.most_common(1)[0][0]
    n = max(1, len(lines))
    notes = []
    if c / n < 0.8:
        notes.append(f"mixed formats {dict(fmt_votes)}; using {fmt}")
    return Sniff(fmt, "syslog" if style != "none" else "none", style, c / n, dict(fmt_votes), notes)


# ------------------------------------------------------------------------------------------------ extraction
def extract_lines(lines: list[str], sn: Sniff, tsv_fields: list[str] | None = None) -> tuple[dict[str, Any], list[dict[str, Any] | None], dict[str, Any]]:
    """Return (extract_spec, per-line field dicts (None where extraction failed), extra) for the sniffed format.

    extract_spec is a ready-to-use `extract:` block for the draft pack. `extra` carries format-specific info (miner Synth, ...)."""
    bodies, ctxs = [], []
    for ln in lines:
        if sn.framing == "syslog":
            msg, ctx, _ = split_syslog(ln)
        else:
            msg, ctx = ln, {}
        bodies.append(msg)
        ctxs.append(ctx)
    extra: dict[str, Any] = {"ctx": ctxs}
    if sn.format == "kv":
        spec = {"kind": "kv", "options": _kv_options(bodies)}
        fn = refengine.EXTRACTORS["kv"]
        return spec, [fn(b, spec["options"]) for b in bodies], extra
    if sn.format == "json":
        spec = {"kind": "json", "options": {}}
        return spec, [refengine.ex_json(b, {}) for b in bodies], extra
    if sn.format == "cef":
        return {"kind": "cef", "options": {}}, [refengine.ex_cef(b, {}) for b in bodies], extra
    if sn.format == "leef":
        return {"kind": "leef", "options": {}}, [refengine.ex_leef(b, {}) for b in bodies], extra
    if sn.format == "xml":
        spec = {"kind": "xml", "options": {"strip_namespaces": True, "named_children": {"Data": "Name"}}}
        return spec, [refengine.ex_xml(b, spec["options"]) for b in bodies], extra
    if sn.format == "tsv":
        names = tsv_fields
        if names is None:
            for b in bodies:
                if b.startswith("#fields\t"):
                    names = b.split("\t")[1:]
        width = max(b.count("\t") + 1 for b in bodies)
        names = names or [f"col_{i + 1}" for i in range(width)]
        spec = {"kind": "tsv_zeek", "options": {"fields": names, "unset": "-", "empty": "(empty)"}}
        return spec, [refengine.ex_tsv_zeek(b, spec["options"]) for b in bodies], extra
    if sn.format == "csv":
        width = max(len(b.split(",")) for b in bodies)
        cols = [f"col_{i + 1}" for i in range(width)]
        spec = {"kind": "csv", "options": {"sep": ",", "columns": cols}}
        return spec, [refengine.ex_csv(b, spec["options"]) for b in bodies], extra
    # free text -> template mining
    synth = miner.synthesize_regex([b for b in bodies if b.strip()])
    if len(synth.alternatives) == 1:
        spec = {"kind": "regex", "options": {"anchor": synth.regex}}
    else:
        spec = {"kind": "regex", "options": {"anchor": synth.alternatives[0], "alternatives": synth.alternatives[1:]}}
    extra["synth"] = synth
    fn = refengine.EXTRACTORS["regex"]
    return spec, [fn(b, spec["options"]) for b in bodies], extra


def _kv_options(bodies: list[str]) -> dict[str, Any]:
    quote = '"'
    joined = " ".join(bodies[:20])
    pair_sep = " "
    if joined.count(", ") > joined.count(" ") * 0.3 and joined.count("=") >= 3 and re.search(r"\w=[^ ,]+, \w+=", joined):
        pair_sep = ","
    return {"pair_sep": pair_sep, "kv_sep": "=", "quote": quote}


# ------------------------------------------------------------------------------------------------ type inference
def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v.strip())
        return True
    except ValueError:
        return False


def _all(vals: list[str], pred, frac: float = 0.95) -> bool:
    return bool(vals) and sum(1 for v in vals if pred(v)) / len(vals) >= frac


def infer_type(name: str, vals: list[str]) -> tuple[str, str | None, str | None]:
    """Return (type, ts_kind, ts_fmt) for the observed non-null values of one field."""
    vals = [str(v) for v in vals if v is not None and str(v) != ""]
    if not vals:
        return "text", None, None
    if _all(vals, _is_ip):
        return "ip", None, None
    if _all(vals, _MAC.match):
        return "mac", None, None
    for kind, rx, fmt in _TS_FORMATS:
        if _all(vals, rx.match):
            return "timestamp", kind, fmt
    low = name.lower()
    if _all(vals, lambda v: _INT.match(v) is not None):
        ints = [int(v) for v in vals]
        if all(1_000_000_000 <= x < 4_000_000_000 for x in ints) and re.search(r"time|ts|stamp|date|epoch|created|start|end", low):
            return "timestamp", "epoch_s", None
        if all(1_000_000_000_000 <= x < 4_000_000_000_000 for x in ints):
            return "timestamp", "epoch_ms", None
        if all(1_000_000_000_000_000_000 <= x < 4_000_000_000_000_000_000 for x in ints):
            return "timestamp", "epoch_ns", None
        if re.search(r"(^|_)(p|port|sport|dport|spt|dpt)$|port", low) and all(0 <= x <= 65535 for x in ints):
            return "port", None, None
        return "int", None, None
    if _all(vals, lambda v: _FLOAT.match(v) is not None or _INT.match(v) is not None):
        fl = [float(v) for v in vals]
        if all(1_000_000_000 <= x < 4_000_000_000 for x in fl) and re.search(r"time|ts|stamp|date|epoch", low):
            return "timestamp", "epoch_s", None
        return "float", None, None
    if _all(vals, lambda v: v.lower() in ("true", "false", "yes", "no")):
        return "bool", None, None
    if _all(vals, _URL.match, 0.9):
        return "url", None, None
    distinct = len(set(vals))
    if distinct <= 12 and (len(vals) < 20 or distinct / len(vals) <= 0.25):
        return "enum", None, None
    return "text", None, None


def infer_fields(rows: list[dict[str, Any] | None], ctxs: list[dict[str, Any]] | None = None) -> dict[str, FieldInfo]:
    """Per-field FieldInfo over all successfully extracted rows. Syslog header fields (syslog.ts, syslog.host) are included."""
    ok = [(i, r) for i, r in enumerate(rows) if r]
    n = max(1, len(ok))
    collected: dict[str, list[str]] = {}
    for _, r in ok:
        for k, v in r.items():
            if k == "_residual":
                continue
            collected.setdefault(k, []).append(v if isinstance(v, str) else str(v))
    if ctxs:
        for i, _r in ok:
            for k, v in ctxs[i].items():
                if k in ("syslog.ts", "syslog.host", "syslog.app"):
                    collected.setdefault(k, []).append(str(v))
    out: dict[str, FieldInfo] = {}
    for k, vals in collected.items():
        t, kind, fmt = infer_type(k, vals)
        if k == "syslog.ts":
            t, kind, fmt = "timestamp", "syslog_ctx", None
        distinct = len(set(vals))
        out[k] = FieldInfo(k, t, kind, fmt, len(vals) / n, distinct, list(dict.fromkeys(vals))[:5], list(dict.fromkeys(vals))[:60])
    return out
