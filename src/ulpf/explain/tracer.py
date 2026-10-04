"""Explain (§7.10): field-level provenance for ONE event, on demand (slow path, never inline).

Pipeline: raw bytes -> pack (by id, else full detection) -> extract again, this time *with span tracking* -> normalize again, this
time recording which extracted fields produced each OCSF value and the rule that did it.

Span offsets are BYTE offsets into the raw bytes (``start`` inclusive, ``end`` exclusive) so they index exactly what ``/raw`` returns.
Each span extractor below re-implements the production extractor's scanning loop with positions; its extracted values are compared
with the production extractor's result and any disagreement degrades that event to a best-effort text search with
``spans_exact = False`` (never a wrong "exact" claim). JSON and XML are display-only by contract (``spans_exact = False``).
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from typing import Any

import orjson

from ..extract.cef import _EXT_SPLIT
from ..extract.syslog_hdr import parse_syslog
from ..extract.tsv_zeek import ZeekState
from ..packs.compiler import CompiledPackImpl, compile_expr
from ..packs.dsl_ops import split_op
from ..packs.schema import Coalesce, Const, Expr, FieldRef, From, When
from ..packs.testrunner import make_env

Span = tuple[int, int]          # char offsets while tracing, converted to byte offsets at the end
FORMAT_OF = {"kv": "kv", "regex": "regex", "csv": "csv", "cef": "cef", "leef": "leef", "json": "json", "xml": "xml", "tsv_zeek": "tsv"}


class NoPack(LookupError):
    """No pack can explain this event (unparsed)."""


@dataclass
class Traced:
    """Extraction result with per-field char spans (absolute into the full raw text)."""

    fields: dict[str, Any]
    spans: dict[str, list[Span]] = field(default_factory=dict)
    escaped: set[str] = field(default_factory=set)      # value differs from its raw slice only by escaping
    exact: bool = True


# ----------------------------------------------------------------------------------------------- span extractors (char offsets)
class _Acc:
    """Collect ``(key, value, span)`` triples with the same duplicate-key naming as the production extractors."""

    def __init__(self) -> None:
        self.fields: dict[str, Any] = {}
        self.spans: dict[str, list[Span]] = {}
        self.escaped: set[str] = set()

    def add(self, key: str, value: Any, span: Span | None, esc: bool = False) -> None:
        name = key
        if name in self.fields:                    # same naming as extract.kv.dedup_set: key, key_2, key_3 ...
            i = 2
            while f"{key}_{i}" in self.fields:
                i += 1
            name = f"{key}_{i}"
        self.fields[name] = value
        self.spans[name] = [span] if span is not None else []
        if esc:
            self.escaped.add(name)


def _unesc_kv(seg: str) -> str:
    buf: list[str] = []
    i, n = 0, len(seg)
    while i < n:
        if seg[i] == "\\" and i + 1 < n:
            buf.append(seg[i + 1])
            i += 2
            continue
        buf.append(seg[i])
        i += 1
    return "".join(buf)


def _kv(text: str, base: int, o: dict[str, Any]) -> _Acc:
    ps, ks, q = o.get("pair_sep", " "), o.get("kv_sep", "="), o.get("quote", '"')
    acc = _Acc()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] == ps:
            i += 1
        j = text.find(ks, i)
        if j < 0:
            break
        key = text[i:j]
        if not key or ps in key:
            k2 = text.find(ps, i)
            if k2 < 0:
                break
            i = k2 + 1
            continue
        i = j + len(ks)
        if i < n and text[i] == q:
            i += 1
            start = i
            while True:
                e = text.find(q, i)
                if e < 0:
                    seg, vend, i = text[start:], n, n
                    break
                bs, k = 0, e - 1
                while k >= 0 and text[k] == "\\":
                    bs += 1
                    k -= 1
                if bs % 2 == 1:
                    i = e + 1
                    continue
                seg, vend, i = text[start:e], e, e + 1
                break
            val = seg if "\\" not in seg else _unesc_kv(seg)
            acc.add(key, val, (base + start, base + vend), esc="\\" in seg)
        else:
            e = text.find(ps, i)
            if e < 0:
                e = n
            acc.add(key, text[i:e], (base + i, base + e))
            i = e
    return acc


def _regex(text: str, base: int, o: dict[str, Any]) -> _Acc | None:
    m = None
    for rx in [o["anchor"], *(o.get("alternatives") or [])]:
        cr = re.compile(rx)
        m = cr.match(text) if rx.startswith("^") else cr.search(text)
        if m:
            break
    if m is None:
        return None
    acc = _Acc()
    for name in m.groupdict():
        v = m.group(name)
        if v is None:
            continue
        if name == "_residual" and v == "":
            continue
        acc.fields[name] = v
        acc.spans[name] = [(base + m.start(name), base + m.end(name))]
    disp = o.get("dispatch_on")
    if disp:
        pat = (o.get("patterns") or {}).get(str(acc.fields.get(disp)))
        dt = o.get("dispatch_text", "body")
        body = acc.fields.get(dt, "")
        if pat is not None and dt in acc.spans:
            m2 = re.compile(pat).match(body)
            if m2:
                b0 = acc.spans[dt][0][0]
                for name in m2.groupdict():
                    v = m2.group(name)
                    if v is not None:
                        acc.fields[name] = v
                        acc.spans[name] = [(b0 + m2.start(name), b0 + m2.end(name))]
                if m2.end() < len(body):
                    acc.fields["_residual"] = body[m2.end():]
                    acc.spans["_residual"] = [(b0 + m2.end(), b0 + len(body))]
    return acc


def _csv_cells(text: str, sep: str) -> list[tuple[str, int, int]]:
    """Cells as ``(value, start, end)``; quoted cells span their inner content. Mirrors ``csv.reader`` for a single record."""
    cells: list[tuple[str, int, int]] = []
    i, n = 0, len(text)
    while True:
        if i < n and text[i] == '"':
            j, buf = i + 1, []
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        buf.append('"')
                        j += 2
                        continue
                    break
                buf.append(text[j])
                j += 1
            end = j
            k = j + 1
            while k < n and text[k] != sep:
                buf.append(text[k])
                k += 1
            cells.append(("".join(buf), i + 1, end))
            i = k
        else:
            j = text.find(sep, i)
            j = n if j < 0 else j
            cells.append((text[i:j], i, j))
            i = j
        if i >= n:
            break
        i += 1                      # skip the separator
        if i == n:
            cells.append(("", n, n))
            break
    return cells


def _csv(text: str, base: int, o: dict[str, Any]) -> _Acc | None:
    sep = o.get("sep", ",")
    if sep not in text:
        return None
    cells = _csv_cells(text, sep)
    try:
        ref = next(csv.reader([text], delimiter=sep), [])
    except csv.Error:             # the production extractor returns None for such a line, so there is nothing to explain
        return None
    if [c[0] for c in cells] != ref:
        raise ValueError("csv cell scan disagrees with csv.reader")
    acc = _Acc()

    def layout(spec: dict[str, Any], pos: int) -> int:
        for name in spec.get("columns", []):
            if pos >= len(cells):
                return pos
            v, s, e = cells[pos]
            if v != "":
                acc.fields[name] = v
                acc.spans[name] = [(base + s, base + e)]
            pos += 1
        br = spec.get("branch")
        if br:
            key = str(acc.fields.get(br["field"], "")).lower()
            sub = (br.get("cases") or {}).get(key, br.get("default"))
            if sub:
                pos = layout(sub, pos)
        return pos

    end = layout(o, 0)
    if end < len(cells):
        acc.fields["_extra"] = sep.join(c[0] for c in cells[end:])
        acc.spans["_extra"] = [(base + cells[end][1], base + cells[-1][2])]
    return acc


def _split_escaped(s: str, sep: str, maxsplit: int) -> list[tuple[str, int, int]]:
    parts: list[tuple[str, int, int]] = []
    buf: list[str] = []
    i, start = 0, 0
    while i < len(s) and len(parts) < maxsplit:
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            buf.append(s[i:i + 2])
            i += 2
            continue
        if c == sep:
            parts.append(("".join(buf), start, i))
            buf, start = [], i + 1
        else:
            buf.append(c)
        i += 1
    parts.append(("".join(buf) + s[i:], start, len(s)))
    return parts


def _cef(text: str, base: int, o: dict[str, Any]) -> _Acc | None:
    i = text.find("CEF:")
    if i < 0:
        return None
    off = i + 4
    parts = _split_escaped(text[off:], "|", 7)
    if len(parts) < 8:
        return None
    unesc = lambda s: s.replace("\\|", "|").replace("\\\\", "\\")   # noqa: E731
    acc = _Acc()
    names = ["cef.version", "cef.vendor", "cef.product", "cef.device_version", "cef.signature_id", "cef.name", "cef.severity"]
    for name, (v, s, e) in zip(names, parts[:7]):
        val = v if name in ("cef.version", "cef.severity") else unesc(v)
        acc.fields[name] = val
        acc.spans[name] = [(base + off + s, base + off + e)]
        if val != v:
            acc.escaped.add(name)
    ext, es = parts[7][0], off + parts[7][1]
    pos = 0
    for tm in list(_EXT_SPLIT.finditer(ext)) + [None]:
        tok_end = tm.start() if tm is not None else len(ext)
        tok = ext[pos:tok_end]
        k, eq, v = tok.partition("=")
        if k:
            val = v.replace("\\=", "=").replace("\\\\", "\\").replace("\\n", "\n")
            vs = pos + len(k) + len(eq)
            acc.add(k, val, (base + es + vs, base + es + tok_end), esc=val != v)
        if tm is not None:
            pos = tm.end()
    return acc


def _leef(text: str, base: int, o: dict[str, Any]) -> _Acc | None:
    i = text.find("LEEF:")
    if i < 0:
        return None
    off = i + 5
    t = text[off:]
    ver = t.split("|", 1)[0]
    two = ver.startswith("2")
    parts = t.split("|", 5 if two else 4)
    if len(parts) < (6 if two else 5):
        return None
    starts, p = [], 0
    for x in parts:
        starts.append(p)
        p += len(x) + 1
    delim = "\t"
    if two:
        rest = parts[5]
        dl, _, ext = rest.partition("|")
        ext_off = starts[5] + (len(dl) + 1 if "|" in rest else len(rest))
        if dl:
            m = re.fullmatch(r"(?:0?x|\\x)([0-9a-fA-F]{2})", dl)
            delim = chr(int(m.group(1), 16)) if m else dl
        names = {"leef.version": 0, "leef.vendor": 1, "leef.product": 2, "leef.product_version": 3, "leef.event_id": 4}
        vals = {k: parts[idx] for k, idx in names.items()}
        spans = {k: (starts[idx], starts[idx] + len(parts[idx])) for k, idx in names.items()}
    else:
        eid, _, ext = parts[4].partition("|")
        ext_off = starts[4] + (len(eid) + 1 if "|" in parts[4] else len(parts[4]))
        vals = {"leef.version": parts[0], "leef.vendor": parts[1], "leef.product": parts[2], "leef.product_version": parts[3],
                "leef.event_id": eid}
        spans = {"leef.version": (0, len(parts[0])), "leef.vendor": (starts[1], starts[1] + len(parts[1])),
                 "leef.product": (starts[2], starts[2] + len(parts[2])), "leef.product_version": (starts[3], starts[3] + len(parts[3])),
                 "leef.event_id": (starts[4], starts[4] + len(eid))}
    acc = _Acc()
    for k, v in vals.items():
        acc.fields[k] = v
        acc.spans[k] = [(base + off + spans[k][0], base + off + spans[k][1])]
    pos = 0
    for tok in ext.split(delim):
        k, eq, v = tok.partition("=")
        if k:
            vs = off + ext_off + pos + len(k) + len(eq)
            acc.add(k.strip(), v, (base + vs, base + vs + len(v)))
        pos += len(tok) + len(delim)
    return acc


def _zeek(text: str, base: int, o: dict[str, Any], state: ZeekState | None) -> _Acc | None:
    if text.startswith("#"):
        return None
    fields, unset, empty, sep = list(o.get("fields") or []), o.get("unset", "-"), o.get("empty", "(empty)"), "\t"
    if state is not None and state.fields:
        fields, unset, empty, sep = state.fields, state.unset, state.empty, state.sep
    cols, pos = [], 0
    for c in text.split(sep):
        cols.append((c, pos, pos + len(c)))
        pos += len(c) + len(sep)
    acc = _Acc()
    for name, (v, s, e) in zip(fields, cols):
        if v != unset and v != empty and v != "":
            acc.fields[name] = v
            acc.spans[name] = [(base + s, base + e)]
    if len(cols) > len(fields):
        acc.fields["_extra"] = sep.join(c[0] for c in cols[len(fields):])
        acc.spans["_extra"] = [(base + cols[len(fields)][1], base + cols[-1][2])]
    return acc


# ---- JSON: a tiny scanner that records value spans per flattened path (display-only: strings may carry escapes)
_WS = " \t\r\n"


def _json_spans(text: str, base: int) -> dict[str, list[Span]]:
    out: dict[str, list[Span]] = {}
    n = len(text)

    def ws(i: int) -> int:
        while i < n and text[i] in _WS:
            i += 1
        return i

    def string(i: int) -> tuple[str, int, int]:
        j = i + 1
        while j < n and text[j] != '"':
            j += 2 if text[j] == "\\" else 1
        raw = text[i:j + 1]
        try:
            val = orjson.loads(raw.encode("utf-8", "surrogateescape"))
        except orjson.JSONDecodeError:
            val = raw[1:-1]
        return val, i + 1, j

    def value(i: int, path: str) -> int:
        i = ws(i)
        c = text[i]
        if c == "{":
            i = ws(i + 1)
            if text[i] == "}":
                return i + 1
            while True:
                key, _s, e = string(ws(i))
                i = ws(e + 1)
                i = ws(i + 1)                                  # ':'
                i = value(i, f"{path}.{key}" if path else key)
                i = ws(i)
                if text[i] == ",":
                    i += 1
                    continue
                return i + 1
        if c == "[":
            start = i
            depth, j = 0, i
            while j < n:
                if text[j] == '"':
                    _v, _s, e = string(j)
                    j = e
                elif text[j] in "[{":
                    depth += 1
                elif text[j] in "]}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out[path] = [(base + start, base + j + 1)]
            return j + 1
        if c == '"':
            _v, s, e = string(i)
            out[path] = [(base + s, base + e)]
            return e + 1
        j = i
        while j < n and text[j] not in ",}] \t\r\n":
            j += 1
        out[path] = [(base + i, base + j)]
        return j

    try:
        value(0, "")
    except (IndexError, ValueError):
        return {}
    return out


# ---- XML: tag scanner mirroring the production walk (display-only)
_TAGRX = re.compile(r"<(/?)([^\s/>!?][^\s/>]*)((?:\s+[^>]*?)?)(/?)>")
_ATTRX = re.compile(r"""([^\s=]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")


def _xml_spans(text: str, base: int, o: dict[str, Any], fields: dict[str, Any]) -> dict[str, list[Span]]:
    strip = o.get("strip_namespaces", True)
    named = o.get("named_children", {}) or {}

    def tag(t: str) -> str:
        return t.split(":", 1)[1] if strip and ":" in t else t

    spans: dict[str, list[Span]] = {}
    seen: dict[str, int] = {}

    def put(key: str, sp: Span) -> None:
        if key not in seen:
            seen[key] = 1
            spans[key] = [sp]
        else:
            seen[key] += 1
            spans[f"{key}_{seen[key]}"] = [sp]

    stack: list[dict[str, Any]] = []
    pos = 0
    for m in _TAGRX.finditer(text):
        if stack and stack[-1]["open_end"] is not None and not stack[-1]["has_child"]:
            stack[-1]["text"] = (pos, m.start())
        closing, name, attrs, selfclose = m.group(1), m.group(2), m.group(3), m.group(4)
        if closing:
            if stack:
                el = stack.pop()
                if not el["has_child"] and el["path"] and el.get("text"):
                    a, b = el["text"]
                    raw = text[a:b]
                    lead = len(raw) - len(raw.lstrip())
                    stripped = raw.strip()
                    if stripped:
                        put(el["path"], (base + a + lead, base + a + lead + len(stripped)))
            pos = m.end()
            continue
        t = tag(name)
        parent = stack[-1] if stack else None
        if parent is not None:
            parent["has_child"] = True
        attr_list = [(am.group(1), am.group(2) if am.group(2) is not None else am.group(3),
                      am.start(2) if am.group(2) is not None else am.start(3)) for am in _ATTRX.finditer(attrs)]
        nm = named.get(t)
        nmval = next((v for k, v, _ in attr_list if nm and tag(k) == nm), None)
        ppath = parent["path"] if parent is not None else ""
        is_root = parent is None
        if is_root:
            path = ""
            for k, v, s in attr_list:
                if k.startswith("xmlns"):
                    continue
                spans[f"@{tag(k)}"] = [(base + m.start(3) + s, base + m.start(3) + s + len(v))]
        else:
            path = f"{ppath}.{nmval if nmval is not None else t}" if ppath else (nmval if nmval is not None else t)
            for k, v, s in attr_list:
                if k.startswith("xmlns") or (nm and tag(k) == nm):
                    continue
                put(f"{path}.@{tag(k)}", (base + m.start(3) + s, base + m.start(3) + s + len(v)))
        el = {"path": path, "has_child": False, "open_end": m.end(), "text": None}
        if selfclose:
            pos = m.end()
            continue
        stack.append(el)
        pos = m.end()
    return {k: v for k, v in spans.items() if k in fields}


def _locate(text: str, base: int, fields: dict[str, Any]) -> dict[str, list[Span]]:
    """Best-effort fallback: find each value's text in order of appearance (never claimed exact)."""
    out: dict[str, list[Span]] = {}
    cursor = 0
    for k, v in fields.items():
        s = str(v)
        if not s:
            continue
        i = text.find(s, cursor)
        if i < 0:
            i = text.find(s)
        if i >= 0:
            out[k] = [(base + i, base + i + len(s))]
            cursor = i + len(s)
    return out


# ----------------------------------------------------------------------------------------------- driver
def trace_extract(pack: CompiledPackImpl, data: bytes, ctx: dict[str, Any]) -> Traced:
    """Run the production extractor (authoritative values), then the span extractor; reconcile."""
    full = data.decode("utf-8", "surrogateescape")
    fields = pack.extract(data, ctx)
    if fields is None:
        raise NoPack("extraction produced nothing")
    msg = full
    base = 0
    if pack.framing == "syslog":
        msg, _ = parse_syslog(full, ctx.get("_recv_ms", 0))
        if full.endswith(msg):
            base = len(full) - len(msg)
        else:
            i = full.find(msg)
            base = i if i >= 0 else -1
    if base < 0:
        return Traced(dict(fields), {}, set(), False)
    o = pack.doc.options
    kind = pack.kind
    acc: _Acc | None = None
    spans: dict[str, list[Span]] | None = None
    try:
        if kind == "kv":
            acc = _kv(msg, base, o)
        elif kind == "regex":
            acc = _regex(msg, base, o)
        elif kind == "csv":
            acc = _csv(msg, base, o)
        elif kind == "cef":
            acc = _cef(msg, base, o)
        elif kind == "leef":
            acc = _leef(msg, base, o)
        elif kind == "tsv_zeek":
            st = ctx.get("_zeek")
            acc = _zeek(msg, base, o, st if isinstance(st, ZeekState) else None)
        elif kind == "json":
            spans = _json_spans(msg, base)
        elif kind == "xml":
            spans = _xml_spans(msg, base, o, fields)
    except (ValueError, IndexError, KeyError, re.error):
        acc, spans = None, None
    if acc is not None:
        if acc.fields == fields:
            return Traced(dict(fields), acc.spans, acc.escaped, True)
        return Traced(dict(fields), _locate(msg, base, fields), set(), False)
    if spans is not None:
        return Traced(dict(fields), {k: v for k, v in spans.items() if k in fields}, set(), False)   # json/xml: display-only
    return Traced(dict(fields), _locate(msg, base, fields), set(), False)


def _byte_map(text: str):  # type: ignore[no-untyped-def]
    """char index -> byte offset (identity for ASCII)."""
    if text.isascii():
        return lambda i: i
    acc = [0]
    for ch in text:
        o = ord(ch)
        acc.append(acc[-1] + (1 if o < 0x80 or 0xDC80 <= o <= 0xDCFF else 2 if o < 0x800 else 3 if o < 0x10000 else 4))
    return lambda i: acc[max(0, min(i, len(acc) - 1))]


# ----------------------------------------------------------------------------------------------- expression provenance
def _op_text(op: Any) -> str:
    name, arg = split_op(op)
    if arg is None:
        return name
    if isinstance(arg, dict):
        inner = ", ".join(f"{k}: {v}" for k, v in arg.items() if k != "map") + (f"map[{len(arg['map'])}]" if "map" in arg else "")
        return f"{name}({inner.strip(', ')})"
    return f"{name}({arg})"


def render_expr(e: Expr) -> str:
    if isinstance(e, Const):
        return f"const {e.value!r}"
    if isinstance(e, FieldRef):
        return f"copy {e.name}"
    if isinstance(e, From):
        src = ",".join(e.names)
        pipe = "".join(f" | {_op_text(o)}" for o in e.pipe)
        return f"from {src}{pipe}" + (f" (default {e.default!r})" if e.default is not None else "")
    if isinstance(e, Coalesce):
        return "coalesce(" + "; ".join(render_expr(x) for x in e.items) + ")"
    assert isinstance(e, When)
    s = f"when {e.field} == {e.eq!r} then {render_expr(e.then) if e.then is not None else 'null'}"
    return s + (f" else {render_expr(e.else_)}" if e.else_ is not None else "")


def producing_sources(e: Expr, view: dict[str, Any], tz: str) -> list[str]:
    """The source fields that actually produced the value (the winning coalesce branch, the taken ``when`` branch)."""
    if isinstance(e, Const):
        return []
    if isinstance(e, FieldRef):
        return [e.name]
    if isinstance(e, From):
        out = list(e.names)
        for op in e.pipe:
            name, arg = split_op(op)
            if name == "strptime" and isinstance(arg, dict) and arg.get("tz_from") in view:
                out.append(arg["tz_from"])
        return out
    if isinstance(e, Coalesce):
        for x in e.items:
            if compile_expr(x, tz)(view) is not None:
                return producing_sources(x, view, tz)
        return []
    assert isinstance(e, When)
    got = view.get(e.field)
    taken = e.then if (got is not None and str(got) == str(e.eq)) else e.else_
    return [e.field] + (producing_sources(taken, view, tz) if taken is not None else [])


# ----------------------------------------------------------------------------------------------- public
def _set_path(d: dict[str, Any], path: str) -> Any:
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def explain_raw(pack: CompiledPackImpl, data: bytes, recv_ms: int, event_id: str = "") -> dict[str, Any]:
    ctx: dict[str, Any] = {"_recv_ms": recv_ms}
    tr = trace_extract(pack, data, ctx)
    text = data.decode("utf-8", "surrogateescape")
    b = _byte_map(text)

    def conv(sp: list[Span]) -> list[dict[str, int]]:
        return [{"start": b(s), "end": b(e)} for s, e in sp]

    env, ref = make_env(data, recv_ms, event_id.split(":")[0] or "00000000-0000-7000-8000-000000000000")
    ctx_keys = tuple(k for k in ctx if k[:1] != "_")
    view = dict(tr.fields)
    for k in ctx_keys:
        view[k] = ctx[k]
    cls_name = pack.select_class(view)
    ev = pack.normalize(dict(tr.fields), env, ref, ctx)[0]
    spec = pack.classes[cls_name]
    exprs = pack.doc.classes.get(cls_name, {})
    tz = pack.default_tz

    rows: list[dict[str, Any]] = []
    # class selection is provenance too: which field decided the class
    for i, r in enumerate(pack.doc.select):
        if r.when_field is None or (view.get(r.when_field) is not None and str(view.get(r.when_field)) == str(r.when_eq)):
            sf = [r.when_field] if r.when_field else []
            rows.append({"ocsf_path": "class_uid", "value": ev["class_uid"], "source_fields": sf,
                         "spans": [s for f in sf for s in conv(tr.spans.get(f, []))],
                         "expr": f"select -> {r.cls}" + (f" when {r.when_field} == {r.when_eq!r}" if r.when_field else " (otherwise)"),
                         "pack_rule": f"select[{i}]"})
            break
    for st in spec.setters:
        v = st.fn(view)
        if v is None:
            continue
        e = exprs[st.path]
        sf = [f for f in dict.fromkeys(producing_sources(e, view, tz)) if f in view]
        sp = [s for f in sf for s in conv(tr.spans.get(f, []))]
        rows.append({"ocsf_path": st.path, "value": _set_path(ev, st.path), "source_fields": sf, "spans": sp, "expr": render_expr(e),
                     "pack_rule": f"classes.{cls_name}.set.{st.path}"})
    um = ev.get("unmapped", {})
    unmapped = [{"field": k, "value": v, "spans": conv(tr.spans.get(k, []))} for k, v in um.items()]
    ign = ev["ulpf"].get("ignored", {})
    ignored = [{"field": k, "reason": r, "spans": conv(tr.spans.get(k, []))} for k, r in ign.items()]
    fmt = FORMAT_OF.get(pack.kind, "text")
    exact = tr.exact and fmt not in ("json", "xml")
    out: dict[str, Any] = {
        "event_id": event_id or ev["ulpf"]["event_id"], "source_id": pack.id, "pack_id": pack.id, "pack_version": pack.version,
        "format": fmt, "raw_len": len(data), "spans_exact": exact, "fields": rows, "unmapped": unmapped,
    }
    if ignored:
        out["ignored"] = ignored
    return out


def explain_event(registry: Any, data: bytes, event: dict[str, Any]) -> dict[str, Any]:
    """Explain a stored event: pack by ``ulpf.source_id`` (the pack that produced it), else full detection."""
    from ..detect import Detector

    u = event.get("ulpf", {})
    recv_ms = int(u.get("recv_time") or 0)
    ps = registry.snapshot
    pack = ps.by_id.get(str(u.get("source_id", "")))
    if pack is None or u.get("status") == "unparsed":
        raise NoPack(f"event {u.get('event_id')} was not parsed by any pack")
    try:
        return explain_raw(pack, data, recv_ms, str(u.get("event_id", "")))
    except NoPack:
        d = Detector(lambda: ps, use_cache=False).detect(data, "explain", None, recv_ms)
        if d is None:
            raise
        return explain_raw(d.pack, data, recv_ms, str(u.get("event_id", ""))) | {"note": "re-detected with a different pack"}
