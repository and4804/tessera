"""Reference interpreter for the pack DSL (docs/pack-dsl.md) — lives in ulpf.onboard so onboarding previews and tests can run
without the production engine (`ulpf.packs`). tools/packref.py is the CLI wrapper.

PURPOSE: authoring/CI aid so packs and golden vectors can be validated independently of the production engine
(`ulpf.packs` + `ulpf.extract` + `ulpf.normalize`).  It is deliberately simple, slow and NOT used in the hot path.
`tests/golden/` runs the production engine when importable and this interpreter otherwise; when both exist
they are cross-checked (tests/golden/test_engines_agree.py).

Closed DSL only (R7): no eval/exec, yaml.safe_load, fixed op table.

CLI:  python -m tools.packref [packs_dir]      -> run every pack's tests[] and print a summary (see tools/packref.py)
"""
from __future__ import annotations

import calendar
import csv
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

try:  # PyYAML ships a C loader on most platforms
    _Loader = yaml.CSafeLoader
except AttributeError:  # pragma: no cover
    _Loader = yaml.SafeLoader

OCSF_VERSION = "1.3.0"
CLASS_UID = {"base_event": 0, "detection_finding": 2004, "authentication": 3002, "network_activity": 4001, "http_activity": 4002,
             "dns_activity": 4003}
CATEGORY_UID = {0: 0, 2004: 2, 3002: 3, 4001: 4, 4002: 4, 4003: 4}
PROTO = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre", 50: "esp", 51: "ah", 58: "ipv6-icmp", 89: "ospf", 132: "sctp"}
KNOWN_OPS = {"str", "int", "float", "lower", "upper", "strip", "ip", "port", "mac", "epoch_s", "epoch_ms", "epoch_ns", "iso8601", "strptime",
             "lookup", "regex", "split", "concat", "mul", "proto_name"}
MAX_INPUT = 1 << 16
_MISSING = object()


# ------------------------------------------------------------------------------------------------ syslog framing
_PRI = re.compile(rb"^<(\d{1,3})>")
_RFC5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\](?= |$)|(?:\[.*?\])+)(?: (.*))?$", re.S)
_RFC3164 = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) (.*)$", re.S)
_TAG = re.compile(r"^([\w./-]+)(?:\[(\d+)\])?:(?: (.*))?$", re.S)
_MON = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def parse_syslog(text: str, recv_ms: int) -> tuple[str, dict[str, Any]]:
    """Return (message, ctx). ctx has syslog.* keys when a header was recognised."""
    ctx: dict[str, Any] = {}
    rest = text
    m = re.match(r"^<(\d{1,3})>", rest)
    if m:
        ctx["syslog.pri"] = int(m.group(1))
        rest = rest[m.end():]
    m5 = _RFC5424.match(rest)
    if m5:
        ts, host, app, pid, _mid, _sd, msg = m5.groups()
        ctx["syslog.ts"] = None if ts == "-" else ts
        if host != "-":
            ctx["syslog.host"] = host
        if app != "-":
            ctx["syslog.app"] = app
        if pid != "-":
            ctx["syslog.pid"] = pid
        # structured data is kept as part of the message for kv/other extractors
        sd = _sd if _sd != "-" else ""
        return ((sd + " " + (msg or "")).strip() if sd else (msg or "")), ctx
    m3 = _RFC3164.match(rest)
    if m3:
        mon, day, hh, mm, ss, tail = m3.groups()
        recv_year = datetime.fromtimestamp(recv_ms / 1000, tz=timezone.utc).year
        year = recv_year
        try:
            ts_ms = calendar.timegm((year, _MON[mon], int(day), int(hh), int(mm), int(ss)))
            if ts_ms * 1000 > recv_ms + 86400_000 * 2:  # December log received in January -> previous year
                year -= 1
        except (KeyError, ValueError):
            pass
        ctx["syslog.ts"] = f"{year:04d}-{_MON.get(mon, 1):02d}-{int(day):02d}T{hh}:{mm}:{ss}Z"
        ctx["syslog.time_quality"] = "assumed_tz"
        mt = _TAG.match(tail)
        if mt:  # "tag[pid]: msg" without host (pfSense quirk)
            ctx["syslog.app"], pid, msg = mt.group(1), mt.group(2), mt.group(3) or ""
            if pid:
                ctx["syslog.pid"] = pid
            return msg, ctx
        parts = tail.split(" ", 1)
        if len(parts) == 2:
            ctx["syslog.host"] = parts[0]
            mt = _TAG.match(parts[1])
            if mt:
                ctx["syslog.app"], pid, msg = mt.group(1), mt.group(2), mt.group(3) or ""
                if pid:
                    ctx["syslog.pid"] = pid
                return msg, ctx
            return parts[1], ctx
        return tail, ctx
    return rest, ctx  # no recognisable header (e.g. FortiGate "<189>date=...")


# ------------------------------------------------------------------------------------------------ extractors
def _dedup_set(out: dict[str, Any], k: str, v: Any) -> None:
    if k not in out:
        out[k] = v
        return
    i = 2
    while f"{k}_{i}" in out:
        i += 1
    out[f"{k}_{i}"] = v


def ex_kv(text: str, o: dict) -> dict | None:
    ps, ks, q = o.get("pair_sep", " "), o.get("kv_sep", "="), o.get("quote", '"')
    out: dict[str, Any] = {}
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] == ps:
            i += 1
        j = text.find(ks, i)
        if j < 0:
            break
        key = text[i:j]
        if ps in key or not key:  # token without '=': skip it
            k2 = text.find(ps, i)
            if k2 < 0:
                break
            i = k2 + 1
            continue
        i = j + len(ks)
        if i < n and text[i] == q:
            i += 1
            buf = []
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if c == q:
                    i += 1
                    break
                buf.append(c)
                i += 1
            val = "".join(buf)
        else:
            e = text.find(ps, i)
            e = n if e < 0 else e
            val = text[i:e]
            i = e
        _dedup_set(out, key, val)
    return out or None


_RX_CACHE: dict[str, re.Pattern[str]] = {}


def _rx(p: str) -> re.Pattern[str]:
    c = _RX_CACHE.get(p)
    if c is None:
        if len(_RX_CACHE) > 512:
            _RX_CACHE.clear()
        c = _RX_CACHE[p] = re.compile(p)
    return c


def ex_regex(text: str, o: dict) -> dict | None:
    """regex extractor. `anchor` (+ optional `dispatch_on`/`patterns`) per spec 7.5/7.6.
    EXTENSION (needed by Onboarding Studio for free-text sources with several structural variants):
    `alternatives: [regex, ...]` are tried in order when `anchor` does not match; group names are shared."""
    m = None
    for rx in [o["anchor"], *o.get("alternatives", [])]:
        cr = _rx(rx)
        m = cr.match(text) if rx.startswith("^") else cr.search(text)
        if m:
            break
    if not m:
        return None
    out = {k: v for k, v in m.groupdict().items() if v is not None and not (k == "_residual" and v == "")}
    disp = o.get("dispatch_on")
    if disp:
        pat = (o.get("patterns") or {}).get(str(out.get(disp)))
        body = out.get(o.get("dispatch_text", "body"), "")
        if pat:
            m2 = _rx(pat).match(body)
            if m2:
                out.update({k: v for k, v in m2.groupdict().items() if v is not None})
                if m2.end() < len(body):
                    out["_residual"] = body[m2.end():]
    return out


def _flat(prefix: str, v: Any, out: dict) -> None:
    if isinstance(v, dict):
        for k, x in v.items():
            _flat(f"{prefix}.{k}" if prefix else k, x, out)
    else:
        out[prefix] = v


def ex_json(text: str, o: dict) -> dict | None:
    try:
        d = json.loads(text)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    out: dict[str, Any] = {}
    _flat("", d, out)
    return out


def _csv_layout(row: list[str], layout: dict, out: dict, pos: int) -> int:
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
            pos = _csv_layout(row, sub, out, pos)
    return pos


def ex_csv(text: str, o: dict) -> dict | None:
    sep = o.get("sep", ",")
    row = next(csv.reader([text], delimiter=sep), [])
    if len(row) < 2:
        return None
    out: dict[str, Any] = {}
    end = _csv_layout(row, o, out, 0)
    if end < len(row):
        out["_extra"] = sep.join(row[end:])
    return out or None


def _split_esc(s: str, sep: str, maxsplit: int) -> list[str]:
    parts, buf, i = [], [], 0
    while i < len(s) and len(parts) < maxsplit:
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            buf.append(s[i:i + 2])
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


def ex_cef(text: str, o: dict) -> dict | None:
    i = text.find("CEF:")
    if i < 0:
        return None
    text = text[i + 4:]
    parts = _split_esc(text, "|", 7)
    if len(parts) < 8:
        return None
    unesc = lambda s: s.replace("\\|", "|").replace("\\\\", "\\")  # noqa: E731
    ver, vendor, product, dver, sig, name, sev, ext = parts
    out: dict[str, Any] = {"cef.version": ver, "cef.vendor": unesc(vendor), "cef.product": unesc(product), "cef.device_version": unesc(dver),
                           "cef.signature_id": unesc(sig), "cef.name": unesc(name), "cef.severity": sev}
    for tok in re.split(r"\s(?=\w+=)", ext):
        k, _, v = tok.partition("=")
        if k:
            _dedup_set(out, k, v.replace("\\=", "=").replace("\\\\", "\\").replace("\\n", "\n"))
    return out


def ex_leef(text: str, o: dict) -> dict | None:
    i = text.find("LEEF:")
    if i < 0:
        return None
    text = text[i + 5:]
    ver = text.split("|", 1)[0]
    two = ver.startswith("2")
    parts = text.split("|", 5 if two else 4)
    if len(parts) < (6 if two else 5):
        return None
    delim = "\t"
    if two:
        _v, vendor, product, pver, eid, rest = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        dl, _, ext = rest.partition("|")
        if dl:
            m = re.fullmatch(r"(?:0?x|\\x)([0-9a-fA-F]{2})", dl)
            delim = chr(int(m.group(1), 16)) if m else dl
    else:
        _v, vendor, product, pver, ext = parts[0], parts[1], parts[2], parts[3], parts[4]
        eid, _, ext = ext.partition("|")
    out: dict[str, Any] = {"leef.version": ver, "leef.vendor": vendor, "leef.product": product, "leef.product_version": pver, "leef.event_id": eid}
    for tok in ext.split(delim):
        k, _, v = tok.partition("=")
        if k:
            _dedup_set(out, k.strip(), v)
    return out


def ex_xml(text: str, o: dict) -> dict | None:
    import xml.etree.ElementTree as ET
    if "<!DOCTYPE" in text or "<!ENTITY" in text:  # no DTD / entity expansion (XXE, billion laughs)
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    strip = o.get("strip_namespaces", True)
    named = o.get("named_children", {})
    out: dict[str, Any] = {}

    def tag(t: str) -> str:
        return t.split("}", 1)[1] if strip and t.startswith("{") else t

    def walk(el, path: str) -> None:
        t = tag(el.tag)
        p = f"{path}.{t}" if path else t
        nm = named.get(t)
        if nm and nm in el.attrib:
            p = f"{path}.{el.attrib[nm]}" if path else el.attrib[nm]
        for k, v in el.attrib.items():
            if nm and k == nm:
                continue
            _dedup_set(out, f"{p}.@{tag(k)}", v)
        txt = (el.text or "").strip()
        if txt and len(el) == 0:
            _dedup_set(out, p, txt)
        for c in el:
            walk(c, p)

    for c in root:
        walk(c, "")
    for k, v in root.attrib.items():
        out[f"@{k}"] = v
    return out or None


def ex_tsv_zeek(text: str, o: dict) -> dict | None:
    if text.startswith("#"):
        return None
    cols = text.split("\t")
    fields = o["fields"]
    unset, empty = o.get("unset", "-"), o.get("empty", "(empty)")
    out: dict[str, Any] = {}
    for name, v in zip(fields, cols, strict=False):
        if v not in (unset, empty, ""):
            out[name] = v
    if len(cols) > len(fields):
        out["_extra"] = "\t".join(cols[len(fields):])
    return out or None


EXTRACTORS = {"kv": ex_kv, "regex": ex_regex, "json": ex_json, "csv": ex_csv, "cef": ex_cef, "leef": ex_leef, "xml": ex_xml, "tsv_zeek": ex_tsv_zeek}


# ------------------------------------------------------------------------------------------------ expression evaluation
def _tz_offset_s(tz: Any) -> int:
    if tz is None:
        return 0
    s = str(tz).strip()
    if s.upper() in ("UTC", "Z", "GMT", ""):
        return 0
    m = re.fullmatch(r"([+-])(\d\d):?(\d\d)", s)
    if not m:
        raise ValueError(tz)
    return (1 if m.group(1) == "+" else -1) * (int(m.group(2)) * 3600 + int(m.group(3)) * 60)


def _apply(op: Any, v: Any, fields: dict) -> Any:
    if v is None:
        return None
    name, arg = (op, None) if isinstance(op, str) else next(iter(op.items()))
    try:
        if name == "str":
            return str(v)
        if name == "int":
            if isinstance(v, bool):
                return int(v)
            if isinstance(v, int):
                return v
            if isinstance(v, float):
                return int(v)
            return int(str(v).strip(), 10)
        if name == "float":
            return float(v)
        if name == "lower":
            return str(v).lower()
        if name == "upper":
            return str(v).upper()
        if name == "strip":
            return str(v).strip()
        if name == "ip":
            return str(ipaddress.ip_address(str(v).strip()))
        if name == "port":
            return v if isinstance(v, int) and 0 <= v <= 65535 else None
        if name == "mac":
            h = re.sub(r"[^0-9a-fA-F]", "", str(v))
            return ":".join(h[i:i + 2] for i in range(0, 12, 2)).lower() if len(h) == 12 else None
        if name == "epoch_s":
            return int(round(float(v) * 1000))
        if name == "epoch_ms":
            return int(v)
        if name == "epoch_ns":
            return int(v) // 1_000_000
        if name == "iso8601":
            s = str(v).strip().replace("Z", "+00:00")
            m = re.match(r"^(.*?\.\d{6})\d+(.*)$", s)  # truncate >6 fractional digits
            if m:
                s = m.group(1) + m.group(2)
            d = datetime.fromisoformat(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return calendar.timegm(d.utctimetuple()) * 1000 + d.microsecond // 1000
        if name == "strptime":
            d = datetime.strptime(str(v), arg["fmt"])
            off = _tz_offset_s(fields.get(arg["tz_from"]) if "tz_from" in arg else arg.get("tz"))
            return (calendar.timegm(d.timetuple()) - off) * 1000
        if name == "lookup":
            m = {str(k): x for k, x in arg["map"].items()}
            key = str(v)
            if key in m:
                return m[key]
            return arg.get("default")
        if name == "regex":
            m = re.search(arg["pattern"], str(v))
            return m.group(arg.get("group", 1)) if m else None
        if name == "split":
            parts = str(v).split(arg["sep"])
            return parts[arg["index"]]
        if name == "mul":
            return v * arg
        if name == "proto_name":
            return PROTO.get(int(v))
    except (ValueError, TypeError, KeyError, IndexError, OverflowError):
        return None
    raise ValueError(f"unknown op {name}")


def _op_name(op: Any) -> str:
    return op if isinstance(op, str) else next(iter(op))


def _concat_sep(op: Any) -> str | None:
    if isinstance(op, dict) and "concat" in op:
        c = op["concat"]
        return c if isinstance(c, str) else c.get("sep", "")
    return None


def _val(fields: dict, name: str) -> Any:
    v = fields.get(name)
    return None if v == "" else v          # an empty value is "no value": never mapped, stays visible in unmapped


def evaluate(expr: Any, fields: dict) -> Any:
    if isinstance(expr, str):
        return _val(fields, expr)
    if "const" in expr:
        return expr["const"]
    if "coalesce" in expr:
        for e in expr["coalesce"]:
            v = evaluate(e, fields)
            if v is not None:
                return v
        return expr.get("default")
    if "when" in expr:
        c = expr["when"]
        got = fields.get(c["field"])
        ok = got is not None and str(got) == str(c["eq"])
        branch = expr.get("then") if ok else expr.get("else")
        return None if branch is None else evaluate(branch, fields)
    if "from" in expr:
        src = expr["from"]
        v: Any = [_val(fields, s) for s in src] if isinstance(src, list) else _val(fields, src)
        if isinstance(src, list) and any(x is None for x in v):
            v = None
        for op in expr.get("pipe", []):
            if v is None:
                break
            sep = _concat_sep(op)
            if sep is not None:
                v = sep.join(str(x) for x in v) if isinstance(v, list) else str(v)
                continue
            v = _apply(op, v, fields)
        return expr.get("default") if v is None else v
    raise ValueError(f"bad expression {expr!r}")


def referenced_fields(expr: Any, acc: set[str]) -> None:
    if isinstance(expr, str):
        acc.add(expr)
    elif isinstance(expr, dict):
        if "from" in expr:
            f = expr["from"]
            acc.update(f if isinstance(f, list) else [f])
            for op in expr.get("pipe", []):
                if isinstance(op, dict) and "strptime" in op and "tz_from" in op["strptime"]:
                    acc.add(op["strptime"]["tz_from"])
        if "coalesce" in expr:
            for e in expr["coalesce"]:
                referenced_fields(e, acc)
        if "when" in expr:
            acc.add(expr["when"]["field"])
            for k in ("then", "else"):
                if k in expr:
                    referenced_fields(expr[k], acc)


# ------------------------------------------------------------------------------------------------ pack
def _set_path(d: dict, path: str, v: Any) -> None:
    parts = path.split(".")
    for p in parts[:-1]:
        d = d.setdefault(p, {})
    d[parts[-1]] = v


def get_path(d: Any, path: str) -> Any:
    """Resolve dotted path; tolerate dotted *keys* (e.g. unmapped['alert.category'])."""
    if not path:
        return d
    if isinstance(d, dict):
        if path in d:
            return d[path]
        parts = path.split(".")
        for i in range(1, len(parts)):
            head = ".".join(parts[:i])
            if head in d:
                r = get_path(d[head], ".".join(parts[i:]))
                if r is not None:
                    return r
    return None


class Pack:
    def __init__(self, doc: dict, path: str = ""):
        self.doc, self.path = doc, path
        self.id, self.version = doc["id"], doc.get("version", "0")
        self.priority = doc.get("match", {}).get("priority", 0)
        self.framing = doc.get("framing", "none")
        self.kind = doc["extract"]["kind"]
        self.options = doc["extract"].get("options") or {}
        self.extract_fn = EXTRACTORS[self.kind]
        self.ignore = set((doc.get("ignore") or {}).keys())
        self.consumed: dict[str, set[str]] = {}
        for cname, c in doc.get("classes", {}).items():
            acc: set[str] = set()
            for e in c["set"].values():
                referenced_fields(e, acc)
            self.consumed[cname] = acc
        sel_acc: set[str] = set()
        for r in doc.get("select", []):
            if "when" in r:
                sel_acc.add(r["when"]["field"])
        self.select_fields = sel_acc

    # -- match
    def _preds(self, preds: list[dict], text: str, fields: dict | None) -> list[bool]:
        res = []
        for p in preds:
            if "contains" in p:
                res.append(p["contains"] in text)
            elif "starts_with" in p:
                res.append(text.startswith(p["starts_with"]))
            elif "regex" in p:
                res.append(re.search(p["regex"], text[:MAX_INPUT]) is not None)
            elif "field_eq" in p:
                f = p["field_eq"]
                res.append(fields is not None and str(fields.get(f["field"])) == str(f["value"]))
            else:
                raise ValueError(f"unknown predicate {p}")
        return res

    def match(self, data: bytes) -> bool:
        text = data.decode("utf-8", "surrogateescape")
        m = self.doc.get("match", {})
        if m.get("all") and not all(self._preds(m["all"], text, None)):
            return False
        if m.get("any") and not any(self._preds(m["any"], text, None)):
            return False
        return bool(m.get("all") or m.get("any"))

    # -- extract
    def extract(self, data: bytes, recv_ms: int = 0) -> tuple[dict | None, dict]:
        text = data.decode("utf-8", "surrogateescape")
        ctx: dict[str, Any] = {}
        if self.framing == "syslog":
            text, ctx = parse_syslog(text, recv_ms)
        f = self.extract_fn(text[:MAX_INPUT], self.options)
        return f, ctx

    # -- normalize
    def normalize(self, fields: dict, ctx: dict, recv_ms: int = 0) -> dict:
        view = {**fields, **ctx}
        cls = "base_event"
        for r in self.doc.get("select", []):
            if "otherwise" in r:
                cls = r["otherwise"]
                break
            c = r["when"]
            got = view.get(c["field"])
            if got is not None and str(got) == str(c["eq"]):
                cls = r["class"]
                break
        cdef = self.doc.get("classes", {}).get(cls, {"set": {}})
        ev: dict[str, Any] = {}
        used: set[str] = set()
        for path, expr in cdef["set"].items():
            v = evaluate(expr, view)
            if v is not None:
                _set_path(ev, path, v)
                referenced_fields(expr, used)   # a field is "consumed" only if an expression that used it produced a value
        cuid = CLASS_UID[cls]
        ev["class_uid"] = cuid
        ev["category_uid"] = CATEGORY_UID[cuid]
        ev["type_uid"] = cuid * 100 + int(ev.get("activity_id", 0))
        # lossless refinement: a source field whose mapping produced null (e.g. invalid IP) stays in `unmapped`
        used |= self.ignore
        unmapped = {k: v for k, v in fields.items() if k not in used}
        status = "parsed"
        quality = ctx.get("syslog.time_quality", "source_tz") if "syslog.ts" in self.consumed.get(cls, set()) else "source_tz"
        if "time" not in ev:
            ev["time"] = recv_ms
            status, quality = "partial", "recv_time"
        ev["metadata"] = {**ev.get("metadata", {}), "version": OCSF_VERSION,
                          "product": {"name": self.doc.get("meta", {}).get("product"), "vendor_name": self.doc.get("meta", {}).get("vendor")}}
        ev["unmapped"] = unmapped
        ev["ulpf"] = {"source_id": self.id, "pack_version": self.version, "status": status, "time_quality": quality,
                      "schema": f"ocsf-{OCSF_VERSION}"}
        return ev

    def process(self, data: bytes, recv_ms: int = 0) -> dict | None:
        fields, ctx = self.extract(data, recv_ms)
        if fields is None:
            return None
        return self.normalize(fields, ctx, recv_ms)


def load_pack(path: str | Path) -> Pack:
    with open(path, encoding="utf-8") as f:
        return Pack(yaml.load(f, Loader=_Loader), str(path))


def load_packs(root: str | Path) -> list[Pack]:
    packs = [load_pack(p) for p in sorted(Path(root).rglob("*.yaml"))]
    packs.sort(key=lambda p: -p.priority)
    return packs


def detect(packs: list[Pack], data: bytes) -> Pack | None:
    for p in packs:
        if p.match(data):
            return p
    return None


RECV_MS = calendar.timegm((2026, 10, 4, 13, 30, 0)) * 1000   # recv clock used by golden tests (RFC 3164 year inference)


def process_raw(packs: list[Pack], data: bytes, recv_ms: int = RECV_MS) -> dict:
    """Detect -> extract -> normalize with the terminal-state rule (never raises)."""
    p = detect(packs, data)
    ev = None
    if p is not None:
        try:
            ev = p.process(data, recv_ms)
        except Exception:  # noqa: BLE001
            ev = None
    if ev is None:
        ev = {"class_uid": 0, "category_uid": 0, "type_uid": 0, "time": recv_ms, "message": data.decode("utf-8", "replace"),
              "ulpf": {"status": "unparsed", "source_id": p.id if p else None}}
    return ev


# ------------------------------------------------------------------------------------------------ test runner / lint
def run_tests(pack: Pack) -> list[str]:
    fails: list[str] = []
    for t in pack.doc.get("tests", []):
        raw = t["raw"].encode("utf-8", "surrogateescape")
        name = f"{pack.id}::{t['name']}"
        if not pack.match(raw):
            fails.append(f"{name}: pack.match() is False")
            continue
        try:
            ev = pack.process(raw, RECV_MS)
        except Exception as e:  # noqa: BLE001
            fails.append(f"{name}: exception {type(e).__name__}: {e}")
            continue
        if ev is None:
            ev = {"ulpf": {"status": "unparsed"}}
        for path, want in (t.get("expect") or {}).items():
            got = get_path(ev, path)
            if got != want or type(got) is not type(want) and not (got is None and want is None):
                fails.append(f"{name}: {path}: expected {want!r} got {got!r}")
    return fails


def lint(pack: Pack, min_tests: int = 5) -> list[str]:
    errs: list[str] = []
    d = pack.doc
    for k in ("pack", "id", "version", "meta", "match", "extract", "select", "classes", "tests"):
        if k not in d:
            errs.append(f"{pack.id}: missing key {k}")
    if d.get("verified") is not False:
        errs.append(f"{pack.id}: R12 requires verified: false on shipped packs")
    if len(d.get("tests", [])) < min_tests:
        errs.append(f"{pack.id}: needs >= {min_tests} tests")
    for cname, c in d.get("classes", {}).items():
        if cname not in CLASS_UID:
            errs.append(f"{pack.id}: unknown class {cname}")
        for path, expr in c["set"].items():
            stack = [expr]
            while stack:
                e = stack.pop()
                if isinstance(e, dict):
                    for op in e.get("pipe", []):
                        if _op_name(op) not in KNOWN_OPS:
                            errs.append(f"{pack.id}: {cname}.{path}: unknown op {_op_name(op)}")
                    for k in ("coalesce",):
                        stack.extend(e.get(k, []))
                    for k in ("then", "else"):
                        if k in e:
                            stack.append(e[k])
    for r in d.get("select", []):
        if "class" in r and r["class"] not in d.get("classes", {}):
            errs.append(f"{pack.id}: select refers to undefined class {r['class']}")
        if "otherwise" in r and r["otherwise"] not in d.get("classes", {}) and r["otherwise"] != "base_event":
            errs.append(f"{pack.id}: otherwise refers to undefined class {r['otherwise']}")
    for rx in re.findall(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*]", json.dumps(d.get("extract", {}))):
        errs.append(f"{pack.id}: possible nested quantifier (ReDoS): {rx}")
    return errs


def main(argv: list[str] | None = None) -> int:
    root = (argv or sys.argv[1:] or ["packs"])[0]
    bad = 0
    for p in load_packs(root):
        errs = lint(p) + run_tests(p)
        n = len(p.doc.get("tests", []))
        print(f"{'FAIL' if errs else 'ok  '} {p.id:28s} {n} vectors")
        for e in errs:
            print("   ", e)
        bad += len(errs)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
