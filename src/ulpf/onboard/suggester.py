"""OCSF suggestion + draft-pack generation (steps 5 and 6 of §7.11). Pure functions, no I/O except reading aliases.yaml."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import miner
from .inferer import FieldInfo, Sniff

ALIASES_PATH = Path(__file__).with_name("aliases.yaml")

CLASS_DOMAIN = {  # path prefixes that make sense per class (others stay in `unmapped`, honestly)
    "network_activity": ("src_endpoint", "dst_endpoint", "connection_info", "traffic", "duration", "action_id", "disposition_id",
                         "severity_id", "device", "message", "user", "activity_id"),
    "http_activity": ("src_endpoint", "dst_endpoint", "http_request", "http_response", "traffic", "duration", "action_id", "disposition_id",
                      "severity_id", "device", "message", "user", "activity_id", "connection_info"),
    "dns_activity": ("src_endpoint", "dst_endpoint", "query", "severity_id", "device", "message", "activity_id", "connection_info"),
    "authentication": ("src_endpoint", "dst_endpoint", "user", "status_id", "severity_id", "device", "message", "activity_id"),
    "detection_finding": ("src_endpoint", "dst_endpoint", "finding_info", "action_id", "disposition_id", "severity_id", "device", "message",
                          "connection_info", "activity_id"),
    "base_event": ("severity_id", "device", "message"),
}
CLASS_CATEGORY = {"network_activity": "firewall", "http_activity": "proxy", "dns_activity": "dns", "authentication": "authentication",
                  "detection_finding": "ids", "base_event": "unknown"}


def norm(name: str) -> str:
    return re.sub(r"[^0-9a-z]", "", name.lower())


@lru_cache(maxsize=1)
def load_aliases() -> dict[str, Any]:
    with open(ALIASES_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


@dataclass
class Suggestion:
    path: str
    field: str
    score: float
    reason: str


@dataclass
class Mapping:
    suggestions: list[Suggestion] = field(default_factory=list)
    class_name: str = "base_event"
    renames: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def by_path(self) -> dict[str, Suggestion]:
        return {s.path: s for s in self.suggestions}


NULLISH = {"n/a", "na", "none", "null", "-", "unknown", "(null)", "nil", ""}
_GENERIC = re.compile(r"^(field|col|alt|f)_?\d*$|^_")


def value_hint_renames(fields: dict[str, FieldInfo]) -> dict[str, str]:
    """Generic names (field_3, col_7...) are renamed from their observed values (e.g. {input,forward,output} -> chain)."""
    al = load_aliases()
    hints = al.get("value_hints", {})
    target_name = {"connection_info.protocol_name": "proto", "connection_info.direction_id": "chain", "http_request.http_method": "method",
                   "action_id": "action"}
    out: dict[str, str] = {}
    taken = set(fields)
    for name, fi in fields.items():
        if not _GENERIC.match(name) or len(fi.values) == 0:
            continue
        vals = {v.lower() for v in fi.values}
        best, bestfrac = None, 0.0
        for path, words in hints.items():
            frac = len(vals & set(words)) / len(vals)
            if frac > bestfrac:
                best, bestfrac = path, frac
        if best and bestfrac >= 0.9:
            new = target_name[best]
            if new not in taken:
                out[name] = new
                taken.add(new)
    return out


def _name_score(name: str, aliases: list[str]) -> tuple[float, str]:
    n = norm(name)
    base = re.sub(r"\d+$", "", n)
    if n in aliases:
        return 1.0, "name"
    if base and base != n and base in aliases:
        return 0.9, "name~"
    return 0.0, ""          # no fuzzy/partial matching: "dst-nat-rule-name" must not look like a signature name


def _type_ok(path: str, fi: FieldInfo, types: list[str]) -> bool:
    if fi.type in types:
        return True
    if fi.type == "enum" and "text" in types:
        return True
    if fi.type == "text" and "enum" in types:
        return True
    if fi.type == "port" and "int" in types:
        return True
    if fi.type == "int" and "port" in types:
        return True
    if fi.type == "int" and "float" in types:
        return True
    return False


def suggest(fields: dict[str, FieldInfo], sniff: Sniff | None = None) -> Mapping:
    al = load_aliases()
    paths: dict[str, dict] = al["paths"]
    order = {p: i for i, p in enumerate(paths)}
    cands: list[tuple[float, int, str, str, str]] = []
    for fname, fi in fields.items():
        if fname.startswith("syslog.") or fname.startswith("_"):
            continue
        for path, spec in paths.items():
            sc, why = _name_score(fname, spec["names"])
            if sc == 0:
                continue
            if not _type_ok(path, fi, spec["types"]):
                sc *= 0.3
            # value-aware disambiguation of ambiguous generic names
            vals = [v.lower() for v in fi.values]
            if path == "http_response.code" and fi.type == "int" and vals and all(100 <= int(v) <= 599 for v in vals if v.isdigit()):
                sc = max(sc, 0.95) if norm(fname) in ("status", "code", "result") else sc
            if path in ("action_id", "status_id") and norm(fname) in ("status", "result", "outcome"):
                words = set(vals)
                a1 = set(al["enums"]["action_id"][1]) | set(al["enums"]["action_id"][2])
                s1 = set(al["enums"]["status_id"][1]) | set(al["enums"]["status_id"][2])
                if path == "action_id" and words and len(words & a1) / len(words) < 0.5:
                    sc *= 0.3
                if path == "status_id" and words and len(words & s1) / len(words) < 0.5:
                    sc *= 0.3
            if path == "severity_id" and fi.type != "enum" and not vals:
                sc *= 0.3
            if vals and sum(1 for v in vals if v.strip().lower() in NULLISH) / len(vals) >= 0.95:
                sc *= 0.2          # a field that only ever says N/A / none / - carries no mapped information
            cands.append((sc, -order[path], fname, path, why))
    cands.sort(reverse=True)
    used_f: set[str] = set()
    used_p: set[str] = set()
    sugg: list[Suggestion] = []
    for sc, _o, fname, path, why in cands:
        if sc < 0.5 or fname in used_f or path in used_p:
            continue
        used_f.add(fname)
        used_p.add(path)
        sugg.append(Suggestion(path, fname, round(sc, 2), why))
    m = Mapping(sugg)
    m.class_name = choose_class({s.path for s in sugg})
    dom = CLASS_DOMAIN[m.class_name]
    keep = []
    for s in m.suggestions:
        if s.path.split(".")[0] in dom:
            keep.append(s)
        else:
            m.notes.append(f"{s.field}: {s.path} does not belong to class {m.class_name}; left in unmapped")
    m.suggestions = keep
    return m


def choose_class(paths: set[str]) -> str:
    if "finding_info.title" in paths:
        return "detection_finding"
    if "http_request.url.text" in paths and ("http_request.http_method" in paths or "http_response.code" in paths):
        return "http_activity"
    if "query.hostname" in paths and "src_endpoint.ip" in paths:
        return "dns_activity"
    if "user.name" in paths and "status_id" in paths:
        return "authentication"
    if "src_endpoint.ip" in paths and ("dst_endpoint.ip" in paths or "dst_endpoint.port" in paths):
        return "network_activity"
    if "src_endpoint.ip" in paths or "dst_endpoint.ip" in paths:
        return "network_activity"
    return "base_event"


# ------------------------------------------------------------------------------------------------ expressions
def _enum_map(enum_name: str, observed: list[str]) -> tuple[dict[str, int], list[str]]:
    al = load_aliases()["enums"][enum_name]
    rev = {w: k for k, ws in al.items() for w in ws}
    mapped = {}
    unknown = []
    for v in observed:
        lv = str(v).lower()
        if lv in rev:
            mapped[lv] = rev[lv]
        else:
            unknown.append(v)
    return dict(sorted(mapped.items())), unknown


def time_expression(fields: dict[str, FieldInfo], sniff: Sniff, tz: str) -> tuple[Any, str | None]:
    """Pick the best timestamp source -> (expression or None, field note)."""
    ts_fields = [f for f in fields.values() if f.type == "timestamp" and not f.name.startswith("syslog.")]
    pref = re.compile(r"(^|[^a-z])(event)?time(stamp)?$|^ts$|timestamp|eventtime|devtime|datetime|@timestamp", re.I)

    def expr(fi: FieldInfo) -> Any:
        k = fi.ts_kind
        if k == "iso8601":
            return {"from": fi.name, "pipe": ["iso8601"]}
        if k == "epoch_s":
            return {"from": fi.name, "pipe": ["float", "epoch_s"]}
        if k == "epoch_ms":
            return {"from": fi.name, "pipe": ["int", "epoch_ms"]}
        if k == "epoch_ns":
            return {"from": fi.name, "pipe": ["int", "epoch_ns"]}
        if k in ("datetime", "syslog_ts_year"):
            return {"from": fi.name, "pipe": [{"strptime": {"fmt": fi.ts_fmt, "tz": tz}}]}
        return None

    ranked = sorted(ts_fields, key=lambda f: (0 if pref.search(f.name) else 1, -f.support))
    for fi in ranked:
        e = expr(fi)
        if e is not None and fi.support >= 0.5:
            return e, fi.name
    d = fields.get("date")
    t = fields.get("time")
    if d and t and d.ts_kind == "date" and t.ts_kind == "time":
        return {"from": ["date", "time"], "pipe": [{"concat": " "}, {"strptime": {"fmt": "%Y-%m-%d %H:%M:%S", "tz": tz}}]}, "date+time"
    if sniff.framing == "syslog" and "syslog.ts" in fields and fields["syslog.ts"].support >= 0.5:
        return {"from": "syslog.ts", "pipe": ["iso8601"]}, "syslog.ts"
    return None, None


def build_set(m: Mapping, fields: dict[str, FieldInfo], sniff: Sniff, tz: str = "UTC") -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (`set` mapping for the chosen class, info) where info lists lookups needing human completion."""
    al = load_aliases()
    s: dict[str, Any] = {}
    info: dict[str, Any] = {"unknown_enum_values": {}, "assumed": []}
    for sg in m.suggestions:
        fi = fields[sg.field]
        f = sg.field
        p = sg.path
        vals = [v for v in fi.values]
        if p.endswith(".ip"):
            s[p] = {"from": f, "pipe": ["ip"]}
        elif p.endswith(".port"):
            s[p] = {"from": f, "pipe": ["int", "port"]}
        elif p.endswith(".mac"):
            s[p] = {"from": f, "pipe": ["mac"]}
        elif p == "connection_info.protocol_name":
            s[p] = {"from": f, "pipe": ["lower"]} if fi.type != "int" else {"from": f, "pipe": ["int", "proto_name"]}
            if fi.type != "int":
                s["connection_info.protocol_num"] = {"from": f, "pipe": ["lower", {"lookup": {"map": dict(al["protocol_numbers"])}}]}
        elif p == "connection_info.protocol_num":
            s[p] = {"from": f, "pipe": ["int"]}
            if "connection_info.protocol_name" not in {x.path for x in m.suggestions}:
                s["connection_info.protocol_name"] = {"from": f, "pipe": ["int", "proto_name"]}
        elif p in ("traffic.bytes", "traffic.bytes_in", "traffic.bytes_out", "traffic.packets_in", "traffic.packets_out",
                   "http_response.code", "logon_type_id"):
            s[p] = {"from": f, "pipe": ["int"]}
        elif p == "duration":
            unit_ms = bool(re.search(r"ms|milli", norm(f)))
            if fi.type == "int":
                s[p] = {"from": f, "pipe": ["int"] + ([] if unit_ms else [{"mul": 1000}])}
            else:
                s[p] = {"from": f, "pipe": ["float"] + ([] if unit_ms else [{"mul": 1000}]) + ["int"]}
            if not unit_ms:
                info["assumed"].append(f"{f}: duration assumed to be in seconds (converted to ms)")
        elif p in ("action_id", "disposition_id", "severity_id", "status_id", "connection_info.direction_id"):
            enum = p if p != "connection_info.direction_id" else p
            mp, unknown = _enum_map(enum, vals)
            if p == "action_id":
                dmp, _ = _enum_map("disposition_id", vals)
            if not mp:
                info["unknown_enum_values"][f] = unknown
                continue
            s[p] = {"from": f, "pipe": ["lower", {"lookup": {"map": mp, "default": 0}}]}
            if unknown:
                info["unknown_enum_values"][f] = unknown
            if p == "action_id":
                s["disposition_id"] = {"from": f, "pipe": ["lower", {"lookup": {"map": dmp, "default": 0}}]}
        elif p == "finding_info.uid":
            s[p] = {"from": f, "pipe": ["str"]}
        elif p == "query.hostname":
            s[p] = {"from": f, "pipe": ["lower"]}
        else:
            s[p] = f
    expr, tnote = time_expression(fields, sniff, tz)
    if expr is not None:
        s["time"] = expr
        if tnote and any(isinstance(o, dict) and "strptime" in o for o in expr.get("pipe", [])):
            info["assumed"].append(f"time from {tnote}: no zone in the log, assumed {tz}")
    else:
        info["assumed"].append("no usable timestamp: events will use receive time (time_quality=recv_time)")
    if sniff.framing == "syslog" and "syslog.host" in fields and "device.hostname" not in s and "device" in CLASS_DOMAIN[m.class_name]:
        s["device.hostname"] = "syslog.host"
    cls = m.class_name
    if cls == "network_activity":
        s.setdefault("activity_id", {"const": 6})
    elif cls == "http_activity":
        meth = m.by_path().get("http_request.http_method")
        if meth:
            s["activity_id"] = {"from": meth.field, "pipe": ["upper", {"lookup": {"map": dict(al["http_method_activity"]), "default": 99}}]}
        else:
            s["activity_id"] = {"const": 99}
    else:
        s.setdefault("activity_id", {"const": 1})
    if "severity_id" not in s:
        s["severity_id"] = {"const": 1}
        info["assumed"].append("severity_id defaulted to 1 (Informational): no severity field found")
    return s, info


# ------------------------------------------------------------------------------------------------ match predicate
def match_block(sn: Sniff, fields: dict[str, FieldInfo], synth: miner.Synth | None, raw_lines: list[str]) -> dict[str, Any]:
    all_: list[dict[str, str]] = []
    if sn.format == "kv":
        keys = sorted((f for f in fields.values() if f.support >= 0.95 and not f.name.startswith("syslog.")),
                      key=lambda f: (-len(f.name), f.name))[:2]
        all_ = [{"contains": f"{k.name}="} for k in keys]
    elif sn.format == "json":
        keys = sorted((f for f in fields.values() if f.support >= 0.95), key=lambda f: (-len(f.name), f.name))[:2]
        all_ = [{"starts_with": "{"}] + [{"contains": f'"{k.name.split(".")[-1]}"'} for k in keys]
    elif sn.format == "cef":
        all_ = [{"contains": "CEF:"}]
        v = fields.get("cef.vendor")
        if v and v.distinct == 1:
            all_.append({"contains": v.examples[0]})
    elif sn.format == "leef":
        all_ = [{"contains": "LEEF:"}]
    elif sn.format == "xml":
        all_ = [{"contains": "<Event"}] if any("<Event" in ln for ln in raw_lines[:5]) else []
        if not all_:
            m = re.match(r"\s*<(\w[\w:.-]*)", raw_lines[0])
            all_ = [{"contains": f"<{m.group(1)}" if m else "<"}]
    elif synth is not None and synth.anchors:
        longest = sorted(set(synth.anchors), key=lambda a: (-len(a.strip()), a))[:2]
        all_ = [{"contains": a.strip()} for a in longest]
    if not all_:
        # fall back to the longest common literal prefix of the samples
        pre = raw_lines[0]
        for ln in raw_lines[1:]:
            while not ln.startswith(pre) and pre:
                pre = pre[:-1]
        all_ = [{"contains": pre[:24]}] if len(pre) >= 4 else [{"regex": r"^.{8,}"}]
    return {"priority": 20, "all": all_}


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "source"


def build_pack(label: str | None, vendor: str | None, product: str | None, sn: Sniff, extract: dict[str, Any], match: dict[str, Any],
               m: Mapping, set_expr: dict[str, Any]) -> dict[str, Any]:
    if not vendor and label:
        parts = label.split(None, 1)
        vendor, product = parts[0], (parts[1] if len(parts) > 1 else product)
    vendor = vendor or "Unknown"
    product = product or sn.format
    pid = f"custom.{slug(vendor)}_{slug(product)}"
    classes = {m.class_name: {"set": set_expr}}
    return {
        "pack": 1, "id": pid, "version": "0.1.0", "verified": False,
        "meta": {"vendor": vendor, "product": product, "category": CLASS_CATEGORY[m.class_name]},
        "match": match,
        "framing": "syslog" if sn.framing == "syslog" else "none",
        "extract": extract,
        "select": [{"otherwise": m.class_name}],
        "classes": classes,
        "tests": [],
    }
