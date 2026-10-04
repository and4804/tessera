"""Field-query DSL -> parameterised DuckDB SQL (§7.13, api-contract.md "Query DSL").

``term := ['-'] ( field ':' [op] value | text )``; terms are AND-ed. ``op`` in ``>= <= > <`` (numeric/time fields). A value may be quoted
(``"a b"``, ``\\"`` escape), a comma list (OR), or a numeric range ``a..b``. IP fields accept CIDR (IPv4) and trailing wildcards;
string fields accept ``*``. Bare/quoted ``text`` matches the event document.

Safety: the field name is looked up in a whitelist and only ever mapped to a column from :data:`COLUMN_OF`; every value is passed as a
bound parameter (``?``); LIKE patterns are escaped; length, term and list-size limits apply. No SQL is built from user text."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from ..normalize.lake_schema import FIELD_TYPES
from ..normalize.timeparse import parse_iso8601

MAX_QUERY = 2000
MAX_TERMS = 24
MAX_LIST = 100
STATUSES = ("parsed", "partial", "unparsed")
ACTION_ALIAS = {"allowed": 1, "allow": 1, "permitted": 1, "denied": 2, "deny": 2, "blocked": 2, "block": 2, "unknown": 0}
LIKE_FIELDS = {"url", "signature", "dns_query", "user_name", "device_host", "proto_name", "http_method"}   # case-insensitive text
TIME_FIELDS = {"time", "recv_time"}
EXTRA_FIELDS: dict[str, str] = {   # alias fields that are not lake columns
    "action": "enum",
    "packets_in": "int", "packets_out": "int",
}
FIELDS: dict[str, str] = {**FIELD_TYPES, **EXTRA_FIELDS}
COLUMN_OF = {k: k for k in FIELD_TYPES} | {"action": "action_id"}
OPS = (">=", "<=", ">", "<")


class QueryError(ValueError):
    """Rejected query; the message is shown to the user verbatim (``400 BAD_QUERY``)."""


@dataclass
class Term:
    neg: bool
    field: str | None
    op: str | None
    values: list[str] = field(default_factory=list)
    text: str = ""


def _split_tokens(q: str) -> list[str]:
    toks: list[str] = []
    i, n = 0, len(q)
    while i < n:
        while i < n and q[i].isspace():
            i += 1
        if i >= n:
            break
        j, inq = i, False
        while j < n and (inq or not q[j].isspace()):
            c = q[j]
            if inq and c == "\\" and j + 1 < n:
                j += 2
                continue
            if c == '"':
                inq = not inq
            j += 1
        if inq:
            raise QueryError("unterminated quote")
        toks.append(q[i:j])
        i = j
    return toks


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return re.sub(r'\\(.)', r"\1", s[1:-1])
    return s


def _split_list(v: str) -> list[str]:
    out, buf, inq, i = [], [], False, 0
    while i < len(v):
        c = v[i]
        if inq and c == "\\" and i + 1 < len(v):
            buf.append(v[i:i + 2])
            i += 2
            continue
        if c == '"':
            inq = not inq
        if c == "," and not inq:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


_FIELD_TOKEN = re.compile(r"^(-?)([A-Za-z_][A-Za-z0-9_]*):(.*)$", re.S)


def parse(q: str) -> list[Term]:
    if len(q) > MAX_QUERY:
        raise QueryError(f"query too long (max {MAX_QUERY} characters)")
    terms: list[Term] = []
    for tok in _split_tokens(q):
        m = _FIELD_TOKEN.match(tok)
        if m and not m.group(2).startswith('"'):
            neg, name, rest = bool(m.group(1)), m.group(2), m.group(3)
            if name not in FIELDS:
                raise QueryError(f"unknown field '{name}'. Known fields: {', '.join(sorted(FIELDS))}")
            if rest == "":
                raise QueryError(f"field '{name}' has no value")
            op = None
            for o in OPS:
                if rest.startswith(o):
                    op, rest = o, rest[len(o):]
                    break
            if op and FIELDS[name] not in ("int", "float", "time"):
                raise QueryError(f"operator '{op}' only applies to numeric and time fields, not '{name}'")
            vals = [_unquote(x) for x in _split_list(rest)]
            if len(vals) > MAX_LIST:
                raise QueryError(f"too many values in list (max {MAX_LIST})")
            if any(v == "" for v in vals):
                raise QueryError(f"empty value for field '{name}'")
            terms.append(Term(neg, name, op, vals))
        else:
            neg = tok.startswith("-") and len(tok) > 1
            body = tok[1:] if neg else tok
            terms.append(Term(neg, None, None, [], _unquote(body)))
        if len(terms) > MAX_TERMS:
            raise QueryError(f"too many terms (max {MAX_TERMS})")
    return terms


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _wild_to_like(s: str) -> str:
    return "".join("%" if ch == "*" else _like_escape(ch) for ch in s)


def _ip_int_sql(col: str) -> str:
    return (f"(try_cast(split_part({col}, '.', 1) AS BIGINT) * 16777216 + try_cast(split_part({col}, '.', 2) AS BIGINT) * 65536"
            f" + try_cast(split_part({col}, '.', 3) AS BIGINT) * 256 + try_cast(split_part({col}, '.', 4) AS BIGINT))")


def _num(v: str, typ: str, fname: str) -> float | int:
    try:
        if fname in TIME_FIELDS:
            if re.fullmatch(r"-?\d+", v):
                return int(v)
            ms = parse_iso8601(v if "T" in v or " " in v else v + "T00:00:00Z")
            if ms is None:
                raise ValueError
            return ms
        return float(v) if typ == "float" else int(v)
    except ValueError:
        kind = "a time (epoch ms or ISO-8601)" if fname in TIME_FIELDS else "a number"
        raise QueryError(f"'{v}' is not {kind} (field '{fname}')") from None


def _one(t: Term, v: str, params: list[Any]) -> str:
    name = t.field or ""
    typ = FIELDS[name]
    col = COLUMN_OF[name]
    is_time = name in TIME_FIELDS
    if name == "action":
        key = v.lower()
        if key in ACTION_ALIAS:
            n = ACTION_ALIAS[key]
        elif re.fullmatch(r"\d+", v):
            n = int(v)
        else:
            raise QueryError(f"action must be denied|allowed|unknown or an action_id number, got '{v}'")
        params.append(n)
        return f"{col} = ?"
    if typ == "enum":
        if v not in STATUSES:
            raise QueryError(f"status must be one of {', '.join(STATUSES)}, got '{v}'")
        params.append(v)
        return f"{col} = ?"
    if typ == "ip":
        if "/" in v:
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                raise QueryError(f"'{v}' is not a valid CIDR") from None
            if net.version != 4:
                raise QueryError("IPv6 CIDR is not supported; use an exact address or a trailing wildcard (2001:db8:*)")
            params += [int(net.network_address), int(net.broadcast_address)]
            return f"({col} IS NOT NULL AND {col} NOT LIKE '%:%' AND {_ip_int_sql(col)} BETWEEN ? AND ?)"
        if "*" in v:
            params.append(_wild_to_like(v))
            return f"{col} LIKE ? ESCAPE '\\'"
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise QueryError(f"'{v}' is not a valid IP address, CIDR or wildcard (field '{name}')") from None
        params.append(str(ipaddress.ip_address(v)))
        return f"{col} = ?"
    if typ in ("int", "float", "time"):
        sql_col = f"{col}" if not is_time else col
        ph = "to_timestamp(? / 1000.0)" if is_time else "?"
        if t.op:
            params.append(_num(v, typ, name))
            return f"{sql_col} {t.op} {ph}"
        if ".." in v:
            a, _, b = v.partition("..")
            params += [_num(a, typ, name), _num(b, typ, name)]
            return f"{sql_col} BETWEEN {ph} AND {ph}"
        params.append(_num(v, typ, name))
        return f"{sql_col} = {ph}"
    # string
    ci = name in LIKE_FIELDS
    if "*" in v:
        params.append(_wild_to_like(v))
        return f"{col} {'ILIKE' if ci else 'LIKE'} ? ESCAPE '\\'"
    if ci:
        params.append(v.lower())
        return f"lower({col}) = ?"
    params.append(v)
    return f"{col} = ?"


def compile_query(q: str | None, text_col: str = "event") -> tuple[str, list[Any]]:
    """Return ``(where_sql, params)``; ``where_sql`` is ``TRUE`` for an empty query."""
    if not q or not q.strip():
        return "TRUE", []
    parts: list[str] = []
    params: list[Any] = []
    for t in parse(q):
        if t.field is None:
            if not t.text:
                continue
            params.append("%" + _like_escape(t.text) + "%")
            sql = f"{text_col} ILIKE ? ESCAPE '\\'"
        else:
            sub = [_one(t, v, params) for v in t.values]
            sql = sub[0] if len(sub) == 1 else "(" + " OR ".join(sub) + ")"
        parts.append(f"NOT COALESCE({sql}, FALSE)" if t.neg else f"COALESCE({sql}, FALSE)")
    return (" AND ".join(parts) or "TRUE"), params


def field_catalog() -> list[dict[str, Any]]:
    desc = {"action": "alias over action_id: denied | allowed", "event_id": "<raw_id>:<n>", "raw_ref": "vault reference"}
    out: list[dict[str, Any]] = []
    for name, typ in sorted(FIELDS.items()):
        d: dict[str, Any] = {"name": name, "type": typ}
        if name in desc:
            d["description"] = desc[name]
        if name == "status":
            d["enum"] = list(STATUSES)
        if name == "action":
            d["enum"] = ["denied", "allowed"]
        out.append(d)
    return out
