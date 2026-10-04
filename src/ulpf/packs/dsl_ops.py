"""The closed set of pipe operations (§7.6). Adding one requires: an entry in ``OP_BUILDERS``, ``docs/pack-dsl.md`` and tests.

Every op factory validates its argument at compile time (raising :class:`PackError`) and returns ``fn(value, fields) -> value | None``.
A failing op (bad int, invalid IP, port out of range, wrong-length MAC ...) yields ``None``, never an exception.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any

from ..normalize import timeparse as tp

Op = Callable[[Any, dict[str, Any]], Any]


class PackError(ValueError):
    """A pack is malformed (raised at load/compile time, never per event)."""


PROTO: dict[int, str] = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre", 50: "esp", 51: "ah", 58: "ipv6-icmp",
                         89: "ospf", 132: "sctp"}

# op name -> (takes_argument, description). The linter and docs are generated from this table.
OP_SPECS: dict[str, tuple[bool, str]] = {
    "str": (False, "to string"), "int": (False, "to int (decimal)"), "float": (False, "to float"),
    "lower": (False, "lowercase"), "upper": (False, "uppercase"), "strip": (False, "trim whitespace"),
    "ip": (False, "validate IPv4/IPv6, canonical text, else null"), "port": (False, "int 0..65535 else null"),
    "mac": (False, "12 hex digits -> aa:bb:cc:dd:ee:ff else null"),
    "epoch_s": (False, "seconds (may be fractional) -> ms"), "epoch_ms": (False, "ms -> ms"), "epoch_ns": (False, "ns -> ms"),
    "iso8601": (False, "ISO-8601 -> ms (naive = UTC)"),
    "strptime": (True, "{fmt, tz | tz_from} -> ms"), "lookup": (True, "{map, default}"), "regex": (True, "{pattern, group}"),
    "split": (True, "{sep, index}"), "concat": (True, "{sep} join a list of fields"), "mul": (True, "multiply a number"),
    "proto_name": (False, "IANA protocol number -> name (closed table)"),
    "hms": (False, "h:mm:ss duration -> ms (reconciliation: ASA teardown duration)"),
}
KNOWN_OPS = frozenset(OP_SPECS)

_IPV4_PART = re.compile(r"(?:0|[1-9]\d{0,2})")
_HMS = re.compile(r"(\d+):([0-5]?\d):([0-5]?\d)")
_NONHEX = re.compile(r"[^0-9a-fA-F]")


def _op_str(v: Any, f: dict[str, Any]) -> Any:
    return str(v)


def _op_int(v: Any, f: dict[str, Any]) -> Any:
    try:
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, int):
            return v
        if isinstance(v, float):
            return int(v)
        return int(str(v).strip(), 10)
    except (ValueError, TypeError, OverflowError):
        return None


def _op_float(v: Any, f: dict[str, Any]) -> Any:
    try:
        return float(v)
    except (ValueError, TypeError, OverflowError):
        return None


def _op_lower(v: Any, f: dict[str, Any]) -> Any:
    return str(v).lower()


def _op_upper(v: Any, f: dict[str, Any]) -> Any:
    return str(v).upper()


def _op_strip(v: Any, f: dict[str, Any]) -> Any:
    return str(v).strip()


def _op_ip(v: Any, f: dict[str, Any]) -> Any:
    s = v if type(v) is str else str(v)
    if s.count(".") == 3 and ":" not in s:  # fast path for dotted quads (the overwhelmingly common case)
        parts = s.split(".")
        if all(len(p) <= 3 and p.isascii() and p.isdigit() and (p == "0" or p[0] != "0") and int(p) < 256 for p in parts):
            return s
    try:
        return str(ipaddress.ip_address(s.strip()))
    except ValueError:
        return None


def _op_port(v: Any, f: dict[str, Any]) -> Any:
    return v if isinstance(v, int) and 0 <= v <= 65535 else None


def _op_mac(v: Any, f: dict[str, Any]) -> Any:
    h = _NONHEX.sub("", str(v))
    return ":".join(h[i : i + 2] for i in range(0, 12, 2)).lower() if len(h) == 12 else None


def _op_epoch_s(v: Any, f: dict[str, Any]) -> Any:
    try:
        return int(round(float(v) * 1000))
    except (ValueError, TypeError, OverflowError):
        return None


def _op_epoch_ms(v: Any, f: dict[str, Any]) -> Any:
    try:
        return int(v)
    except (ValueError, TypeError, OverflowError):
        return None


def _op_epoch_ns(v: Any, f: dict[str, Any]) -> Any:
    try:
        return int(v) // 1_000_000
    except (ValueError, TypeError, OverflowError):
        return None


def _op_iso8601(v: Any, f: dict[str, Any]) -> Any:
    try:
        return tp.parse_iso8601(str(v))
    except (ValueError, OverflowError):
        return None


def _op_proto_name(v: Any, f: dict[str, Any]) -> Any:
    try:
        return PROTO.get(int(v))
    except (ValueError, TypeError, OverflowError):
        return None


def _op_hms(v: Any, f: dict[str, Any]) -> Any:
    m = _HMS.fullmatch(str(v).strip())
    if m is None:
        return None
    return (int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))) * 1000


def _plain(fn: Op) -> Callable[[Any], Op]:
    def build(arg: Any) -> Op:
        if arg is not None:
            raise PackError("this op takes no argument")
        return fn

    return build


def _b_strptime(arg: Any, default_tz: str = "UTC") -> Op:
    if not isinstance(arg, dict) or not isinstance(arg.get("fmt"), str):
        raise PackError("strptime needs {fmt: str, tz: str | tz_from: field}")
    extra = set(arg) - {"fmt", "tz", "tz_from"}
    if extra:
        raise PackError(f"strptime: unknown keys {sorted(extra)}")
    if "tz" in arg and "tz_from" in arg:
        raise PackError("strptime: give tz or tz_from, not both")
    spec = tp.strptime_spec(arg["fmt"])
    tz_const = arg.get("tz")
    tz_from: str | None = arg.get("tz_from")

    def op(v: Any, f: dict[str, Any]) -> Any:
        n = spec.parse_naive_s(str(v))
        if n is None:
            return None
        tz = f.get(tz_from) if tz_from is not None else tz_const
        if tz is None or tz == "":
            tz = default_tz  # resolution order: field -> pack literal -> pack/global default_tz
        try:
            return tp.naive_to_utc_ms(n, tz)
        except ValueError:
            return None

    return op


def _b_lookup(arg: Any) -> Op:
    if not isinstance(arg, dict) or not isinstance(arg.get("map"), dict) or set(arg) - {"map", "default"}:
        raise PackError("lookup needs {map: {...}, default: v}")
    table = {str(k): x for k, x in arg["map"].items()}
    default = arg.get("default")

    def op(v: Any, f: dict[str, Any]) -> Any:
        return table.get(v if type(v) is str else str(v), default)

    return op


def _b_regex(arg: Any) -> Op:
    if not isinstance(arg, dict) or not isinstance(arg.get("pattern"), str) or set(arg) - {"pattern", "group"}:
        raise PackError("regex needs {pattern: str, group: int|name}")
    try:
        rx = re.compile(arg["pattern"])
    except re.error as e:
        raise PackError(f"regex op: bad pattern: {e}") from e
    group = arg.get("group", 1)

    def op(v: Any, f: dict[str, Any]) -> Any:
        m = rx.search(str(v)[:65536])
        if m is None:
            return None
        try:
            return m.group(group)
        except (IndexError, re.error):
            return None

    return op


def _b_split(arg: Any) -> Op:
    if not isinstance(arg, dict) or not isinstance(arg.get("sep"), str) or not isinstance(arg.get("index"), int) or set(arg) - {"sep", "index"}:
        raise PackError("split needs {sep: str, index: int}")
    sep, idx = arg["sep"], arg["index"]
    if not sep:
        raise PackError("split: empty separator")

    def op(v: Any, f: dict[str, Any]) -> Any:
        try:
            return str(v).split(sep)[idx]
        except IndexError:
            return None

    return op


def _b_mul(arg: Any) -> Op:
    if isinstance(arg, bool) or not isinstance(arg, int | float):
        raise PackError("mul needs a number")

    def op(v: Any, f: dict[str, Any]) -> Any:
        if isinstance(v, bool) or not isinstance(v, int | float):
            return None  # never string repetition
        return v * arg

    return op


def concat_sep(arg: Any) -> str:
    """``{concat: " "}`` or ``{concat: {sep: " "}}`` -> the separator."""
    if isinstance(arg, str):
        return arg
    if isinstance(arg, dict) and set(arg) <= {"sep"}:
        return str(arg.get("sep", ""))
    raise PackError("concat needs a separator string or {sep: str}")


def _b_concat(arg: Any) -> Op:
    sep = concat_sep(arg)

    def op(v: Any, f: dict[str, Any]) -> Any:
        return sep.join(str(x) for x in v) if isinstance(v, list) else str(v)

    return op


OP_BUILDERS: dict[str, Callable[[Any], Op]] = {
    "str": _plain(_op_str), "int": _plain(_op_int), "float": _plain(_op_float), "lower": _plain(_op_lower),
    "upper": _plain(_op_upper), "strip": _plain(_op_strip), "ip": _plain(_op_ip), "port": _plain(_op_port),
    "mac": _plain(_op_mac), "epoch_s": _plain(_op_epoch_s), "epoch_ms": _plain(_op_epoch_ms), "epoch_ns": _plain(_op_epoch_ns),
    "iso8601": _plain(_op_iso8601), "proto_name": _plain(_op_proto_name), "hms": _plain(_op_hms),
    "strptime": _b_strptime, "lookup": _b_lookup, "regex": _b_regex, "split": _b_split, "mul": _b_mul, "concat": _b_concat,
}
assert set(OP_BUILDERS) == KNOWN_OPS


def split_op(op: Any) -> tuple[str, Any]:
    """A pipe entry is ``"name"`` or ``{name: arg}`` (exactly one key)."""
    if isinstance(op, str):
        return op, None
    if isinstance(op, dict) and len(op) == 1:
        name, arg = next(iter(op.items()))
        return str(name), arg
    raise PackError(f"bad pipe op {op!r}")


def build_op(op: Any, default_tz: str = "UTC") -> Op:
    name, arg = split_op(op)
    if name == "strptime":
        return _b_strptime(arg, default_tz)
    b = OP_BUILDERS.get(name)
    if b is None:
        raise PackError(f"unknown op {name!r}")
    if OP_SPECS[name][0] and arg is None:
        raise PackError(f"op {name!r} needs an argument")
    return b(arg)
