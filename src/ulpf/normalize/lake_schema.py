"""Stable typed lake schema (§7.9). One wide row per event; ``event`` holds the full OCSF document as JSON text.

Hive layout ``class_uid=C/dt=YYYY-MM-DD/hour=HH/`` is produced by the sink; ``class_uid`` is also a real column so plain
``read_parquet('lake/**/*.parquet')`` works without partition discovery."""
from __future__ import annotations

import json
from typing import Any

import orjson
import pyarrow as pa

TS = pa.timestamp("ms", tz="UTC")

COLUMNS: list[tuple[str, pa.DataType]] = [
    ("event_id", pa.string()), ("raw_ref", pa.string()), ("raw_sha256", pa.string()),
    ("time", TS), ("recv_time", TS),
    ("class_uid", pa.int32()), ("activity_id", pa.int32()), ("severity_id", pa.int32()), ("action_id", pa.int32()),
    ("status", pa.string()), ("source_id", pa.string()),
    ("src_ip", pa.string()), ("src_port", pa.int32()), ("dst_ip", pa.string()), ("dst_port", pa.int32()),
    ("proto_name", pa.string()), ("proto_num", pa.int32()),
    ("bytes_in", pa.int64()), ("bytes_out", pa.int64()), ("packets_in", pa.int64()), ("packets_out", pa.int64()),
    ("duration_ms", pa.int64()),
    ("user_name", pa.string()), ("url", pa.string()), ("http_method", pa.string()), ("http_status", pa.int32()),
    ("dns_query", pa.string()), ("signature", pa.string()), ("device_host", pa.string()),
    ("coverage", pa.float32()),
    ("unmapped", pa.string()), ("event", pa.string()),
]
SCHEMA = pa.schema(COLUMNS)
COLUMN_NAMES = [c for c, _ in COLUMNS]
STRING_COLS = [i for i, (_, t) in enumerate(COLUMNS) if t == pa.string()]
_EMPTY: dict[str, Any] = {}

# columns the query DSL / API may reference, with their API-level type
FIELD_TYPES: dict[str, str] = {
    "event_id": "string", "raw_ref": "string", "time": "time", "recv_time": "time", "class_uid": "int", "activity_id": "int",
    "severity_id": "int", "action_id": "int", "status": "enum", "source_id": "string", "src_ip": "ip", "src_port": "int",
    "dst_ip": "ip", "dst_port": "int", "proto_name": "string", "proto_num": "int", "bytes_in": "int", "bytes_out": "int",
    "packets_in": "int", "packets_out": "int", "duration_ms": "int", "user_name": "string", "url": "string",
    "http_method": "string", "http_status": "int", "dns_query": "string", "signature": "string", "device_host": "string",
    "coverage": "float",
}


def dumps_event(ev: dict[str, Any]) -> str:
    """JSON text of an event. orjson refuses lone surrogates (invalid UTF-8 preserved via surrogateescape): fall back to the stdlib,
    which escapes them as ``\\udcXX`` so nothing is lost."""
    try:
        return orjson.dumps(ev).decode()
    except (TypeError, orjson.JSONEncodeError):
        return json.dumps(ev, ensure_ascii=True, default=str)


def dumps_obj(o: Any) -> str:
    try:
        return orjson.dumps(o).decode()
    except (TypeError, orjson.JSONEncodeError):
        return json.dumps(o, ensure_ascii=True, default=str)


def clean(s: Any) -> Any:
    """Parquet strings must be valid UTF-8: bytes that arrived as surrogate escapes are replaced (the event JSON and the vault keep them)."""
    if s.__class__ is str and not s.isascii():
        return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return s


def _int(v: Any) -> int | None:
    return v if v.__class__ is int else None


def project(ev: dict[str, Any], event_json: str | None = None) -> tuple[Any, ...]:
    """Event dict -> row tuple in :data:`COLUMNS` order (missing -> None)."""
    g = ev.get
    u = g("ulpf") or _EMPTY
    src = g("src_endpoint") or _EMPTY
    dst = g("dst_endpoint") or _EMPTY
    ci = g("connection_info") or _EMPTY
    tr = g("traffic") or _EMPTY
    user = (g("user") or _EMPTY).get("name") or ((g("actor") or _EMPTY).get("user") or _EMPTY).get("name")
    req = g("http_request") or _EMPTY
    resp = g("http_response") or _EMPTY
    q = g("query") or _EMPTY
    fi = g("finding_info") or _EMPTY
    dev = g("device") or _EMPTY
    url = (req.get("url") or _EMPTY).get("text")
    um = g("unmapped") or _EMPTY
    bytes_out = tr.get("bytes_out")
    t = g("time")
    return (
        u.get("event_id"), u.get("raw_ref"), u.get("raw_sha256"),
        t if t.__class__ is int else None, u.get("recv_time"),
        _int(g("class_uid")), _int(g("activity_id")), _int(g("severity_id")), _int(g("action_id")),
        u.get("status"), u.get("source_id"),
        clean(src.get("ip")), _int(src.get("port")), clean(dst.get("ip")), _int(dst.get("port")),
        clean(ci.get("protocol_name")), _int(ci.get("protocol_num")),
        _int(tr.get("bytes_in")), _int(bytes_out), _int(tr.get("packets_in")), _int(tr.get("packets_out")),
        _int(g("duration")),
        clean(user) if user.__class__ is str else None, clean(url) if url.__class__ is str else None,
        clean(req.get("http_method")), _int(resp.get("code")),
        clean(q.get("hostname")), clean(fi.get("title")), clean(dev.get("hostname")),
        u.get("coverage"),
        dumps_obj(um) if um else "{}", event_json if event_json is not None else dumps_event(ev),
    )


def rows_to_table(rows: list[tuple[Any, ...]]) -> pa.Table:
    cols = list(zip(*rows)) if rows else [()] * len(COLUMNS)
    arrays = []
    for (_name, typ), col in zip(COLUMNS, cols):
        try:
            arrays.append(pa.array(col, type=typ))
        except (pa.ArrowInvalid, pa.ArrowTypeError, UnicodeEncodeError):
            if typ == pa.string():
                arrays.append(pa.array([clean(x) if x is not None else None for x in col], type=typ))
            else:
                arrays.append(pa.array([x if x.__class__ is int else None for x in col], type=typ))
    return pa.Table.from_arrays(arrays, schema=SCHEMA)


def tail_row(ev: dict[str, Any], message: str | None = None) -> dict[str, Any]:
    """Thin projection for the live stream / API ``EventRow`` (api-contract.md)."""
    r = project(ev, "")
    d = {name: r[i] for i, name in enumerate(COLUMN_NAMES) if name not in ("unmapped", "event", "raw_sha256")}
    d["coverage"] = float(d["coverage"] or 0.0)
    d["message"] = message
    return d
