"""Lightweight OCSF conformance check (§7.7): required attributes, enum membership, ``type_uid`` arithmetic, IP/port validity and
integer-millisecond ``time``. Runs in tests and sampled (1 in ``sample_validate``) in production; violations increment
``ocsf_violation_total{pack,field}``. Not a substitute for the official JSON schema (P1)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from ..model.event import get_path
from ..model.ocsf import (
    ACTION_IDS,
    ACTIVITY_IDS,
    CATEGORY_UID,
    CLASS_NAME,
    DISPOSITION_IDS,
    REQUIRED_BY_CLASS,
    SEVERITY_IDS,
    STATUS_IDS,
)


@dataclass(frozen=True, slots=True)
class Violation:
    field: str
    message: str

    def __str__(self) -> str:
        return f"{self.field}: {self.message}"


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_ip(ev: dict[str, Any], path: str, out: list[Violation]) -> None:
    v = get_path(ev, path)
    if v is None:
        return
    try:
        ipaddress.ip_address(v)
    except (ValueError, TypeError):
        out.append(Violation(path, f"not a valid IP address: {v!r}"))


def _check_port(ev: dict[str, Any], path: str, out: list[Violation]) -> None:
    v = get_path(ev, path)
    if v is not None and not (_is_int(v) and 0 <= v <= 65535):
        out.append(Violation(path, f"not a valid port: {v!r}"))


def validate_event(ev: dict[str, Any]) -> list[Violation]:
    out: list[Violation] = []
    cuid = ev.get("class_uid")
    if not _is_int(cuid) or cuid not in CLASS_NAME:
        return [Violation("class_uid", f"unknown class_uid {cuid!r}")]
    if ev.get("category_uid") != CATEGORY_UID[cuid]:
        out.append(Violation("category_uid", f"expected {CATEGORY_UID[cuid]} for class {cuid}, got {ev.get('category_uid')!r}"))
    aid = ev.get("activity_id", 0)
    if not _is_int(aid) or aid not in ACTIVITY_IDS[cuid]:
        out.append(Violation("activity_id", f"{aid!r} is not an activity id of class {cuid}"))
    elif ev.get("type_uid") != cuid * 100 + aid:
        out.append(Violation("type_uid", f"expected class_uid*100+activity_id = {cuid * 100 + aid}, got {ev.get('type_uid')!r}"))
    t = ev.get("time")
    if not _is_int(t) or t < 0 or t > 4_102_444_800_000 * 2:
        out.append(Violation("time", f"must be integer epoch milliseconds, got {t!r}"))
    for name, allowed in (("action_id", ACTION_IDS), ("disposition_id", DISPOSITION_IDS), ("severity_id", SEVERITY_IDS),
                          ("status_id", STATUS_IDS)):
        v = ev.get(name)
        if v is not None and (not _is_int(v) or v not in allowed):
            out.append(Violation(name, f"{v!r} is not a valid {name}"))
    for p in REQUIRED_BY_CLASS.get(cuid, ()):
        if get_path(ev, p) is None and ev.get("ulpf", {}).get("status") == "parsed":
            out.append(Violation(p, f"required for class {cuid}"))
    for p in ("src_endpoint.ip", "dst_endpoint.ip"):
        _check_ip(ev, p, out)
    for p in ("src_endpoint.port", "dst_endpoint.port"):
        _check_port(ev, p, out)
    if not isinstance(ev.get("unmapped"), dict):
        out.append(Violation("unmapped", "must be an object"))
    u = ev.get("ulpf")
    if not isinstance(u, dict):
        out.append(Violation("ulpf", "lineage object missing"))
    else:
        for k in ("event_id", "raw_ref", "raw_sha256", "source_id", "status", "coverage", "time_quality", "schema"):
            if k not in u:
                out.append(Violation(f"ulpf.{k}", "missing"))
        if u.get("status") not in ("parsed", "partial", "unparsed"):
            out.append(Violation("ulpf.status", f"bad status {u.get('status')!r}"))
    return out
