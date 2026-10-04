"""Event assembly (§7.7): run a class's compiled ``set`` closures, build nested dicts in one pass, derive ``type_uid`` /
``category_uid``, compute the lossless ``unmapped`` bucket and fill ``metadata.*`` / ``ulpf.*``.

``unmapped = extracted - consumed - ignored``. A field counts as *consumed* only if an expression that references it produced a
value (so a field whose mapping failed, e.g. an invalid IP, stays visible in ``unmapped``)."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..model.envelope import RawEnvelope
from ..model.lineage import VaultRef
from ..model.ocsf import CLASS_UID, OCSF_VERSION, category_for

Closure = Callable[[dict[str, Any]], Any]
SCHEMA_TAG = f"ocsf-{OCSF_VERSION}"


@dataclass(frozen=True, slots=True)
class Setter:
    path: str
    parts: tuple[str, ...]
    fn: Closure
    refs: frozenset[str]


@dataclass(frozen=True, slots=True)
class ClassSpec:
    name: str
    class_uid: int
    category_uid: int
    setters: tuple[Setter, ...]
    uses_syslog_ts: bool


@dataclass(frozen=True, slots=True)
class PackMeta:
    source_id: str
    version: str
    product: str | None
    vendor: str | None
    ignore: dict[str, str]
    ignore_keys: frozenset[str]


def make_class_spec(name: str, setters: list[Setter]) -> ClassSpec:
    uid = CLASS_UID[name]
    uses = any("syslog.ts" in s.refs for s in setters)
    return ClassSpec(name, uid, category_for(uid), tuple(setters), uses)


def build_event(spec: ClassSpec, view: dict[str, Any], ctx_keys: frozenset[str] | tuple[str, ...], meta: PackMeta, env: RawEnvelope,
                ref: VaultRef, ctx: dict[str, Any], n: int = 0) -> dict[str, Any]:
    """``view`` = extracted fields with the ``syslog.*`` context merged in (``ctx_keys`` names the merged keys)."""
    ev: dict[str, Any] = {}
    used: set[str] = set()
    for s in spec.setters:
        v = s.fn(view)
        if v is None:
            continue
        parts = s.parts
        if len(parts) == 1:
            ev[parts[0]] = v
        else:
            d = ev
            for p in parts[:-1]:
                nxt = d.get(p)
                if nxt.__class__ is not dict:
                    nxt = d[p] = {}
                d = nxt
            d[parts[-1]] = v
        used.update(s.refs)
    cuid = spec.class_uid
    ev["class_uid"] = cuid
    ev["category_uid"] = spec.category_uid
    aid = ev.get("activity_id", 0)
    ev["type_uid"] = cuid * 100 + (aid if aid.__class__ is int else 0)

    unmapped: dict[str, Any] = {}
    ignored: dict[str, str] | None = None
    total = consumed = 0
    ik = meta.ignore_keys
    for k, v in view.items():
        if k in ctx_keys:
            continue
        total += 1
        if k in used:
            consumed += 1
        elif k in ik:
            if ignored is None:
                ignored = {}
            ignored[k] = meta.ignore[k]
        else:
            unmapped[k] = v

    recv_ms = env.recv_ns // 1_000_000
    status = "parsed"
    quality = ctx.get("syslog.time_quality", "source_tz") if spec.uses_syslog_ts else "source_tz"
    if ev.get("time").__class__ is not int:
        ev["time"] = recv_ms
        status, quality = "partial", "recv_time"
    md = ev.get("metadata")
    if md.__class__ is not dict:
        md = ev["metadata"] = {}
    event_id = f"{env.raw_id}:{n}"
    md["version"] = OCSF_VERSION
    md["uid"] = event_id
    md["product"] = {"name": meta.product, "vendor_name": meta.vendor}
    ev["unmapped"] = unmapped
    u: dict[str, Any] = {
        "event_id": event_id, "raw_ref": str(ref), "raw_sha256": ref.sha256, "recv_time": recv_ms,
        "collector_id": env.collector_id, "transport": env.transport, "peer_ip": env.peer_ip,
        "source_id": meta.source_id, "pack_version": meta.version, "schema": SCHEMA_TAG, "status": status,
        "coverage": round(consumed / total, 4) if total else 1.0, "time_quality": quality,
    }
    if ignored:
        u["ignored"] = ignored
    if env.truncated:
        u["truncated"] = True
    ev["ulpf"] = u
    return ev


def unparsed_event(env: RawEnvelope, ref: VaultRef, template_id: str | None = None, reason: str | None = None,
                   source_id: str = "unknown", n: int = 0) -> dict[str, Any]:
    """Base Event (class 0) for an envelope no pack could parse: raw is already vaulted, ``message`` is a lossy-safe preview."""
    recv_ms = env.recv_ns // 1_000_000
    event_id = f"{env.raw_id}:{n}"
    u: dict[str, Any] = {
        "event_id": event_id, "raw_ref": str(ref), "raw_sha256": ref.sha256, "recv_time": recv_ms,
        "collector_id": env.collector_id, "transport": env.transport, "peer_ip": env.peer_ip,
        "source_id": source_id, "pack_version": "", "schema": SCHEMA_TAG, "status": "unparsed", "coverage": 0.0,
        "time_quality": "recv_time",
    }
    if template_id is not None:
        u["template_id"] = template_id
    if reason:
        u["reason"] = reason
    if env.truncated:
        u["truncated"] = True
    return {
        "class_uid": 0, "category_uid": 0, "type_uid": 0, "activity_id": 0, "time": recv_ms, "severity_id": 0,
        "message": env.data.decode("utf-8", "replace"),
        "metadata": {"version": OCSF_VERSION, "uid": event_id, "product": {"name": None, "vendor_name": None}},
        "unmapped": {}, "ulpf": u,
    }
