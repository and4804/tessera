"""OCSF class table and the closed set of attribute paths ULPF may emit.

This is a curated subset written against the 1.3-era schema (R12: not verified against the vendored JSON schema; the validator
and linter use this table so drift is caught in one place). ``type_uid = class_uid * 100 + activity_id``.
"""
from __future__ import annotations

OCSF_VERSION = "1.3.0"

CLASS_UID: dict[str, int] = {
    "base_event": 0,
    "detection_finding": 2004,
    "authentication": 3002,
    "network_activity": 4001,
    "http_activity": 4002,
    "dns_activity": 4003,
}
CATEGORY_UID: dict[int, int] = {0: 0, 2004: 2, 3002: 3, 4001: 4, 4002: 4, 4003: 4}
CLASS_NAME: dict[int, str] = {v: k for k, v in CLASS_UID.items()}

# activity_id enum per class (0 = Unknown, 99 = Other are always valid)
ACTIVITY_IDS: dict[int, frozenset[int]] = {
    0: frozenset({0, 1}),
    2004: frozenset({0, 1, 2, 3, 99}),
    3002: frozenset({0, 1, 2, 3, 4, 5, 6, 99}),
    4001: frozenset({0, 1, 2, 3, 4, 5, 6, 7, 99}),
    4002: frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 99}),
    4003: frozenset({0, 1, 2, 6, 99}),
}
ACTION_IDS = frozenset({0, 1, 2, 3, 4, 99})
DISPOSITION_IDS = frozenset(range(0, 28)) | {99}
SEVERITY_IDS = frozenset({0, 1, 2, 3, 4, 5, 6, 99})
STATUS_IDS = frozenset({0, 1, 2, 99})

# Attributes the validator expects on a `parsed` event. `status` (parsed/partial) itself only hinges on `time` (see normalize.mapper).
REQUIRED_BY_CLASS: dict[int, tuple[str, ...]] = {
    0: ("time",),
    2004: ("time", "activity_id", "finding_info.title"),
    3002: ("time", "activity_id"),
    4001: ("time", "activity_id"),
    4002: ("time", "activity_id"),
    4003: ("time", "activity_id"),
}

_COMMON = {
    "activity_id", "action_id", "disposition_id", "severity_id", "status_id", "time", "duration", "message", "start_time", "end_time",
    "count", "status", "status_code", "status_detail", "activity_name", "action", "disposition", "severity", "category_name", "class_name",
    "device.hostname", "device.ip", "device.name", "device.uid", "device.mac", "device.type_id", "device.os.name",
    "metadata.original_time", "metadata.uid", "metadata.product.name", "metadata.product.vendor_name", "metadata.product.version",
    "metadata.log_name", "metadata.log_provider", "metadata.logged_time", "metadata.profiles", "metadata.version",
    "src_endpoint.ip", "src_endpoint.port", "src_endpoint.hostname", "src_endpoint.interface_name", "src_endpoint.mac",
    "src_endpoint.name", "src_endpoint.uid", "src_endpoint.interface_uid", "src_endpoint.domain", "src_endpoint.location.country",
    "dst_endpoint.ip", "dst_endpoint.port", "dst_endpoint.hostname", "dst_endpoint.interface_name", "dst_endpoint.mac",
    "dst_endpoint.name", "dst_endpoint.uid", "dst_endpoint.interface_uid", "dst_endpoint.domain", "dst_endpoint.location.country",
    "observables", "enrichments", "raw_data", "unmapped",
}
_NET = {
    "connection_info.protocol_name", "connection_info.protocol_num", "connection_info.uid", "connection_info.direction",
    "connection_info.direction_id", "connection_info.boundary", "connection_info.boundary_id", "connection_info.tcp_flags",
    "connection_info.protocol_ver", "connection_info.protocol_ver_id",
    "traffic.bytes", "traffic.bytes_in", "traffic.bytes_out", "traffic.packets", "traffic.packets_in", "traffic.packets_out",
    "proxy_endpoint.ip", "proxy_endpoint.port", "tls.version", "tls.sni", "firewall_rule.name", "firewall_rule.uid",
    "firewall_rule.type", "firewall_rule.category", "file.name", "file.path", "app_name", "policy.name", "policy.uid",
}
OCSF_PATHS: dict[int, frozenset[str]] = {
    0: frozenset(_COMMON),
    2004: frozenset(_COMMON | _NET | {
        "finding_info.title", "finding_info.uid", "finding_info.desc", "finding_info.types", "finding_info.src_url",
        "finding_info.created_time", "finding_info.first_seen_time", "finding_info.last_seen_time", "finding_info.product_uid",
        "evidences", "confidence", "confidence_id", "risk_score", "risk_level", "risk_level_id", "impact", "impact_id",
        "vulnerabilities", "remediation.desc", "attacks", "is_alert", "verdict", "verdict_id",
    }),
    3002: frozenset(_COMMON | _NET | {
        "user.name", "user.uid", "user.domain", "user.type", "user.type_id", "user.email_addr", "user.full_name", "user.groups",
        "logon_type", "logon_type_id", "auth_protocol", "auth_protocol_id", "is_mfa", "is_remote", "is_new_logon",
        "session.uid", "service.name", "service.uid", "dst_endpoint.svc_name", "actor.user.name", "actor.user.uid",
        "actor.process.name", "actor.process.pid", "logon_process.name", "authentication_token",
    }),
    4001: frozenset(_COMMON | _NET | {"actor.user.name", "actor.process.name", "actor.process.pid"}),
    4002: frozenset(_COMMON | _NET | {
        "http_request.http_method", "http_request.url.text", "http_request.url.hostname", "http_request.url.path",
        "http_request.url.port", "http_request.url.scheme", "http_request.url.query_string", "http_request.user_agent",
        "http_request.referrer", "http_request.version", "http_request.length", "http_request.http_headers",
        "http_response.code", "http_response.status", "http_response.message", "http_response.length", "http_response.latency",
        "http_response.content_type", "http_status", "actor.user.name", "actor.user.uid", "actor.user.domain",
        "actor.process.name", "file.mime_type", "file.size",
    }),
    4003: frozenset(_COMMON | _NET | {
        "query.hostname", "query.type", "query.class", "query.opcode", "query.opcode_id",
        "answers", "rcode", "rcode_id", "query_time", "response_time", "actor.user.name",
    }),
}


def known_path(class_uid: int, path: str) -> bool:
    paths = OCSF_PATHS.get(class_uid)
    if paths is None:
        return False
    if path in paths:
        return True
    root = path.split(".", 1)[0]
    return root in ("unmapped", "enrichments", "observables", "answers", "evidences")


def category_for(class_uid: int) -> int:
    return CATEGORY_UID.get(class_uid, 0)
