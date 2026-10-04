"""Normalized-event helpers. Events are plain ``dict``s in the hot path (§6.2); this module documents statuses and builders."""
from __future__ import annotations

from typing import Any

from .ocsf import OCSF_VERSION

STATUS_PARSED = "parsed"
STATUS_PARTIAL = "partial"
STATUS_UNPARSED = "unparsed"
STATUSES = (STATUS_PARSED, STATUS_PARTIAL, STATUS_UNPARSED)

TQ_SOURCE = "source_tz"
TQ_ASSUMED = "assumed_tz"
TQ_RECV = "recv_time"

SCHEMA_TAG = f"ocsf-{OCSF_VERSION}"

Event = dict[str, Any]


def get_path(d: Any, path: str) -> Any:
    """Resolve a dotted path; tolerates dotted *keys* (``unmapped['alert.category']``). Returns None when absent."""
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
