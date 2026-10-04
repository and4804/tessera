"""OpenSearch sink (`siem` profile): ``_bulk`` NDJSON with an index template and daily indices. Plain HTTP via httpx, so the
optional ``opensearch-py`` library is not required."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from ..normalize.lake_schema import dumps_event
from .base import SinkError, with_retry

INDEX_TEMPLATE: dict[str, Any] = {
    "index_patterns": ["ulpf-ocsf-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "dynamic": True,
            "properties": {
                "time": {"type": "date", "format": "epoch_millis"},
                "class_uid": {"type": "integer"}, "type_uid": {"type": "integer"}, "severity_id": {"type": "integer"},
                "src_endpoint": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
                "dst_endpoint": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
                "unmapped": {"type": "object", "enabled": False},
                "ulpf": {"properties": {"event_id": {"type": "keyword"}, "raw_ref": {"type": "keyword"},
                                        "source_id": {"type": "keyword"}, "status": {"type": "keyword"}}},
            },
        },
    },
}


class OpenSearchSink:
    name = "opensearch"

    def __init__(self, url: str, index: str = "ulpf-ocsf-%Y.%m.%d", bulk_size: int = 1000, client: httpx.Client | None = None,
                 user: str | None = None, password: str | None = None) -> None:
        self.url = url.rstrip("/")
        self.index = index
        self.bulk_size = bulk_size
        auth = (user, password) if user else None
        self.client = client or httpx.Client(timeout=30.0, auth=auth)
        self._buf: list[dict[str, Any]] = []
        self._template_ok = False
        self.rows_written = 0

    def ensure_template(self) -> None:
        if self._template_ok:
            return
        r = self.client.put(f"{self.url}/_index_template/ulpf-ocsf", json=INDEX_TEMPLATE)
        r.raise_for_status()
        self._template_ok = True

    def _index_for(self, ev: dict[str, Any]) -> str:
        t = ev.get("time")
        d = datetime.fromtimestamp(t / 1000, UTC) if isinstance(t, int) and t > 0 else datetime.now(UTC)
        return d.strftime(self.index)

    def build_bulk(self, events: list[dict[str, Any]]) -> str:
        lines: list[str] = []
        for ev in events:
            eid = (ev.get("ulpf") or {}).get("event_id")
            meta = {"index": {"_index": self._index_for(ev), **({"_id": eid} if eid else {})}}   # _id = event_id: idempotent redelivery
            import json

            lines.append(json.dumps(meta))
            lines.append(dumps_event(ev))
        return "\n".join(lines) + "\n"

    def write(self, events: list[dict[str, Any]]) -> None:
        self._buf.extend(events)
        if len(self._buf) >= self.bulk_size:
            self.flush()

    def flush(self) -> None:
        if not self._buf:
            return
        batch, self._buf = self._buf, []

        def send() -> None:
            self.ensure_template()
            r = self.client.post(f"{self.url}/_bulk", content=self.build_bulk(batch).encode("utf-8"),
                                 headers={"Content-Type": "application/x-ndjson"})
            r.raise_for_status()
            body = r.json()
            if body.get("errors"):
                bad = [i for i in body.get("items", []) if next(iter(i.values())).get("error")]
                raise SinkError(f"{len(bad)} bulk items rejected: {str(bad[0])[:200]}")

        try:
            with_retry(send)
        except SinkError:
            self._buf = batch + self._buf   # keep for the caller's retry/spool decision
            raise
        self.rows_written += len(batch)

    def close(self) -> None:
        try:
            self.flush()
        finally:
            self.client.close()
