"""Splunk HTTP Event Collector sink: batched ``{"time","host","sourcetype","event"}`` documents."""
from __future__ import annotations

import json
from typing import Any

import httpx

from ..normalize.lake_schema import dumps_event
from .base import with_retry


class SplunkHecSink:
    name = "splunk_hec"

    def __init__(self, url: str, token: str, batch: int = 500, sourcetype: str = "ulpf:ocsf", client: httpx.Client | None = None) -> None:
        self.url = url
        self.token = token
        self.batch = batch
        self.sourcetype = sourcetype
        self.client = client or httpx.Client(timeout=30.0)
        self._buf: list[dict[str, Any]] = []
        self.rows_written = 0

    def build(self, events: list[dict[str, Any]]) -> str:
        out = []
        for ev in events:
            t = ev.get("time")
            doc: dict[str, Any] = {"sourcetype": self.sourcetype, "event": json.loads(dumps_event(ev))}
            host = (ev.get("device") or {}).get("hostname")
            if host:
                doc["host"] = host
            if isinstance(t, int):
                doc["time"] = t / 1000.0
            out.append(json.dumps(doc))
        return "\n".join(out)

    def write(self, events: list[dict[str, Any]]) -> None:
        self._buf.extend(events)
        if len(self._buf) >= self.batch:
            self.flush()

    def flush(self) -> None:
        if not self._buf:
            return
        batch, self._buf = self._buf, []

        def send() -> None:
            r = self.client.post(self.url, content=self.build(batch).encode("utf-8"),
                                 headers={"Authorization": f"Splunk {self.token}"})
            r.raise_for_status()

        try:
            with_retry(send)
        except Exception:
            self._buf = batch + self._buf
            raise
        self.rows_written += len(batch)

    def close(self) -> None:
        try:
            self.flush()
        finally:
            self.client.close()
