"""Syslog-out sink: RFC 5424 envelope around the OCSF JSON, over UDP (best effort by nature; datagrams > 60 KB are truncated)."""
from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any

from ..normalize.lake_schema import dumps_event

MAX_DGRAM = 60_000


class SyslogOutSink:
    name = "syslog_out"

    def __init__(self, host: str = "127.0.0.1", port: int = 5514, hostname: str = "ulpf", facility: int = 16) -> None:
        self.addr = (host, port)
        self.hostname = hostname
        self.pri = facility * 8 + 6
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rows_written = 0

    def format(self, ev: dict[str, Any]) -> bytes:
        t = ev.get("time")
        ts = datetime.fromtimestamp(t / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if isinstance(t, int) and t > 0 else "-"
        msg = f"<{self.pri}>1 {ts} {self.hostname} ulpf - - - {dumps_event(ev)}".encode("utf-8", "replace")
        return msg[:MAX_DGRAM]

    def write(self, events: list[dict[str, Any]]) -> None:
        for ev in events:
            self.sock.sendto(self.format(ev), self.addr)
        self.rows_written += len(events)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.sock.close()
