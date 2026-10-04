"""Syslog listeners (UDP, TCP, TLS) on asyncio (§7.1)."""
from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any

from ..config import split_hostport
from .framing import Deframer
from .publisher import Publisher


class _Flusher:
    """Flush the shared publisher at most ~5 ms after the first buffered envelope."""

    def __init__(self, pub: Publisher, loop: asyncio.AbstractEventLoop) -> None:
        self.pub, self.loop = pub, loop
        self._h: asyncio.TimerHandle | None = None

    def touch(self) -> None:
        if self.pub.pending and self._h is None:
            self._h = self.loop.call_later(self.pub.batch_s, self._fire)

    def _fire(self) -> None:
        self._h = None
        self.pub.flush()

    def close(self) -> None:
        if self._h:
            self._h.cancel()
        self.pub.flush()


class UdpProtocol(asyncio.DatagramProtocol):
    """One datagram = one event. Oversize is truncated and flagged by the publisher, never dropped."""

    def __init__(self, pub: Publisher, hint: str | None = None) -> None:
        self.pub, self.hint = pub, hint
        self.flusher: _Flusher | None = None
        self.received = 0

    def connection_made(self, transport: Any) -> None:
        self.flusher = _Flusher(self.pub, asyncio.get_running_loop())
        sock = transport.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            except OSError:
                pass

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if data.endswith(b"\n"):  # some senders terminate datagrams with a newline; that is framing, not payload
            data = data[:-1]
        if not data:
            return
        self.received += 1
        self.pub.ingest(data, "udp", addr[0], addr[1], self.hint)
        assert self.flusher is not None
        self.flusher.touch()

    def connection_lost(self, exc: Exception | None) -> None:
        if self.flusher:
            self.flusher.close()


class TcpProtocol(asyncio.Protocol):
    def __init__(self, pub: Publisher, framing: str, tls: bool, hint: str | None = None) -> None:
        self.pub, self.framing, self.tls, self.hint = pub, framing, tls, hint
        self.deframer = Deframer(pub.max_event_bytes, framing)
        self.transport: asyncio.Transport | None = None
        self.peer: tuple[str, int] = ("", 0)
        self.flusher: _Flusher | None = None
        self.received = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        pn = transport.get_extra_info("peername") or ("", 0)
        self.peer = (pn[0], pn[1])
        self.flusher = _Flusher(self.pub, asyncio.get_running_loop())

    def data_received(self, data: bytes) -> None:
        name = "tls" if self.tls else "tcp"
        for msg, trunc in self.deframer.feed(data):
            self.received += 1
            self.pub.ingest(msg, name, self.peer[0], self.peer[1], self.hint, trunc)
        assert self.flusher is not None
        self.flusher.touch()
        # backpressure: publish is synchronous, so a slow bus already stalls this loop; if the buffer is big, flush before reading on
        if self.pub.pending >= self.pub.batch_max:
            self.pub.flush()

    def connection_lost(self, exc: Exception | None) -> None:
        name = "tls" if self.tls else "tcp"
        for msg, trunc in self.deframer.close():
            self.pub.ingest(msg, name, self.peer[0], self.peer[1], self.hint, trunc)
        if self.flusher:
            self.flusher.close()


class SyslogServers:
    """Owns the UDP/TCP/TLS endpoints; ``ports`` reports the actually bound ports (tests bind port 0)."""

    def __init__(self, pub: Publisher) -> None:
        self.pub = pub
        self.udp: asyncio.DatagramTransport | None = None
        self.tcp: asyncio.Server | None = None
        self.tls: asyncio.Server | None = None
        self.ports: dict[str, int] = {}
        self._udp_proto: UdpProtocol | None = None

    async def start_udp(self, listen: str, hint: str | None = None) -> int:
        host, port = split_hostport(listen)
        loop = asyncio.get_running_loop()
        self._udp_proto = UdpProtocol(self.pub, hint)
        tr, _ = await loop.create_datagram_endpoint(lambda: self._udp_proto, local_addr=(host, port))
        self.udp = tr  # type: ignore[assignment]
        self.ports["udp"] = tr.get_extra_info("sockname")[1]
        return int(self.ports["udp"])

    async def start_tcp(self, listen: str, framing: str = "auto", hint: str | None = None) -> int:
        host, port = split_hostport(listen)
        loop = asyncio.get_running_loop()
        self.tcp = await loop.create_server(lambda: TcpProtocol(self.pub, framing, False, hint), host, port)
        self.ports["tcp"] = self.tcp.sockets[0].getsockname()[1]
        return int(self.ports["tcp"])

    async def start_tls(self, listen: str, cert: str, key: str, framing: str = "auto", hint: str | None = None) -> int:
        host, port = split_hostport(listen)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        loop = asyncio.get_running_loop()
        self.tls = await loop.create_server(lambda: TcpProtocol(self.pub, framing, True, hint), host, port, ssl=ctx)
        self.ports["tls"] = self.tls.sockets[0].getsockname()[1]
        return int(self.ports["tls"])

    async def close(self) -> None:
        for s in (self.tcp, self.tls):
            if s:
                s.close()
                await s.wait_closed()
        if self.udp:
            self.udp.close()
        self.pub.flush()
