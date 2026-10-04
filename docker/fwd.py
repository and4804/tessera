"""Minimal port forwarder for the `gateway` compose service.

Docker does not publish ports of containers that are attached only to an `internal: true` network, so the app containers (api, ingest,
worker, redis) stay internal and this process is the single bridge to the host: it listens on the published ports and forwards to the
internal services. Stdlib only. Usage: python fwd.py tcp:8080=api:8080 tcp:5140=ingest:5140 udp:5140=ingest:5140
Limitation: UDP syslog reaches the node from the gateway's address, so source attribution must come from the syslog header (hostname),
not the datagram's sender address.
"""
import asyncio
import sys


async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except OSError:
        pass
    finally:
        w.close()


def _tcp(host: str, port: int):
    async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        try:
            ur, uw = await asyncio.open_connection(host, port)
        except OSError:
            cw.close()
            return
        await asyncio.gather(_pipe(cr, uw), _pipe(ur, cw))
    return handle


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, target: tuple[str, int]) -> None:
        self.target = target
        self.up: asyncio.DatagramTransport | None = None

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.up is not None:
            self.up.sendto(data)


async def main(specs: list[str]) -> None:
    loop = asyncio.get_running_loop()
    for spec in specs:
        proto, rest = spec.split(":", 1)
        lport, target = rest.split("=", 1)
        host, port = target.rsplit(":", 1)
        if proto == "tcp":
            await asyncio.start_server(_tcp(host, int(port)), "0.0.0.0", int(lport))
        elif proto == "udp":
            p = _Udp((host, int(port)))
            await loop.create_datagram_endpoint(lambda p=p: p, local_addr=("0.0.0.0", int(lport)))
            up, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=(host, int(port)))
            p.up = up  # type: ignore[assignment]
        else:
            raise SystemExit(f"bad spec {spec}")
        print(f"forward {spec}", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
