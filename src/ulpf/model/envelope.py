"""Raw envelope: exactly the bytes of ONE event after transport de-framing, plus where/when it was received."""
from __future__ import annotations

import msgspec


class RawEnvelope(msgspec.Struct, frozen=True):
    raw_id: str              # UUIDv7 string, assigned at ingest (time-ordered)
    recv_ns: int             # receive time, ns since epoch, UTC
    collector_id: str        # node id
    transport: str           # "udp" | "tcp" | "tls" | "http" | "file" | "replay"
    peer_ip: str             # "" for file/replay
    peer_port: int
    data: bytes              # EXACT bytes of ONE event after transport de-framing
    hint: str | None = None  # source hint from listener/file rule (pack id or vendor tag)
    truncated: bool = False  # oversize input was cut at max_event_bytes (flagged, never dropped)


_enc = msgspec.msgpack.Encoder()
_dec = msgspec.msgpack.Decoder(RawEnvelope)


def encode_envelope(env: RawEnvelope) -> bytes:
    return _enc.encode(env)


def decode_envelope(buf: bytes) -> RawEnvelope:
    return _dec.decode(buf)
