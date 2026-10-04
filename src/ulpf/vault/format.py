"""Raw Vault segment format (§7.3).

    magic "ULPFSEG1" | u32 header_len | msgpack(header)
    block*   : u32 comp_len | u32 n_frames | zstd(msgpack([frame, ...])) | 32B chain_hash
    footer   : msgpack(footer) | ed25519_sig(chain_head) (0 or 64 B) | u32 footer_len | u8 sig_len | "ULPFEND1"
    frame    : [raw_id, recv_ns, transport, peer_ip, peer_port, sha256(32B), data, hint, truncated]

``hint`` and ``truncated`` are trailing additions to the §7.3 frame (readers accept the 7-field form).
chain_hash_i = SHA256(chain_hash_{i-1} || SHA256(plain_block_bytes)); block 0 chains from ``prev_segment_head``.
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import msgspec
import zstandard

MAGIC = b"ULPFSEG1"
END_MAGIC = b"ULPFEND1"
VERSION = 1
GENESIS = bytes(32)
BLOCK_HDR = struct.Struct("<II")        # comp_len, n_frames
U32 = struct.Struct("<I")
TRAILER = struct.Struct("<IB8s")        # footer_len, sig_len, END_MAGIC
TRAILER_SIZE = TRAILER.size
SEG_SUFFIX = ".ulpfseg"
MANIFEST_SUFFIX = ".manifest.json"
MAX_COMP_LEN = 1 << 30
ZSTD_LEVEL = 3

F_RAW_ID, F_RECV_NS, F_TRANSPORT, F_PEER_IP, F_PEER_PORT, F_SHA, F_DATA, F_HINT, F_TRUNC = range(9)

_enc = msgspec.msgpack.Encoder()
_dec = msgspec.msgpack.Decoder()
_cctx = zstandard.ZstdCompressor(level=ZSTD_LEVEL, write_checksum=False, write_content_size=True)
_dctx = zstandard.ZstdDecompressor()


class FormatError(Exception):
    """Structurally invalid segment bytes."""


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def chain_next(prev: bytes, plain_sha: bytes) -> bytes:
    return hashlib.sha256(prev + plain_sha).digest()


def encode_header(header: dict[str, Any]) -> bytes:
    body = _enc.encode(header)
    return MAGIC + U32.pack(len(body)) + body


def decode_header(buf: bytes) -> tuple[dict[str, Any], int]:
    """Return (header, offset_of_first_block)."""
    if len(buf) < len(MAGIC) + 4 or buf[: len(MAGIC)] != MAGIC:
        raise FormatError("bad magic")
    (n,) = U32.unpack_from(buf, len(MAGIC))
    end = len(MAGIC) + 4 + n
    if n > 1 << 20 or len(buf) < end:
        raise FormatError("truncated header")
    try:
        h = _dec.decode(buf[len(MAGIC) + 4 : end])
    except msgspec.DecodeError as e:
        raise FormatError(f"header undecodable: {e}") from e
    if not isinstance(h, dict):
        raise FormatError("header is not a map")
    return h, end


def encode_block(frames: Sequence[Sequence[Any]], prev_chain: bytes) -> tuple[bytes, bytes]:
    """Return (block bytes, new chain hash)."""
    plain = _enc.encode(list(frames))
    comp = _cctx.compress(plain)
    new_chain = chain_next(prev_chain, sha256(plain))
    return BLOCK_HDR.pack(len(comp), len(frames)) + comp + new_chain, new_chain


def decode_block_payload(comp: bytes, n_frames: int) -> tuple[list[list[Any]], bytes]:
    """Decompress + decode; returns (frames, plain_sha). Raises FormatError."""
    try:
        plain = _dctx.decompress(comp, max_output_size=1 << 31)
    except zstandard.ZstdError as e:
        raise FormatError(f"zstd: {e}") from e
    try:
        frames = _dec.decode(plain)
    except msgspec.DecodeError as e:
        raise FormatError(f"msgpack: {e}") from e
    if not isinstance(frames, list) or len(frames) != n_frames:
        raise FormatError("frame count mismatch")
    for f in frames:
        if not isinstance(f, list) or len(f) < 7 or not isinstance(f[F_DATA], bytes | bytearray) or not isinstance(f[F_SHA], bytes):
            raise FormatError("malformed frame")
    return frames, sha256(plain)


@dataclass(frozen=True, slots=True)
class BlockLoc:
    offset: int       # offset of the block header
    comp_len: int
    n_frames: int

    @property
    def payload_offset(self) -> int:
        return self.offset + BLOCK_HDR.size

    @property
    def end(self) -> int:
        return self.payload_offset + self.comp_len + 32


def encode_footer(footer: dict[str, Any], sig: bytes) -> bytes:
    body = _enc.encode(footer)
    return body + sig + TRAILER.pack(len(body), len(sig), END_MAGIC)


def decode_trailer(tail: bytes) -> tuple[int, int] | None:
    """Parse the last TRAILER_SIZE bytes -> (footer_len, sig_len) or None if this is not a sealed segment end."""
    if len(tail) < TRAILER_SIZE:
        return None
    fl, sl, m = TRAILER.unpack(tail[-TRAILER_SIZE:])
    if m != END_MAGIC or sl not in (0, 64):
        return None
    return fl, sl


def decode_footer(body: bytes) -> dict[str, Any]:
    try:
        f = _dec.decode(body)
    except msgspec.DecodeError as e:
        raise FormatError(f"footer undecodable: {e}") from e
    if not isinstance(f, dict):
        raise FormatError("footer is not a map")
    return f


def scan_blocks(f: Any, start: int, limit: int) -> tuple[list[BlockLoc], int]:
    """Walk block headers from ``start`` (no decompression). Stops at the first block that is incomplete or implausible.

    Returns the complete blocks and the offset just past the last of them."""
    out: list[BlockLoc] = []
    pos = start
    while pos + BLOCK_HDR.size + 32 <= limit:
        f.seek(pos)
        hdr = f.read(BLOCK_HDR.size)
        if len(hdr) < BLOCK_HDR.size:
            break
        comp_len, n = BLOCK_HDR.unpack(hdr)
        if comp_len > MAX_COMP_LEN or n == 0 or pos + BLOCK_HDR.size + comp_len + 32 > limit:
            break
        out.append(BlockLoc(pos, comp_len, n))
        pos += BLOCK_HDR.size + comp_len + 32
    return out, pos


def read_block(f: Any, loc: BlockLoc) -> tuple[bytes, bytes]:
    """Return (compressed payload, stored chain hash)."""
    f.seek(loc.payload_offset)
    buf = f.read(loc.comp_len + 32)
    if len(buf) != loc.comp_len + 32:
        raise FormatError("short block read")
    return buf[: loc.comp_len], buf[loc.comp_len :]


def seg_seq(segment_id: str) -> int:
    return int(segment_id.rsplit("-", 1)[1])
