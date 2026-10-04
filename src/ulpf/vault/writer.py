"""Vault writer: append-only, deterministic block assignment, crash recovery, optional Ed25519 sealing (§7.3)."""
from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

from ..model.envelope import RawEnvelope
from ..model.lineage import VaultRef
from . import format as fmt


def generate_keypair(path: str | Path) -> tuple[Path, Path]:
    """Write a new Ed25519 seed (hex, mode 0600) to ``path`` and the public key to ``path + '.pub'``."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    sk = SigningKey.generate()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(bytes(sk).hex() + "\n")
    pub = Path(str(p) + ".pub")
    pub.write_text(bytes(sk.verify_key).hex() + "\n")
    return p, pub


def load_signing_key(path: str | Path | None) -> SigningKey | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    return SigningKey(bytes.fromhex(p.read_text().strip()))


def _fsync_dir(d: Path) -> None:
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class VaultWriter:
    """One writer owns one shard: segments ``<node_id><shard>-NNNNNN`` under ``root/yyyy/mm/dd/``.

    ``append`` returns the final ``VaultRef`` immediately (segment, block, idx are decided at append time). A block is written when
    ``block_events`` frames are buffered or ``block_max_ms`` has elapsed (checked on append/``tick``); ``flush()`` writes any
    partial block and fsyncs. Callers MUST ``flush()`` before releasing events to sinks (I1).
    """

    def __init__(
        self,
        root: str | Path,
        node_id: str,
        *,
        shard: str = "",
        block_events: int = 1000,
        block_max_ms: int = 500,
        segment_max_mb: float = 256,
        fsync: bool = True,
        signing_key: SigningKey | None = None,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        self.root = Path(root)
        self.node_id = node_id
        self.prefix = f"{node_id}{shard}"
        self.block_events = block_events
        self.block_max_s = block_max_ms / 1000.0
        self.segment_max_bytes = int(segment_max_mb * 1024 * 1024)
        self.fsync = fsync
        self.sk = signing_key
        self._clock = clock_ns
        self.root.mkdir(parents=True, exist_ok=True)
        # state of the open segment
        self._f: Any = None
        self._path: Path | None = None
        self._segment = ""
        self._seq = 0
        self._chain = fmt.GENESIS
        self._block_seq = 0
        self._n_events = 0          # events in blocks already written
        self._offsets: list[int] = []
        self._size = 0
        self._header: dict[str, Any] = {}
        self._need_rotate = False
        self._buf: list[tuple[Any, ...]] = []
        self._buf_started = 0.0
        self.recovered_truncated_bytes = 0
        self.appended = 0
        self._open_or_recover()

    # ------------------------------------------------------------------ segment lifecycle
    def _existing(self) -> list[tuple[int, Path]]:
        found: list[tuple[int, Path]] = []
        for p in self.root.rglob(f"{self.prefix}-*{fmt.SEG_SUFFIX}"):
            stem = p.name[: -len(fmt.SEG_SUFFIX)]
            head, _, num = stem.rpartition("-")
            if head == self.prefix and num.isdigit():
                found.append((int(num), p))
        found.sort()
        return found

    @staticmethod
    def _sealed_head(path: Path) -> bytes | None:
        """chain_head of a sealed segment, or None when it is open/damaged."""
        try:
            size = path.stat().st_size
            with open(path, "rb") as f:
                if size < fmt.TRAILER_SIZE:
                    return None
                f.seek(size - fmt.TRAILER_SIZE)
                t = fmt.decode_trailer(f.read(fmt.TRAILER_SIZE))
                if t is None:
                    return None
                fl, sl = t
                f.seek(size - fmt.TRAILER_SIZE - sl - fl)
                footer = fmt.decode_footer(f.read(fl))
            return bytes.fromhex(footer["chain_head"])
        except (OSError, fmt.FormatError, KeyError, ValueError):
            return None

    def _open_or_recover(self) -> None:
        existing = self._existing()
        prev_head = fmt.GENESIS
        next_seq = 1
        while existing:
            seq, path = existing[-1]
            head = self._sealed_head(path)
            if head is not None:
                prev_head, next_seq = head, seq + 1
                break
            if self._resume(seq, path):
                return
            # unusable (header torn): move aside, fall back to the segment before it
            path.rename(path.with_suffix(".torn"))
            existing.pop()
            if existing:
                head = self._sealed_head(existing[-1][1])
                if head is not None:
                    prev_head = head
            next_seq = seq
        self._new_segment(next_seq, prev_head)

    def _resume(self, seq: int, path: Path) -> bool:
        """Re-open an unsealed segment, truncating a torn trailing block. False when the header itself is unusable."""
        size = path.stat().st_size
        with open(path, "rb") as f:
            try:
                header, first = fmt.decode_header(f.read(min(size, 1 << 16)))
            except fmt.FormatError:
                return False
            blocks, end = fmt.scan_blocks(f, first, size)
            genesis_prev = bytes.fromhex(header["prev_segment_head"]) if header.get("prev_segment_head") else fmt.GENESIS
            chain = genesis_prev
            # Re-validate the LAST complete block only: a torn write can be complete in length yet garbage. Mid-file damage is
            # not a crash symptom and is left for `ulpf verify` to report (never truncated away).
            while blocks:
                last = blocks[-1]
                comp, stored = fmt.read_block(f, last)
                prior = fmt.read_block(f, blocks[-2])[1] if len(blocks) > 1 else genesis_prev
                try:
                    _frames, psha = fmt.decode_block_payload(comp, last.n_frames)
                    ok = fmt.chain_next(prior, psha) == stored
                except fmt.FormatError:
                    ok = False
                if ok:
                    chain = stored
                    break
                blocks.pop()
                end = last.offset
            if not blocks:
                end = first
        self._n_events = sum(b.n_frames for b in blocks)
        self.recovered_truncated_bytes = size - end
        fh = open(path, "r+b")
        fh.truncate(end)
        fh.seek(end)
        self._f, self._path = fh, path
        self._segment = path.name[: -len(fmt.SEG_SUFFIX)]
        self._seq = seq
        self._chain = chain
        self._block_seq = len(blocks)
        self._offsets = [b.offset for b in blocks]
        self._size = end
        self._header = header
        return True

    def _new_segment(self, seq: int, prev_head: bytes) -> None:
        now = self._clock()
        d = datetime.fromtimestamp(now / 1e9, UTC)
        directory = self.root / f"{d.year:04d}" / f"{d.month:02d}" / f"{d.day:02d}"
        directory.mkdir(parents=True, exist_ok=True)
        self._segment = f"{self.prefix}-{seq:06d}"
        self._path = directory / f"{self._segment}{fmt.SEG_SUFFIX}"
        header = {
            "segment_id": self._segment, "node_id": self.node_id, "created_ns": now, "version": fmt.VERSION,
            "prev_segment_head": prev_head.hex() if prev_head != fmt.GENESIS else "",
            "pubkey": bytes(self.sk.verify_key).hex() if self.sk else "",
        }
        hb = fmt.encode_header(header)
        self._f = open(self._path, "wb")
        self._f.write(hb)
        self._f.flush()
        if self.fsync:
            os.fsync(self._f.fileno())
            _fsync_dir(directory)
        self._seq = seq
        self._chain = prev_head
        self._block_seq = 0
        self._n_events = 0
        self._offsets = []
        self._size = len(hb)
        self._header = header

    def _seal(self) -> None:
        if self._f is None or self._path is None:
            return
        footer = {
            "block_offsets": self._offsets, "n_events": self._n_events, "n_blocks": self._block_seq,
            "chain_head": self._chain.hex(), "sealed_ns": self._clock(),
        }
        sig = self.sk.sign(self._chain).signature if self.sk else b""
        self._f.write(fmt.encode_footer(footer, sig))
        self._f.flush()
        if self.fsync:
            os.fsync(self._f.fileno())
        size = self._f.tell()
        self._f.close()
        self._f = None
        header = self._header
        manifest = {
            "segment": self._segment, "node_id": header.get("node_id", self.node_id), "created_ns": header.get("created_ns"),
            "sealed_ns": footer["sealed_ns"], "n_events": self._n_events, "n_blocks": self._block_seq, "size_bytes": size,
            "chain_head": footer["chain_head"], "prev_segment_head": header.get("prev_segment_head", ""),
            "pubkey": header.get("pubkey", ""), "signed": bool(sig), "file": self._path.name,
        }
        mp = self._path.with_name(self._segment + fmt.MANIFEST_SUFFIX)
        tmp = mp.with_suffix(".tmp")
        tmp.write_text(json.dumps(manifest))
        os.replace(tmp, mp)

    def _rotate(self) -> None:
        head = self._chain
        self._seal()
        self._new_segment(self._seq + 1, head)

    # ------------------------------------------------------------------ public API
    @property
    def segment(self) -> str:
        return self._segment

    @property
    def path(self) -> Path:
        assert self._path is not None
        return self._path

    def append(
        self, raw_id: str, recv_ns: int, transport: str, peer_ip: str, peer_port: int, data: bytes,
        hint: str | None = None, truncated: bool = False,
    ) -> VaultRef:
        digest = fmt.sha256(data)
        if not self._buf:
            if self._need_rotate:  # lazy rotation: never leaves an empty trailing segment
                self._need_rotate = False
                self._rotate()
            self._buf_started = time.monotonic()
        idx = len(self._buf)
        self._buf.append((raw_id, recv_ns, transport, peer_ip, peer_port, digest, data, hint, truncated))
        ref = VaultRef(self._segment, self._block_seq, idx, digest.hex())
        self.appended += 1
        if idx + 1 >= self.block_events or time.monotonic() - self._buf_started >= self.block_max_s:
            self._write_block()
        return ref

    def append_envelope(self, env: RawEnvelope) -> VaultRef:
        return self.append(env.raw_id, env.recv_ns, env.transport, env.peer_ip, env.peer_port, env.data, env.hint, env.truncated)

    def tick(self) -> None:
        """Cut a block if one has been buffering for ``block_max_ms`` (call from idle loops)."""
        if self._buf and time.monotonic() - self._buf_started >= self.block_max_s:
            self._write_block()

    def _write_block(self) -> None:
        if not self._buf:
            return
        assert self._f is not None
        data, self._chain = fmt.encode_block(self._buf, self._chain)
        self._offsets.append(self._size)
        self._f.write(data)
        self._size += len(data)
        self._n_events += len(self._buf)
        self._block_seq += 1
        self._buf = []
        if self._size >= self.segment_max_bytes:
            self._need_rotate = True

    def flush(self) -> None:
        """Write any partial block and make everything appended so far durable (fsync)."""
        self._write_block()
        if self._f is not None:
            self._f.flush()
            if self.fsync:
                os.fsync(self._f.fileno())

    def close(self, seal: bool = True) -> None:
        if self._f is None:
            return
        self.flush()
        if seal:
            self._seal()
        else:
            self._f.close()
            self._f = None

    def __enter__(self) -> VaultWriter:
        return self

    def __exit__(self, *a: object) -> None:
        self.close()

    def stats(self) -> dict[str, Any]:
        return {"segment": self._segment, "blocks": self._block_seq, "events": self._n_events + len(self._buf), "bytes": self._size,
                "buffered": len(self._buf)}
