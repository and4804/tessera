"""Vault reader: ``read(ref)`` seeks one block, decompresses it and re-verifies the SHA-256 of the requested frame."""
from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..model.lineage import VaultRef, parse_raw_ref
from . import format as fmt
from .integrity import IntegrityError


class NotFoundError(KeyError):
    """No such segment / block / frame."""


@dataclass(frozen=True, slots=True)
class RawRead:
    data: bytes
    sha256_actual: str      # recomputed from `data` just now
    sha256_stored: str      # recorded in the vault frame
    sha256_expected: str    # recorded at ingest (from the event), "" when not supplied
    verified: bool
    raw_id: str
    recv_ns: int
    transport: str
    peer_ip: str
    peer_port: int
    hint: str | None
    truncated: bool
    size: int


class VaultReader:
    def __init__(self, root: str | Path, cache_blocks: int = 64) -> None:
        self.root = Path(root)
        self._cache: OrderedDict[tuple[str, int], list[list[Any]]] = OrderedDict()
        self._cache_max = cache_blocks
        self._paths: dict[str, Path] = {}
        self._index: dict[str, tuple[int, list[fmt.BlockLoc]]] = {}   # segment -> (file size when indexed, blocks)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ locating
    def _segment_path(self, segment: str) -> Path:
        p = self._paths.get(segment)
        if p is not None and p.exists():
            return p
        for q in self.root.rglob(f"{segment}{fmt.SEG_SUFFIX}"):
            self._paths[segment] = q
            return q
        raise NotFoundError(f"segment {segment} not found")

    def _blocks(self, segment: str, path: Path, want_block: int) -> list[fmt.BlockLoc]:
        size = path.stat().st_size
        cached = self._index.get(segment)
        if cached is not None and (cached[0] == size or want_block < len(cached[1])):
            return cached[1]
        with open(path, "rb") as f:
            _, first = fmt.decode_header(f.read(min(size, 1 << 16)))
            limit = size
            if size >= fmt.TRAILER_SIZE:
                f.seek(size - fmt.TRAILER_SIZE)
                t = fmt.decode_trailer(f.read(fmt.TRAILER_SIZE))
                if t is not None:
                    limit = max(first, size - fmt.TRAILER_SIZE - t[1] - t[0])
            blocks, _ = fmt.scan_blocks(f, first, limit)
        self._index[segment] = (size, blocks)
        return blocks

    def _load_block(self, segment: str, block: int, fresh: bool = False) -> list[list[Any]]:
        key = (segment, block)
        with self._lock:
            hit = None if fresh else self._cache.get(key)
            if fresh:
                self._cache.pop(key, None)
            if hit is not None:
                self._cache.move_to_end(key)
                return hit
        path = self._segment_path(segment)
        try:
            blocks = self._blocks(segment, path, block)
        except fmt.FormatError as e:
            raise IntegrityError(f"segment header damaged: {e}", segment=segment) from e
        if block < 0 or block >= len(blocks):
            raise NotFoundError(f"{segment}/{block}: no such block")
        loc = blocks[block]
        with open(path, "rb") as f:
            try:
                comp, _stored = fmt.read_block(f, loc)
                frames, _ = fmt.decode_block_payload(comp, loc.n_frames)
            except fmt.FormatError as e:
                raise IntegrityError(f"block undecodable: {e}", segment=segment, block=block) from e
        with self._lock:
            self._cache[key] = frames
            while len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)
        return frames

    # ------------------------------------------------------------------ public
    def read_frame(self, segment: str, block: int, idx: int, expected_sha256: str = "", fresh: bool = False) -> RawRead:
        """Fetch one frame. Never raises on a hash mismatch (``verified=False``): callers decide (the API shows both sides).
        ``fresh=True`` bypasses the block cache and re-reads the block from disk (the API's Verify path: a cached block would hide
        damage done to the file after it was cached)."""
        frames = self._load_block(segment, block, fresh)
        if idx < 0 or idx >= len(frames):
            raise NotFoundError(f"{segment}/{block}/{idx}: no such frame")
        fr = frames[idx]
        data = bytes(fr[fmt.F_DATA])
        import hashlib

        actual = hashlib.sha256(data).hexdigest()
        stored = bytes(fr[fmt.F_SHA]).hex()
        ok = actual == stored and (not expected_sha256 or actual == expected_sha256)
        return RawRead(
            data=data, sha256_actual=actual, sha256_stored=stored, sha256_expected=expected_sha256, verified=ok,
            raw_id=str(fr[fmt.F_RAW_ID]), recv_ns=int(fr[fmt.F_RECV_NS]), transport=str(fr[fmt.F_TRANSPORT]),
            peer_ip=str(fr[fmt.F_PEER_IP]), peer_port=int(fr[fmt.F_PEER_PORT]),
            hint=(fr[fmt.F_HINT] if len(fr) > fmt.F_HINT else None), truncated=bool(fr[fmt.F_TRUNC]) if len(fr) > fmt.F_TRUNC else False,
            size=len(data),
        )

    def read(self, ref: VaultRef | str, expected_sha256: str | None = None) -> bytes:
        """Return the raw bytes, raising :class:`IntegrityError` when the recomputed SHA-256 differs from the recorded one."""
        if isinstance(ref, VaultRef):
            seg, block, idx, exp = ref.segment, ref.block, ref.idx, ref.sha256
        else:
            seg, block, idx = parse_raw_ref(ref)
            exp = ""
        if expected_sha256:
            exp = expected_sha256
        r = self.read_frame(seg, block, idx, exp)
        if not r.verified:
            raise IntegrityError(
                f"SHA-256 mismatch for {seg}/{block}/{idx}: expected {exp or r.sha256_stored}, got {r.sha256_actual}",
                segment=seg, block=block, frame=idx,
            )
        return r.data

    def iter_block_frames(self, segment: str, block: int) -> list[list[Any]]:
        return self._load_block(segment, block)

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()
            self._index.clear()

    # ------------------------------------------------------------------ listing
    def list_segments(self) -> list[dict[str, Any]]:
        """Light listing from manifests (sealed) or a header+block scan (open). No hash verification."""
        import json

        from .integrity import iter_segments

        out: list[dict[str, Any]] = []
        for p in iter_segments(self.root):
            seg = p.name[: -len(fmt.SEG_SUFFIX)]
            mp = p.with_name(seg + fmt.MANIFEST_SUFFIX)
            if mp.exists():
                try:
                    m = json.loads(mp.read_text())
                    m["sealed"] = True
                    out.append(m)
                    continue
                except (OSError, ValueError):
                    pass
            try:
                size = p.stat().st_size
                with open(p, "rb") as f:
                    header, first = fmt.decode_header(f.read(min(size, 1 << 16)))
                    blocks, _ = fmt.scan_blocks(f, first, size)
                out.append({
                    "segment": seg, "node_id": header.get("node_id", ""), "created_ns": header.get("created_ns"), "sealed_ns": None,
                    "n_events": sum(b.n_frames for b in blocks), "n_blocks": len(blocks), "size_bytes": size, "chain_head": "",
                    "sealed": False, "pubkey": header.get("pubkey", ""), "prev_segment_head": header.get("prev_segment_head", ""),
                })
            except (OSError, fmt.FormatError):
                out.append({"segment": seg, "sealed": False, "n_events": 0, "n_blocks": 0, "size_bytes": 0, "damaged": True})
        return out
