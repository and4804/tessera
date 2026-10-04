"""Vault verification (`ulpf verify`): recompute every frame hash, the chain, cross-segment links and the signature."""
from __future__ import annotations

import json
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from . import format as fmt


class IntegrityError(Exception):
    """Stored bytes do not match their recorded hash / chain."""

    def __init__(self, message: str, *, segment: str = "", block: int | None = None, frame: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.segment = segment
        self.block = block
        self.frame = frame


@dataclass(slots=True)
class SegmentReport:
    segment: str
    path: str
    ok: bool = True
    sealed: bool = False
    chain_status: str = "ok"            # ok | open | broken
    signature_ok: bool | None = None    # None: unsigned/open
    signature_pinned: bool = False
    blocks_checked: int = 0
    frames_checked: int = 0
    n_events: int = 0
    n_blocks: int = 0
    size_bytes: int = 0
    chain_head: str = ""
    prev_head: str = ""
    node_id: str = ""
    created_ns: int = 0
    sealed_ns: int | None = None
    error_block: int | None = None
    error_frame: int | None = None
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    def fail(self, msg: str, block: int | None = None, frame: int | None = None) -> None:
        if self.ok:  # keep the FIRST failure
            self.ok = False
            self.error, self.error_block, self.error_frame = msg, block, frame
        self.chain_status = "broken"


def iter_segments(root: str | Path) -> list[Path]:
    """All segment files under ``root`` ordered by (shard prefix, sequence)."""
    paths = [p for p in Path(root).rglob(f"*{fmt.SEG_SUFFIX}")]

    def key(p: Path) -> tuple[str, int]:
        stem = p.name[: -len(fmt.SEG_SUFFIX)]
        head, _, num = stem.rpartition("-")
        return head, int(num) if num.isdigit() else 0

    return sorted(paths, key=key)


def verify_segment(path: str | Path, pubkey: bytes | None = None, *, prev_head: bytes | None = None) -> SegmentReport:
    """Verify one segment file. ``pubkey`` pins the trusted signer; without it the key embedded in the header is used and the
    report marks the signature as unpinned. ``prev_head`` (when known) is checked against the header's ``prev_segment_head``."""
    p = Path(path)
    seg = p.name[: -len(fmt.SEG_SUFFIX)]
    rep = SegmentReport(segment=seg, path=str(p))
    manifest_path = p.with_name(seg + fmt.MANIFEST_SUFFIX)
    manifest: dict[str, Any] | None = None
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError):
            rep.fail("manifest unreadable")
    try:
        size = p.stat().st_size
    except OSError as e:
        rep.fail(f"cannot stat: {e}")
        return rep
    rep.size_bytes = size
    with open(p, "rb") as f:
        try:
            header, first = fmt.decode_header(f.read(min(size, 1 << 16)))
        except fmt.FormatError as e:
            rep.fail(f"header: {e}")
            return rep
        rep.node_id = str(header.get("node_id", ""))
        rep.created_ns = int(header.get("created_ns", 0) or 0)
        if header.get("segment_id") != seg:
            rep.fail(f"header segment_id {header.get('segment_id')!r} != file name")
        try:
            hdr_prev = bytes.fromhex(header.get("prev_segment_head") or "") or fmt.GENESIS
        except ValueError:
            rep.fail("header prev_segment_head is not hex")
            return rep
        rep.prev_head = hdr_prev.hex() if hdr_prev != fmt.GENESIS else ""
        if prev_head is not None and prev_head != hdr_prev:
            rep.fail("segment does not chain from the previous segment's head (missing/replaced/reordered segment)", block=0)

        # locate footer
        limit = size
        footer: dict[str, Any] | None = None
        sig = b""
        if size >= fmt.TRAILER_SIZE:
            f.seek(size - fmt.TRAILER_SIZE)
            t = fmt.decode_trailer(f.read(fmt.TRAILER_SIZE))
            if t is not None:
                fl, sl = t
                fstart = size - fmt.TRAILER_SIZE - sl - fl
                if fstart >= first:
                    f.seek(fstart)
                    body = f.read(fl)
                    sig = f.read(sl)
                    try:
                        footer = fmt.decode_footer(body)
                        limit = fstart
                    except fmt.FormatError as e:
                        rep.fail(f"footer: {e}")
        rep.sealed = footer is not None
        if footer is None and manifest is not None:
            rep.fail("segment is recorded as sealed (manifest) but its footer is missing or damaged")

        blocks, end = fmt.scan_blocks(f, first, limit)
        if end != limit:
            if footer is None and manifest is None:
                rep.notes.append(f"{limit - end} trailing bytes after the last complete block (torn write; recoverable by the writer)")
            else:
                rep.fail(f"{limit - end} unaccounted bytes before the footer", block=len(blocks))
        chain = hdr_prev
        for bi, loc in enumerate(blocks):
            try:
                comp, stored = fmt.read_block(f, loc)
            except fmt.FormatError as e:
                rep.fail(str(e), block=bi)
                break
            try:
                frames, psha = fmt.decode_block_payload(comp, loc.n_frames)
            except fmt.FormatError as e:
                rep.fail(f"block undecodable ({e})", block=bi)
                # cannot recompute this block's chain; adopt the stored value to keep checking later blocks independently
                chain = stored
                rep.blocks_checked += 1
                continue
            for fi, fr in enumerate(frames):
                if fmt.sha256(bytes(fr[fmt.F_DATA])) != fr[fmt.F_SHA]:
                    rep.fail("frame data does not match its recorded SHA-256", block=bi, frame=fi)
                rep.frames_checked += 1
            want = fmt.chain_next(chain, psha)
            if want != stored:
                rep.fail("chain hash mismatch (block content or chain link altered)", block=bi)
            chain = stored
            rep.blocks_checked += 1
            rep.n_events += loc.n_frames
        rep.n_blocks = len(blocks)
        rep.chain_head = chain.hex()

        if footer is not None:
            if footer.get("chain_head") != rep.chain_head:
                rep.fail("footer chain_head differs from the recomputed chain")
            if footer.get("n_events") != rep.n_events or footer.get("n_blocks", len(blocks)) != len(blocks):
                rep.fail("footer event/block counts differ from the segment contents")
            if footer.get("block_offsets") != [b.offset for b in blocks]:
                rep.fail("footer block offsets differ from the segment contents")
            rep.sealed_ns = footer.get("sealed_ns")
            if manifest is not None and manifest.get("chain_head") != rep.chain_head:
                rep.fail("manifest chain_head differs from the recomputed chain")
            embedded = header.get("pubkey") or ""
            if sig:
                key_hex = pubkey.hex() if pubkey else embedded
                rep.signature_pinned = pubkey is not None
                if pubkey is not None and embedded and embedded != pubkey.hex():
                    rep.signature_ok = False
                    rep.fail("segment was signed by a different key than the trusted public key")
                else:
                    try:
                        VerifyKey(bytes.fromhex(key_hex)).verify(chain, sig)
                        rep.signature_ok = True
                    except (BadSignatureError, ValueError):
                        rep.signature_ok = False
                        rep.fail("Ed25519 signature over the chain head is invalid")
                if rep.signature_ok and not rep.signature_pinned:
                    rep.notes.append("signature valid against the key embedded in the segment (pass --pubkey to pin the signer)")
            elif pubkey is not None:
                rep.signature_ok = False
                rep.fail("segment is unsigned but a trusted public key was supplied")
        else:
            rep.chain_status = "open" if rep.ok else "broken"
    if rep.ok and rep.sealed:
        rep.chain_status = "ok"
    return rep


def verify_all(
    root: str | Path, pubkey: bytes | None = None, only: str | None = None,
) -> Iterator[SegmentReport]:
    """Verify every segment (or only ``only``), checking links between consecutive segments of each shard."""
    last_head: dict[str, bytes] = {}
    last_seq: dict[str, int] = {}
    first_seen: set[str] = set()
    for p in iter_segments(root):
        stem = p.name[: -len(fmt.SEG_SUFFIX)]
        shard, _, num = stem.rpartition("-")
        seq = int(num) if num.isdigit() else 0
        expected_prev = last_head.get(shard) if (shard in first_seen and last_seq.get(shard, 0) + 1 == seq) else None
        gap = shard in first_seen and last_seq.get(shard, 0) + 1 != seq
        if only is None or stem == only:
            rep = verify_segment(p, pubkey, prev_head=expected_prev)
            if gap:
                rep.fail(f"sequence gap: segment {last_seq[shard]} is followed by {seq} (segment missing)", block=0)
            yield rep
            head = bytes.fromhex(rep.chain_head) if rep.chain_head else fmt.GENESIS
        else:
            # still need its head to link the next segment; cheap structural read
            rep = verify_segment(p, pubkey, prev_head=None)
            head = bytes.fromhex(rep.chain_head) if rep.chain_head else fmt.GENESIS
        first_seen.add(shard)
        last_head[shard], last_seq[shard] = head, seq


def verify_summary(reports: list[SegmentReport]) -> dict[str, Any]:
    t0 = time.time()
    bad = next((r for r in reports if not r.ok), None)
    return {
        "ok": bad is None, "segments_checked": len(reports), "frames_checked": sum(r.frames_checked for r in reports),
        "first_failure": None if bad is None else {"segment": bad.segment, "block": bad.error_block, "frame": bad.error_frame,
                                                    "message": bad.error},
        "t": t0,
    }
