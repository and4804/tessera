"""``/ledger``, ``/vault/segments``, ``POST /vault/verify`` (NDJSON progress), ``/health``-adjacent integrity views."""
from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import orjson
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from ..pipeline.ledger import backlog, report
from ..vault.integrity import iter_segments, verify_all
from .state import AppState, err


def make_router(st: AppState) -> APIRouter:
    r = APIRouter()

    @r.get("/ledger")
    def ledger() -> dict[str, Any]:
        if st.bus is None:
            raise err(503, "NO_BUS", "this API process has no bus connection, so no ledger")
        try:
            return report(st.bus.ledger.snapshot(), backlog(st.bus), int(time.time() * 1000))
        except Exception as e:  # noqa: BLE001
            raise err(503, "BUS_DOWN", f"cannot read the ledger: {e}") from e

    @r.get("/vault/segments")
    def segments() -> dict[str, Any]:
        items = []
        for s in st.vault.list_segments():
            seg = s.get("segment", "")
            c = st.verify_cache.get(seg)
            sealed = bool(s.get("sealed"))
            created = s.get("created_ns")
            item: dict[str, Any] = {
                "segment": seg, "node_id": s.get("node_id", ""), "created_ms": int(created // 1_000_000) if created else 0,
                "sealed_ms": int(s["sealed_ns"] // 1_000_000) if s.get("sealed_ns") else None, "n_events": int(s.get("n_events", 0)),
                "n_blocks": int(s.get("n_blocks", 0)), "size_bytes": int(s.get("size_bytes", 0)), "chain_head": s.get("chain_head", ""),
                "chain_status": "open" if not sealed else "unverified", "signature_ok": None, "last_verified_ms": None, "error": None,
            }
            if s.get("damaged"):
                item["chain_status"] = "broken"
                item["error"] = {"block": 0, "frame": None, "message": "segment header unreadable"}
            if c is not None:
                item.update({"chain_status": c["chain_status"], "signature_ok": c["signature_ok"], "last_verified_ms": c["t"],
                             "error": c["error"]})
                if c["chain_status"] == "ok" and not sealed:
                    item["chain_status"] = "open"
            items.append(item)
        return {"items": items}

    @r.post("/vault/verify")
    async def verify(request: Request) -> StreamingResponse:
        try:
            body = await request.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            raise err(400, "BAD_REQUEST", "body must be {all: true} or {segment: name}")
        only = body.get("segment")
        if not body.get("all") and not only:
            raise err(400, "BAD_REQUEST", "body must be {\"all\": true} or {\"segment\": \"n1-000042\"}")
        if only is not None and not isinstance(only, str):
            raise err(400, "BAD_REQUEST", "segment must be a string")
        total = len(iter_segments(st.cfg.vault.dir)) if not only else 1
        pub = st.pubkey

        def gen() -> Iterator[bytes]:
            t0 = time.time()
            n = frames = 0
            first: dict[str, Any] | None = None
            for rep in verify_all(st.cfg.vault.dir, pub, only):
                n += 1
                frames += rep.frames_checked
                err_obj = None if rep.ok else {"block": rep.error_block if rep.error_block is not None else 0, "frame": rep.error_frame,
                                               "message": rep.error or "failed"}
                st.verify_cache[rep.segment] = {"chain_status": rep.chain_status if rep.ok or rep.chain_status == "broken" else "broken",
                                                "signature_ok": rep.signature_ok, "t": int(time.time() * 1000), "error": err_obj}
                if not rep.ok and first is None:
                    first = {"segment": rep.segment, "block": err_obj["block"] if err_obj else 0, "frame": rep.error_frame}
                yield orjson.dumps({"type": "segment_result", "segment": rep.segment, "ok": rep.ok, "blocks_checked": rep.blocks_checked,
                                    "frames_checked": rep.frames_checked, "error": err_obj}) + b"\n"
                yield orjson.dumps({"type": "progress", "segment": rep.segment, "done": n, "total": max(total, n)}) + b"\n"
            yield orjson.dumps({"type": "done", "ok": first is None, "segments_checked": n, "frames_checked": frames,
                                "duration_ms": int((time.time() - t0) * 1000), "first_failure": first}) + b"\n"

        return StreamingResponse(gen(), media_type="application/x-ndjson")

    return r
