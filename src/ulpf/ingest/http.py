"""HTTP ingest router (§7.1): ``POST <path>`` body = one event, or ``application/x-ndjson`` = many. Optional bearer token.

Mounted by the API process; it shares the same :class:`Publisher` contract as the syslog listeners."""
from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from .publisher import Publisher


def make_ingest_router(pub: Publisher, path: str = "/ingest/raw", token: str | None = None, max_body: int = 16 * 1024 * 1024) -> APIRouter:
    router = APIRouter()

    @router.post(path)
    async def ingest_raw(request: Request, hint: str | None = None) -> dict[str, Any]:
        if token:
            got = request.headers.get("authorization", "")
            if not hmac.compare_digest(got, f"Bearer {token}"):
                raise HTTPException(401, detail={"error": {"code": "UNAUTHORIZED", "message": "bad or missing bearer token"}})
        body = await request.body()
        if len(body) > max_body:
            raise HTTPException(413, detail={"error": {"code": "TOO_LARGE", "message": f"body exceeds {max_body} bytes"}})
        peer = request.client.host if request.client else ""
        port = request.client.port if request.client else 0
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        hint = hint or request.headers.get("x-ulpf-hint") or None
        n = 0
        if ctype in ("application/x-ndjson", "application/ndjson"):
            for ln in body.split(b"\n"):
                if ln.endswith(b"\r"):
                    ln = ln[:-1]
                if ln:
                    pub.ingest(ln, "http", peer, port, hint)
                    n += 1
        elif body:
            pub.ingest(body[:-1] if body.endswith(b"\n") else body, "http", peer, port, hint)
            n = 1
        pub.flush()
        return {"accepted": n}

    return router
