"""``WS /stream``: live tail from ``norm.tail`` (Redis stream or the in-process tail) with server-side filtering.

Client -> server: ``{"op": "filter", "q": str, "sources": [..], "statuses": [..]}`` (sent on open and on every change).
Server -> client: ``hello``, ``batch`` (every ~100 ms, <= 500 rows; ``dropped`` counts rows skipped for this connection by
backpressure), ``error``. The query field DSL is evaluated by DuckDB over the batch (same compiler as ``/events``; bare text matches the
row's raw preview instead of the full event document)."""
from __future__ import annotations

import asyncio
import hmac
import time
from typing import Any

import duckdb
import orjson
import pyarrow as pa
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .query_dsl import QueryError, compile_query
from .state import AppState

BATCH_MAX = 500
TICK_S = 0.1
STATUSES = {"parsed", "partial", "unparsed"}


def _filter_rows(rows: list[dict[str, Any]], q: str) -> list[dict[str, Any]]:
    """Run the field DSL over ``rows`` (tail projections)."""
    where, params = compile_query(q, text_col="coalesce(message, '')")
    cols = {k: [r.get(k) for r in rows] for k in rows[0]}
    tbl = pa.table(cols)
    # time columns arrive as epoch ms ints; the DSL compares timestamps, so expose them as such
    con = duckdb.connect(":memory:")
    try:
        con.register("t0", tbl)
        sel = ", ".join(f'"{c}"' for c in rows[0] if c not in ("time", "recv_time"))
        keep = con.execute(f"SELECT idx FROM (SELECT row_number() OVER () - 1 AS idx, {sel}, to_timestamp(time / 1000.0) AS time, "
                           f"to_timestamp(recv_time / 1000.0) AS recv_time FROM t0) WHERE {where}", params).fetchall()
    finally:
        con.close()
    ok = {int(i[0]) for i in keep}
    return [r for i, r in enumerate(rows) if i in ok]


def make_router(st: AppState) -> APIRouter:
    r = APIRouter()

    def authorized(ws: WebSocket) -> bool:
        tok = st.cfg.api.token
        if not tok:
            return True
        got = ws.query_params.get("access_token") or ws.headers.get("authorization", "").removeprefix("Bearer ").strip()
        return hmac.compare_digest(got, tok)

    @r.websocket("/stream")
    async def stream(ws: WebSocket) -> None:
        if not authorized(ws):
            await ws.close(code=4401)
            return
        await ws.accept()
        tail = st.tail
        if tail is None:
            await ws.send_text(orjson.dumps({"type": "error", "message": "this API process has no live tail (no bus)"}).decode())
            await ws.close()
            return
        flt: dict[str, Any] = {"q": "", "sources": [], "statuses": []}
        await ws.send_text(orjson.dumps({"type": "hello", "server_time": int(time.time() * 1000), "buffer": 20000}).decode())
        last = await asyncio.to_thread(tail.head)

        async def reader() -> None:
            while True:
                msg = await ws.receive_text()
                try:
                    d = orjson.loads(msg)
                except orjson.JSONDecodeError:
                    await ws.send_text(orjson.dumps({"type": "error", "message": "not JSON"}).decode())
                    continue
                if isinstance(d, dict) and d.get("op") == "filter":
                    q = str(d.get("q") or "")
                    try:
                        compile_query(q)
                    except QueryError as e:
                        await ws.send_text(orjson.dumps({"type": "error", "message": f"bad query: {e}"}).decode())
                        continue
                    flt["q"] = q
                    flt["sources"] = [str(x) for x in (d.get("sources") or [])][:100]
                    flt["statuses"] = [x for x in (d.get("statuses") or []) if x in STATUSES]

        rtask = asyncio.create_task(reader())
        try:
            while not rtask.done():
                last, rows = await asyncio.to_thread(tail.read_after, last, 5000)
                dropped = 0
                if len(rows) > BATCH_MAX * 4:
                    dropped = len(rows) - BATCH_MAX * 4
                    rows = rows[-BATCH_MAX * 4:]
                if rows:
                    if flt["sources"]:
                        rows = [x for x in rows if x.get("source_id") in flt["sources"]]
                    if flt["statuses"]:
                        rows = [x for x in rows if x.get("status") in flt["statuses"]]
                    if flt["q"] and rows:
                        try:
                            rows = await asyncio.to_thread(_filter_rows, rows, flt["q"])
                        except Exception:  # noqa: BLE001
                            rows = []
                    if len(rows) > BATCH_MAX:
                        dropped += len(rows) - BATCH_MAX
                        rows = rows[-BATCH_MAX:]
                    if rows or dropped:
                        payload: dict[str, Any] = {"type": "batch", "events": rows}
                        if dropped:
                            payload["dropped"] = dropped
                        await ws.send_text(orjson.dumps(payload).decode())
                await asyncio.sleep(TICK_S)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            rtask.cancel()

    return r
