"""``/events*`` (api-contract.md "Events"), live ``/export/*`` and the field catalogue."""
from __future__ import annotations

import base64
import csv
import io
from collections.abc import Iterator
from typing import Any

import orjson
from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from ..explain.tracer import NoPack, explain_event
from ..model.lineage import parse_raw_ref
from ..normalize.lake_schema import FIELD_TYPES
from ..vault import IntegrityError, NotFoundError
from .lake import ROW_NAMES, BadCursor, Lake
from .query_dsl import QueryError, field_catalog
from .state import AppState, err

STRING_VALUE_FIELDS = {"source_id", "device_host", "user_name", "signature", "dns_query", "proto_name", "http_method", "url"}


def make_router(st: AppState) -> APIRouter:
    r = APIRouter()
    lake: Lake = st.lake

    def filters(q: str | None, t_from: int | None, t_to: int | None, class_uid: int | None, source: str | None, status: str | None
                ) -> tuple[str, list[Any]]:
        if status is not None and status not in ("parsed", "partial", "unparsed"):
            raise err(400, "BAD_QUERY", "status must be parsed, partial or unparsed")
        try:
            return lake.where(q, t_from, t_to, class_uid, source, status)
        except QueryError as e:
            raise err(400, "BAD_QUERY", str(e)) from e

    @r.get("/events")
    def list_events(q: str | None = None, from_: int | None = Query(None, alias="from"), to: int | None = None,
                    class_: int | None = Query(None, alias="class"), source: str | None = None, status: str | None = None,
                    limit: int = Query(100, ge=1, le=500), cursor: str | None = None) -> dict[str, Any]:
        import time

        t0 = time.perf_counter()
        w, p = filters(q, from_, to, class_, source, status)
        try:
            items, nxt = lake.list_events(w, p, limit, cursor, from_, to, class_)
        except BadCursor as e:
            raise err(400, "BAD_QUERY", str(e)) from e
        return {"items": items, "next_cursor": nxt, "took_ms": round((time.perf_counter() - t0) * 1000, 1), "total_estimate": None}

    @r.get("/events/fields")
    def fields() -> dict[str, Any]:
        return {"fields": [{**f, "suggest": f["name"] in STRING_VALUE_FIELDS} for f in field_catalog()]}

    @r.get("/events/values")
    def values(field: str, prefix: str = "", limit: int = Query(20, ge=1, le=100)) -> dict[str, Any]:
        if field not in STRING_VALUE_FIELDS or field not in FIELD_TYPES:
            raise err(400, "BAD_QUERY", f"autocomplete is available for: {', '.join(sorted(STRING_VALUE_FIELDS))}")
        return {"values": lake.values(field, prefix, limit)}

    @r.get("/events/histogram")
    def histogram(q: str | None = None, from_: int | None = Query(None, alias="from"), to: int | None = None,
                  class_: int | None = Query(None, alias="class"), source: str | None = None, status: str | None = None,
                  buckets: int = Query(60, ge=10, le=200)) -> dict[str, Any]:
        w, p = filters(q, from_, to, class_, source, status)
        return lake.histogram(w, p, from_, to, class_, buckets)

    @r.get("/events/{event_id}")
    def get_event(event_id: str) -> Response:
        ev = lake.get_event(event_id)
        if ev is None:
            raise err(404, "NOT_FOUND", f"no event {event_id}")
        return Response(orjson.dumps(ev), media_type="application/json")

    @r.get("/events/{event_id}/raw")
    def get_raw(event_id: str) -> dict[str, Any]:
        row = lake.find_row(event_id, "raw_ref, raw_sha256")
        if row is None:
            raise err(404, "NOT_FOUND", f"no event {event_id}")
        ref, expected = row
        if not ref:
            raise err(404, "NO_RAW", "this event is synthetic (analytics finding) and has no raw bytes; see its evidences")
        try:
            seg, block, idx = parse_raw_ref(ref)
        except ValueError as e:
            raise err(500, "BAD_REF", f"malformed raw_ref {ref!r}") from e
        base = {"event_id": event_id, "raw_ref": ref, "segment": seg, "block": block, "idx": idx}
        try:
            rd = st.vault.read_frame(seg, block, idx, expected or "", fresh=True)
        except NotFoundError as e:
            raise err(404, "RAW_NOT_FOUND", str(e)) from e
        except IntegrityError as e:
            return {**base, "size": 0, "data_b64": "", "sha256_expected": expected or "", "sha256_actual": "", "verified": False,
                    "error": {"code": "IntegrityError", "message": e.message}}
        out = {**base, "size": rd.size, "data_b64": base64.b64encode(rd.data).decode(), "sha256_expected": expected or rd.sha256_stored,
               "sha256_actual": rd.sha256_actual, "verified": rd.verified, "error": None}
        if not rd.verified:
            out["error"] = {"code": "IntegrityError", "message": f"SHA-256 mismatch for {ref}: expected {expected or rd.sha256_stored}, "
                                                                  f"recomputed {rd.sha256_actual}"}
        return out

    @r.get("/events/{event_id}/explain")
    def explain(event_id: str) -> dict[str, Any]:
        ev = lake.get_event(event_id)
        if ev is None:
            raise err(404, "NOT_FOUND", f"no event {event_id}")
        u = ev.get("ulpf", {})
        if u.get("status") == "unparsed" or not u.get("raw_ref"):
            raise err(404, "NO_PACK", "unparsed or synthetic event: no pack to explain it")
        try:
            seg, block, idx = parse_raw_ref(u["raw_ref"])
            rd = st.vault.read_frame(seg, block, idx, u.get("raw_sha256", ""), fresh=True)
        except NotFoundError as e:
            raise err(404, "RAW_NOT_FOUND", str(e)) from e
        except IntegrityError as e:
            raise err(409, "IntegrityError", e.message) from e
        if not rd.verified:
            raise err(409, "IntegrityError", f"raw bytes of {u['raw_ref']} fail SHA-256 verification; refusing to explain tampered data")
        try:
            return explain_event(st.registry, rd.data, ev)
        except NoPack as e:
            raise err(404, "NO_PACK", str(e)) from e

    # -------------------------------------------------------------------------------------------- export
    @r.get("/export/{fmt}")
    def export(fmt: str, request: Request, q: str | None = None, from_: int | None = Query(None, alias="from"), to: int | None = None,
               class_: int | None = Query(None, alias="class"), source: str | None = None, status: str | None = None) -> Response:
        if fmt not in ("csv", "json", "arrow"):
            raise err(404, "NOT_FOUND", "export formats: csv, json, arrow")
        w, p = filters(q, from_, to, class_, source, status)
        if fmt == "arrow":
            import pyarrow as pa

            from .lake import ROW_COLS

            files = lake.files(class_, from_, to)
            tbl = lake.arrow(files, f"SELECT {ROW_COLS} FROM {{lake}} WHERE {w} ORDER BY time DESC, event_id DESC LIMIT 1000000", p) if files \
                else pa.table({n: [] for n in ROW_NAMES})
            sink = io.BytesIO()
            with pa.ipc.new_stream(sink, tbl.schema) as wr:
                wr.write_table(tbl)
            return Response(sink.getvalue(), media_type="application/vnd.apache.arrow.stream",
                            headers={"Content-Disposition": 'attachment; filename="ulpf-events.arrow"'})

        def gen() -> Iterator[bytes]:
            if fmt == "csv":
                buf = io.StringIO()
                wr = csv.writer(buf)
                wr.writerow(ROW_NAMES)
                yield buf.getvalue().encode()
                for chunk in lake.export_rows(w, p, from_, to, class_):
                    buf = io.StringIO()
                    wr = csv.writer(buf)
                    for row in chunk:
                        wr.writerow(["" if row[n] is None else row[n] for n in ROW_NAMES])
                    yield buf.getvalue().encode()
            else:
                yield b"["
                first = True
                for chunk in lake.export_rows(w, p, from_, to, class_):
                    for row in chunk:
                        yield (b"" if first else b",") + orjson.dumps(row)
                        first = False
                yield b"]"

        media = "text/csv" if fmt == "csv" else "application/json"
        return StreamingResponse(gen(), media_type=media, headers={"Content-Disposition": f'attachment; filename="ulpf-events.{fmt}"'})

    return r


__all__ = ["make_router", "JSONResponse"]
