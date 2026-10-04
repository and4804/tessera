"""FastAPI application (§7.13). Everything is under ``/api/v1`` exactly as ``docs/api-contract.md`` lists it; ``POST /ingest/raw`` (HTTP
ingest) and the built UI are served beside it. Auth: optional static bearer (``Authorization`` header, or ``?access_token=`` for WebSocket and
downloads). Errors are ``{"error": {"code", "message"}}``. CORS is closed unless ``api.cors_origins`` lists origins."""
from __future__ import annotations

import hmac
import importlib.metadata
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Receive, Scope, Send

from ..bus.base import Bus
from ..config import Config
from ..ingest import Publisher
from ..ingest.http import make_ingest_router
from ..model.ocsf import OCSF_VERSION
from ..obs.metrics import read_snapshots, render
from ..packs import PackRegistry
from ..pipeline.unparsed import ClusterStore
from ..vault import VaultReader
from . import routes_analytics, routes_events, routes_integrity, routes_onboard, routes_sources, ws
from .lake import Lake
from .state import AppState, err
from .stats import SourceStats

PREFIX = "/api/v1"
PUBLIC = {f"{PREFIX}/health"}


def _version() -> str:
    try:
        return importlib.metadata.version("ulpf")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0"


class BodyLimit:
    """Pure-ASGI request size cap (works for chunked bodies too): 413 as soon as the limit is crossed."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app, self.max = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for k, v in scope.get("headers", []):
            if k == b"content-length" and v.isdigit() and int(v) > self.max:
                await self._reject(scope, receive, send)
                return
        seen = 0
        too_big = False

        async def limited() -> Any:
            nonlocal seen, too_big
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max:
                    too_big = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return msg

        started = False

        async def guarded_send(m: Any) -> None:
            nonlocal started
            if too_big and not started:
                started = True
                await self._reject(scope, receive, send)
                return
            if not too_big:
                started = True
                await send(m)

        await self.app(scope, limited, guarded_send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        r = JSONResponse({"error": {"code": "TOO_LARGE", "message": f"request body exceeds {self.max} bytes"}}, status_code=413)
        await r(scope, receive, send)


def find_ui_dir(cfg: Config, ui_dir: str | Path | None = None) -> Path | None:
    """The built UI (``ui/dist``): explicit setting, else ./ui/dist, /app/ui/dist, or the source checkout's ui/dist."""
    explicit = ui_dir or cfg.api.ui_dir
    cands = [Path(explicit)] if explicit else [Path("ui/dist"), Path("/app/ui/dist"), Path(__file__).resolve().parents[3] / "ui" / "dist"]
    return next((p for p in cands if (p / "index.html").is_file()), None)


def create_app(cfg: Config, *, bus: Bus | None = None, registry: PackRegistry | None = None, tail: Any = None,
               clusters: ClusterStore | None = None, publisher: Publisher | None = None,
               snapshots: Callable[[], Any] | None = None, ui_dir: str | Path | None = None) -> FastAPI:
    registry = registry or PackRegistry(cfg.packs.dirs, cfg.pipeline.default_tz)
    lake = Lake(cfg.lake_dir)
    st = AppState(cfg=cfg, registry=registry, lake=lake, vault=VaultReader(cfg.vault.dir), stats=SourceStats(lake, registry), bus=bus,
                  tail=tail, clusters=clusters, publisher=publisher, snapshots=snapshots)
    if st.snapshots is None and bus is not None and getattr(bus, "r", None) is not None:
        client = bus.r  # type: ignore[attr-defined]
        st.snapshots = lambda: read_snapshots(client)
    if publisher is None and bus is not None:
        st.publisher = Publisher(bus, cfg.node_id, max_event_bytes=cfg.ingest.max_event_bytes, batch_max=cfg.ingest.batch_max)

    app = FastAPI(title="ULPF", version=_version(), docs_url=None, redoc_url=None, openapi_url=None)
    app.state.ulpf = st

    @app.exception_handler(StarletteHTTPException)
    async def http_exc(_: Request, e: StarletteHTTPException) -> JSONResponse:
        d = e.detail
        if isinstance(d, dict) and "error" in d:
            return JSONResponse(d, status_code=e.status_code, headers=getattr(e, "headers", None))
        code = {400: "BAD_REQUEST", 401: "UNAUTHORIZED", 404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 413: "TOO_LARGE"}.get(e.status_code, "ERROR")
        return JSONResponse({"error": {"code": code, "message": str(d)}}, status_code=e.status_code, headers=getattr(e, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def val_exc(_: Request, e: RequestValidationError) -> JSONResponse:
        first = e.errors()[0] if e.errors() else {}
        loc = ".".join(str(x) for x in first.get("loc", []) if x != "query" and x != "body")
        return JSONResponse({"error": {"code": "BAD_REQUEST", "message": f"{loc}: {first.get('msg', 'invalid request')}".strip(": ")}},
                            status_code=400)

    @app.exception_handler(Exception)
    async def any_exc(_: Request, e: Exception) -> JSONResponse:
        return JSONResponse({"error": {"code": "INTERNAL", "message": f"{type(e).__name__}: {e}"[:300]}}, status_code=500)

    token = cfg.api.token

    @app.middleware("http")
    async def auth(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path = request.url.path
        if token and path.startswith(PREFIX) and path not in PUBLIC and request.method != "OPTIONS":
            got = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
            if not got and (path.startswith(f"{PREFIX}/export/") or path.endswith("/stream")):
                got = request.query_params.get("access_token", "")
            if not hmac.compare_digest(got, token):
                return JSONResponse({"error": {"code": "UNAUTHORIZED", "message": "missing or invalid bearer token"}}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
        return await call_next(request)

    app.add_middleware(BodyLimit, max_bytes=cfg.api.max_body_bytes)
    if cfg.api.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=cfg.api.cors_origins, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])

    @app.get(f"{PREFIX}/health")
    def health() -> dict[str, Any]:
        ok = not registry.errors
        if bus is not None:
            try:
                bus.lag(0)
            except Exception:  # noqa: BLE001
                ok = False
        return {"status": "ok" if ok else "degraded", "version": _version(), "node_id": cfg.node_id, "ocsf_version": OCSF_VERSION,
                "time": int(time.time() * 1000)}

    @app.get(f"{PREFIX}/benchmark")
    def benchmark() -> Response:
        for p in (Path(cfg.data_dir) / "bench" / "results.json", Path("bench") / "results.json"):
            if p.is_file():
                try:
                    json.loads(p.read_text())
                except ValueError:
                    continue
                return Response(p.read_bytes(), media_type="application/json")
        raise err(404, "NO_BENCHMARK", "no benchmark has been run: run `ulpf bench`")

    @app.get(f"{PREFIX}/metrics")
    def metrics() -> Response:
        snaps = list(st.snapshots()) if st.snapshots else []

        def gauges() -> list[tuple[str, str, dict[str, str], float]]:
            out: list[tuple[str, str, dict[str, str], float]] = []
            if bus is not None:
                for p in range(bus.partitions):
                    try:
                        out.append(("ulpf_stream_lag", "messages published but not yet acknowledged, per partition", {"partition": str(p)},
                                    float(bus.lag(p))))
                    except Exception:  # noqa: BLE001
                        break
            out.append(("ulpf_packs_loaded", "compiled packs", {}, float(len(registry.snapshot.by_id))))
            out.append(("ulpf_api_uptime_seconds", "API process uptime", {}, time.time() - st.started))
            return out

        return Response(render(lambda: snaps, gauges), media_type="text/plain; version=0.0.4; charset=utf-8")

    for mod in (routes_events, routes_sources, routes_integrity, routes_analytics, routes_onboard):
        app.include_router(mod.make_router(st), prefix=PREFIX)
    app.include_router(ws.make_router(st), prefix=PREFIX)
    if st.publisher is not None and cfg.ingest.http.enabled:
        app.include_router(make_ingest_router(st.publisher, cfg.ingest.http.path, cfg.ingest.http.token or token, cfg.api.max_body_bytes))

    ui = find_ui_dir(cfg, ui_dir)
    if ui is not None:
        root = ui.resolve()

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> Response:
            if path.startswith("api/") or path == "api":
                raise HTTPException(404, detail={"error": {"code": "NOT_FOUND", "message": "no such endpoint"}})
            f = (root / path).resolve()
            if path and f.is_file() and root in f.parents:
                return FileResponse(f)
            return FileResponse(root / "index.html")

    app.state.shutdown = lambda: None
    return app
