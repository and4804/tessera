"""``/sources`` and ``/sources/{id}/health``."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from .state import AppState, err


def make_router(st: AppState) -> APIRouter:
    r = APIRouter()

    @r.get("/sources")
    def sources() -> dict[str, Any]:
        return {"items": st.stats.summaries()}

    @r.get("/sources/{source_id}/health")
    def health(source_id: str) -> dict[str, Any]:
        h = st.stats.health(source_id)
        if h is None:
            raise err(404, "NOT_FOUND", f"unknown source {source_id}")
        return h

    return r
