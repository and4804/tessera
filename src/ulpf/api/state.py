"""Shared handles for the API process (one object, built once by :func:`ulpf.api.app.create_app`)."""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from ..bus.base import Bus
from ..config import Config
from ..ingest.publisher import Publisher
from ..packs import PackRegistry
from ..pipeline.unparsed import ClusterStore
from ..vault import VaultReader
from .lake import Lake
from .stats import SourceStats


def err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status, detail={"error": {"code": code, "message": message}})


@dataclass
class AppState:
    cfg: Config
    registry: PackRegistry
    lake: Lake
    vault: VaultReader
    stats: SourceStats
    bus: Bus | None = None
    tail: Any = None
    clusters: ClusterStore | None = None
    publisher: Publisher | None = None
    snapshots: Callable[[], Iterable[dict[str, Any]]] | None = None
    started: float = field(default_factory=time.time)
    verify_cache: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def pubkey(self) -> bytes | None:
        k = self.cfg.vault.signing_key
        if k and Path(k + ".pub").exists():
            try:
                return bytes.fromhex(Path(k + ".pub").read_text().strip())
            except ValueError:
                return None
        return None
