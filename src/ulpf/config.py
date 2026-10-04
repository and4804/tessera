"""Configuration (§16.1). Validated once at the edge with pydantic; the hot path only sees plain attributes."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OcsfCfg(_M):
    version: str = "1.3.0"


class BusCfg(_M):
    kind: Literal["redis", "memory"] = "redis"
    url: str = "redis://localhost:6379/0"
    partitions: int = Field(16, ge=1, le=1024)
    maxlen: int = 2_000_000


class Listener(_M):
    enabled: bool = True
    listen: str = "0.0.0.0:5140"
    framing: Literal["auto", "octet", "newline"] = "auto"
    cert: str | None = None
    key: str | None = None


class HttpIngest(_M):
    enabled: bool = True
    path: str = "/ingest/raw"
    token: str | None = None


class FileWatch(_M):
    path: str
    hint: str | None = None


class IngestCfg(_M):
    syslog_udp: Listener = Listener()
    syslog_tcp: Listener = Listener()
    syslog_tls: Listener = Listener(enabled=False, listen="0.0.0.0:6514")
    http: HttpIngest = HttpIngest()
    file_watch: list[FileWatch] = []
    max_event_bytes: int = 65536
    batch_max: int = 500
    batch_ms: int = 5


class VaultCfg(_M):
    dir: str = "/data/vault"
    block_events: int = 1000
    block_max_ms: int = 500
    segment_max_mb: int = 256
    fsync: Literal["block", "none"] = "block"
    signing_key: str | None = "/run/secrets/ulpf_ed25519"
    retention_days: int | None = None


class PipelineCfg(_M):
    workers: int | Literal["auto"] = "auto"
    source_cache: bool = True
    default_tz: str = "UTC"
    sample_validate: int = 1000
    drop_unparsed: bool = False  # R3: dropping is explicit, counted, and off by default
    read_batch: int = 500


class PacksCfg(_M):
    dirs: list[str] = ["/app/packs", "/data/packs/custom"]
    hot_reload: bool = True


class SinkOnOff(_M):
    enabled: bool = False


class ParquetCfg(_M):
    enabled: bool = True
    dir: str = "/data/lake"
    flush_rows: int = 50000
    flush_secs: float = 5.0
    compact_secs: float = 300.0


class JsonlCfg(_M):
    enabled: bool = False
    dir: str = "/data/out"
    rotate_mb: int = 64


class OpenSearchCfg(_M):
    enabled: bool = False
    url: str = "http://opensearch:9200"
    index: str = "ulpf-ocsf-%Y.%m.%d"
    bulk_size: int = 1000


class HecCfg(_M):
    enabled: bool = False
    url: str = "http://splunk:8088/services/collector/event"
    token: str = ""
    batch: int = 500


class SyslogOutCfg(_M):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 5514


class SinksCfg(_M):
    parquet: ParquetCfg = ParquetCfg()
    jsonl: JsonlCfg = JsonlCfg()
    opensearch: OpenSearchCfg = OpenSearchCfg()
    splunk_hec: HecCfg = HecCfg()
    syslog_out: SyslogOutCfg = SyslogOutCfg()


class AnalyticsCfg(_M):
    enabled: bool = True
    window_s: int = 60


class LlmCfg(_M):
    enabled: bool = False
    endpoint: str = "http://ollama:11434"
    model: str = ""


class OnboardCfg(_M):
    llm: LlmCfg = LlmCfg()


class ApiCfg(_M):
    listen: str = "0.0.0.0:8080"
    token: str | None = None
    cors_origins: list[str] = []
    max_body_bytes: int = 8 * 1024 * 1024
    ui_dir: str | None = None


class Config(_M):
    node_id: str = "n1"
    data_dir: str = "/data"
    ocsf: OcsfCfg = OcsfCfg()
    bus: BusCfg = BusCfg()
    ingest: IngestCfg = IngestCfg()
    vault: VaultCfg = VaultCfg()
    pipeline: PipelineCfg = PipelineCfg()
    packs: PacksCfg = PacksCfg()
    sinks: SinksCfg = SinksCfg()
    analytics: AnalyticsCfg = AnalyticsCfg()
    onboard: OnboardCfg = OnboardCfg()
    api: ApiCfg = ApiCfg()

    @property
    def n_workers(self) -> int:
        w = self.pipeline.workers
        return max(1, (os.cpu_count() or 2) - 1) if w == "auto" else int(w)

    @property
    def lake_dir(self) -> Path:
        return Path(self.sinks.parquet.dir)

    def rebase(self, data_dir: str | Path) -> Config:
        """Return a copy with every ``/data/...`` path moved under ``data_dir`` (dev, replay and tests)."""
        d = str(data_dir)

        def mv(p: str | None) -> str | None:
            if p and p.startswith("/data"):
                return d.rstrip("/") + p[len("/data"):]
            return p

        c = self.model_copy(deep=True)
        c.data_dir = d
        c.vault.dir = mv(c.vault.dir) or c.vault.dir
        c.sinks.parquet.dir = mv(c.sinks.parquet.dir) or c.sinks.parquet.dir
        c.sinks.jsonl.dir = mv(c.sinks.jsonl.dir) or c.sinks.jsonl.dir
        c.packs.dirs = [mv(x) or x for x in c.packs.dirs]
        c.ingest.file_watch = [FileWatch(path=mv(f.path) or f.path, hint=f.hint) for f in c.ingest.file_watch]
        return c


def _deep_merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a)
    for k, v in b.items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _env_overrides() -> dict[str, Any]:
    """``ULPF_API_TOKEN``, ``ULPF_BUS_URL``, ``ULPF_NODE_ID`` ... map onto known keys (secrets arrive via env, §7.13)."""
    out: dict[str, Any] = {}
    m = {
        "ULPF_NODE_ID": ("node_id",), "ULPF_BUS_URL": ("bus", "url"), "ULPF_BUS_KIND": ("bus", "kind"),
        "ULPF_API_TOKEN": ("api", "token"), "ULPF_VAULT_DIR": ("vault", "dir"), "ULPF_LAKE_DIR": ("sinks", "parquet", "dir"),
        "ULPF_SIGNING_KEY": ("vault", "signing_key"), "ULPF_DATA_DIR": ("data_dir",),
    }
    for env, path in m.items():
        v = os.environ.get(env)
        if v is None:
            continue
        d = out
        for p in path[:-1]:
            d = d.setdefault(p, {})
        d[path[-1]] = v
    return out


def load_config(path: str | Path | None = None, overrides: dict[str, Any] | None = None) -> Config:
    """Load YAML (``path`` or ``$ULPF_CONFIG`` or ``./configs/ulpf.yaml`` when present), apply env then explicit overrides."""
    p = path or os.environ.get("ULPF_CONFIG")
    if p is None and Path("configs/ulpf.yaml").exists():
        p = "configs/ulpf.yaml"
    raw: dict[str, Any] = {}
    if p:
        with open(p, encoding="utf-8") as f:
            raw = yaml.load(f, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)) or {}
    raw = _deep_merge(raw, _env_overrides())
    if overrides:
        raw = _deep_merge(raw, overrides)
    # §16.1 spells the listeners as {listen: "host:port"}; "enabled" defaults true.
    return Config.model_validate(raw)


def split_hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host or "0.0.0.0", int(port)
