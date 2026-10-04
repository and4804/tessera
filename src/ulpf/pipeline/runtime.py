"""Process entry points and the supervisor behind ``ulpf run`` (§16.2, docker/compose.yml).

``run --role api|ingest|worker`` is one container each; ``--role all`` is the single-node convenience: with a Redis bus it spawns one API
process, one ingest process and N worker processes (N = ``--workers`` or ``pipeline.workers``); with the in-memory bus (no Redis, nothing
to share between processes) it runs everything in this process (worker on a thread, ingest and API on the asyncio loop)."""
from __future__ import annotations

import asyncio
import logging
import multiprocessing as mp
import os
import signal
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from ..config import Config

log = logging.getLogger("ulpf.runtime")


# ----------------------------------------------------------------------------------------------- signing key
def ensure_signing_key(cfg: Config) -> str | None:
    """Make sure ``cfg.vault.signing_key`` names a readable key; generate one under ``<data_dir>/keys`` when the configured secret is
    missing (dev, ``--no-redis`` demo). Safe when several containers start at once: the key is generated to a temp name and published
    with ``link(2)``, which fails for every racer but one, and the losers read the winner's key. Returns the path in use."""
    from ..vault import generate_keypair

    k = cfg.vault.signing_key
    if not k:
        return None
    if Path(k).is_file():
        return k
    final = Path(cfg.data_dir) / "keys" / "ulpf_ed25519"
    final.parent.mkdir(parents=True, exist_ok=True)
    if not final.is_file():
        tmp = final.parent / f".gen-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        _, tmp_pub = generate_keypair(tmp)
        try:
            os.link(tmp, final)
            os.replace(tmp_pub, str(final) + ".pub")       # only the winner publishes the public key
        except FileExistsError:
            pass
        finally:
            for p in (tmp, tmp_pub):
                try:
                    os.unlink(p)
                except OSError:
                    pass
    for _ in range(50):                                    # a loser may look before the winner's pub file lands
        if final.is_file():
            break
        time.sleep(0.1)
    pub = Path(str(final) + ".pub")
    if not pub.exists():
        from ..vault import load_signing_key

        sk = load_signing_key(final)
        if sk is not None:
            pub.write_text(bytes(sk.verify_key).hex() + "\n")
    cfg.vault.signing_key = str(final)
    return str(final)


# ----------------------------------------------------------------------------------------------- shared builders
def _bus(cfg: Config) -> Any:
    from ..bus import make_bus

    return make_bus(cfg.bus.kind, cfg.bus.url, cfg.bus.partitions, cfg.bus.maxlen)


def _install_stop(stop: threading.Event) -> None:
    def h(_s: int, _f: Any) -> None:
        stop.set()

    for s in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(s, h)
        except ValueError:  # not the main thread
            pass


def _pack_reload_listener(client: Any, registry: Any, stop: threading.Event) -> threading.Thread:
    """``packs.reload`` pub/sub (published by the API after Studio publishes a pack) -> immediate registry reload on this worker."""
    from ..onboard.studio import RELOAD_CHANNEL

    def loop() -> None:
        ps = client.pubsub(ignore_subscribe_messages=True)
        try:
            ps.subscribe(RELOAD_CHANNEL)
            while not stop.is_set():
                msg = ps.get_message(timeout=0.5)
                if msg:
                    try:
                        registry.poll()
                    except Exception:  # noqa: BLE001
                        log.warning("pack reload failed", exc_info=True)
        except Exception:  # noqa: BLE001 - Redis hiccup: the 1 s file poll in the worker still picks changes up
            log.warning("pack reload listener stopped", exc_info=True)
        finally:
            try:
                ps.close()
            except Exception:  # noqa: BLE001
                pass

    t = threading.Thread(target=loop, name="pack-reload", daemon=True)
    t.start()
    return t


# ----------------------------------------------------------------------------------------------- worker
def make_worker(cfg: Config, bus: Any, *, static: tuple[int, int] | None = None) -> Any:
    from ..packs import PackRegistry
    from .leases import LeaseManager
    from .unparsed import MemoryClusterStore, RedisClusterStore
    from .worker import Worker, make_tail

    reg = PackRegistry(cfg.packs.dirs, cfg.pipeline.default_tz)
    client = getattr(bus, "r", None)
    store = RedisClusterStore(client) if client is not None else MemoryClusterStore()
    name = f"w{uuid.uuid4().hex[:6]}"
    if static is not None or client is None:
        i, n = static or (0, 1)
        return Worker(cfg, bus, reg, i, n, tail=make_tail(bus), cluster_store=store, metrics_client=client, shard=n > 1, name=f"w{i}")
    return Worker(cfg, bus, reg, 0, 1, tail=make_tail(bus), cluster_store=store, metrics_client=client, name=name,
                  leases=LeaseManager(client, bus.partitions, name))


def run_worker(cfg: Config, stop: threading.Event | None = None, static: tuple[int, int] | None = None, ready: Any = None) -> None:
    stop = stop or threading.Event()
    ensure_signing_key(cfg)
    bus = _bus(cfg)
    w = make_worker(cfg, bus, static=static)
    client = getattr(bus, "r", None)
    if client is not None and cfg.packs.hot_reload:
        _pack_reload_listener(client, w.registry, stop)
    log.info("worker %s up: partitions=%s", w.name, "leased" if w.leases else w.partitions)
    if ready is not None:
        ready.set()
    w.run_forever(stop)


# ----------------------------------------------------------------------------------------------- ingest
async def ingest_main(cfg: Config, bus: Any, stop: threading.Event, pub: Any = None) -> Any:
    """Syslog UDP/TCP/TLS listeners + file watchers feeding one Publisher; flushes on the 5 ms tick. Returns when ``stop`` is set."""
    from ..ingest import FileTailer, Publisher, SyslogServers

    pub = pub or Publisher(bus, cfg.node_id, max_event_bytes=cfg.ingest.max_event_bytes, batch_max=cfg.ingest.batch_max,
                           batch_ms=cfg.ingest.batch_ms)
    srv = SyslogServers(pub)
    ic = cfg.ingest
    if ic.syslog_udp.enabled:
        await srv.start_udp(ic.syslog_udp.listen)
    if ic.syslog_tcp.enabled:
        await srv.start_tcp(ic.syslog_tcp.listen, ic.syslog_tcp.framing)
    if ic.syslog_tls.enabled and ic.syslog_tls.cert and ic.syslog_tls.key:
        await srv.start_tls(ic.syslog_tls.listen, ic.syslog_tls.cert, ic.syslog_tls.key, ic.syslog_tls.framing)
    tailer = FileTailer(pub, [(f.path, f.hint) for f in ic.file_watch]) if ic.file_watch else None
    log.info("ingest up: %s", srv.ports)
    last_poll = 0.0
    try:
        while not stop.is_set():
            await asyncio.sleep(0.005)
            try:
                if pub.flush_due():
                    pub.flush()
                if tailer is not None and time.monotonic() - last_poll >= 0.5:
                    last_poll = time.monotonic()
                    await asyncio.get_running_loop().run_in_executor(None, tailer.poll)
            except Exception:  # noqa: BLE001 - Redis down: the Publisher keeps its buffer and retries on the next tick
                log.warning("ingest flush failed", exc_info=True)
                await asyncio.sleep(0.5)
    finally:
        await srv.close()
    return srv


def run_ingest(cfg: Config, stop: threading.Event | None = None) -> None:
    stop = stop or threading.Event()
    _install_stop(stop)
    asyncio.run(ingest_main(cfg, _bus(cfg), stop))


# ----------------------------------------------------------------------------------------------- api
def build_api(cfg: Config, bus: Any) -> Any:
    from ..api.app import create_app
    from ..packs import PackRegistry
    from .unparsed import MemoryClusterStore, RedisClusterStore
    from .worker import make_tail

    client = getattr(bus, "r", None)
    reg = PackRegistry(cfg.packs.dirs, cfg.pipeline.default_tz)
    return create_app(cfg, bus=bus, registry=reg, tail=make_tail(bus),
                      clusters=RedisClusterStore(client) if client is not None else MemoryClusterStore())


def _background(cfg: Config) -> list[Any]:
    """Compactor + analytics loop (API process)."""
    from ..sinks import Compactor
    from .analysis import AnalyticsRunner

    out: list[Any] = []
    if cfg.sinks.parquet.enabled:
        c = Compactor(cfg.lake_dir)
        c.start(cfg.sinks.parquet.compact_secs)
        out.append(c)
    if cfg.analytics.enabled:
        a = AnalyticsRunner(cfg.lake_dir, cfg.node_id, cfg.analytics.window_s, Path(cfg.data_dir) / "analytics_state.json")
        a.start(30.0)
        out.append(a)
    return out


def run_api(cfg: Config, stop: threading.Event | None = None) -> None:
    import uvicorn

    from ..config import split_hostport

    ensure_signing_key(cfg)
    bus = _bus(cfg)
    app = build_api(cfg, bus)
    bg = _background(cfg)
    host, port = split_hostport(cfg.api.listen)
    try:
        uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
    finally:
        for b in bg:
            b.stop()


# ----------------------------------------------------------------------------------------------- supervisor
def _spawn_target(role: str, cfg_json: str, idx: int, n: int, ready: Any = None, static: bool = False) -> None:
    cfg = Config.model_validate_json(cfg_json)
    stop = threading.Event()
    _install_stop(stop)
    if role == "worker":
        run_worker(cfg, stop, (idx, n) if static else None, ready)
    elif role == "ingest":
        run_ingest(cfg, stop)
    elif role == "api":
        run_api(cfg, stop)


def _all_inproc(cfg: Config) -> None:
    """Memory bus: one process. Worker thread + syslog/file ingest + API on one asyncio loop."""
    import uvicorn

    from ..config import split_hostport
    from ..ingest import Publisher

    ensure_signing_key(cfg)
    bus = _bus(cfg)
    stop = threading.Event()
    w = make_worker(cfg, bus)
    t = threading.Thread(target=w.run_forever, args=(stop,), name="worker", daemon=True)
    t.start()
    pub = Publisher(bus, cfg.node_id, max_event_bytes=cfg.ingest.max_event_bytes, batch_max=cfg.ingest.batch_max, batch_ms=cfg.ingest.batch_ms)
    from ..api.app import create_app

    app = create_app(cfg, bus=bus, registry=w.registry, tail=w.tail, clusters=w.lane.store if hasattr(w.lane, "store") else None, publisher=pub)
    bg = _background(cfg)
    host, port = split_hostport(cfg.api.listen)
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False))

    async def main() -> None:
        ing = asyncio.create_task(ingest_main(cfg, bus, stop, pub))
        try:
            await server.serve()
        finally:
            stop.set()
            await ing

    try:
        asyncio.run(main())
    finally:
        stop.set()
        t.join(timeout=10)
        for b in bg:
            b.stop()


def ui_url(cfg: Config) -> str:
    from ..config import split_hostport

    host, port = split_hostport(cfg.api.listen)
    return f"http://{'127.0.0.1' if host in ('0.0.0.0', '::', '') else host}:{port}/"


def _announce(cfg: Config, role: str, n: int) -> None:
    """One human-readable start-up banner (stdout): the URL to open and what is listening."""
    if role not in ("all", "api"):
        return
    ic = cfg.ingest
    ing = [f"syslog udp {ic.syslog_udp.listen}" if ic.syslog_udp.enabled else "", f"tcp {ic.syslog_tcp.listen}" if ic.syslog_tcp.enabled else "",
           f"http POST {ic.http.path}" if ic.http.enabled else ""]
    print(f"ULPF node {cfg.node_id}: UI and API at {ui_url(cfg)}", flush=True)
    if role == "all":
        print(f"  bus={cfg.bus.kind} workers={n if cfg.bus.kind != 'memory' else 1} ingest: {', '.join(x for x in ing if x)}", flush=True)
    if not _ui_present(cfg):
        print("  warning: UI bundle not found (build it with `make ui`, or set api.ui_dir); the API still works", flush=True)


def _ui_present(cfg: Config) -> bool:
    from ..api.app import find_ui_dir

    return find_ui_dir(cfg) is not None


def run_node(cfg: Config, role: str = "all", workers: int | None = None) -> None:
    """``ulpf run``: blocks until SIGINT/SIGTERM."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    n = workers if workers else cfg.n_workers
    _announce(cfg, role, n)
    if role == "api":
        run_api(cfg)
    elif role == "ingest":
        run_ingest(cfg)
    elif role == "worker":
        run_worker(cfg)
    elif role == "all":
        if cfg.bus.kind == "memory":
            _all_inproc(cfg)
            return
        ensure_signing_key(cfg)               # generated once here so the children do not race
        ctx = mp.get_context("spawn")
        cj = cfg.model_dump_json()
        procs = [ctx.Process(target=_spawn_target, args=("api", cj, 0, 1), name="ulpf-api"),
                 ctx.Process(target=_spawn_target, args=("ingest", cj, 0, 1), name="ulpf-ingest")]
        procs += [ctx.Process(target=_spawn_target, args=("worker", cj, i, n), name=f"ulpf-worker-{i}") for i in range(n)]
        stop = threading.Event()
        _install_stop(stop)
        for p in procs:
            p.start()
        try:
            while not stop.is_set() and all(p.is_alive() for p in procs):
                time.sleep(0.5)
        finally:
            for p in procs:
                if p.is_alive():
                    p.terminate()           # SIGTERM: workers flush sinks and release leases in close()
            for p in procs:
                p.join(timeout=20)
                if p.is_alive():
                    p.kill()
    else:
        raise ValueError(f"unknown role {role!r}: api|ingest|worker|all")


# ----------------------------------------------------------------------------------------------- worker pool (replay, bench)
class WorkerPool:
    """N worker processes with static partition assignment (``p % N == i``) for ``replay --workers`` and ``bench``: deterministic, and
    no lease warm-up in a measurement. Each process opens its own vault shard and Parquet writer."""

    def __init__(self, cfg: Config, n: int) -> None:
        self.cfg, self.n = cfg, n
        self.ctx = mp.get_context("spawn")
        self.procs: list[Any] = []
        self.ready: list[Any] = []

    def start(self, timeout: float = 60.0) -> None:
        cj = self.cfg.model_dump_json()
        for i in range(self.n):
            ev = self.ctx.Event()
            p = self.ctx.Process(target=_spawn_target, args=("worker", cj, i, self.n, ev, True), name=f"ulpf-worker-{i}")
            p.start()
            self.procs.append(p)
            self.ready.append(ev)
        t0 = time.monotonic()
        for ev, p in zip(self.ready, self.procs):
            while not ev.wait(0.2):
                if not p.is_alive() or time.monotonic() - t0 > timeout:
                    self.stop()
                    raise RuntimeError("worker process failed to start")

    @property
    def pids(self) -> list[int]:
        return [int(p.pid) for p in self.procs if p.pid]

    def stop(self) -> None:
        for p in self.procs:
            if p.is_alive():
                p.terminate()
        for p in self.procs:
            p.join(timeout=30)
            if p.is_alive():
                p.kill()
        self.procs, self.ready = [], []


def wait_drained(bus: Any, timeout: float = 900.0, poll: float = 0.05) -> bool:
    """True once every ingested message is sunk or counted as dropped (ledger in_flight == 0)."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        snap = bus.ledger.snapshot()
        ing = sum(r.get("ingested", 0) for r in snap.values())
        done = sum(r.get("sunk", 0) + r.get("dropped", 0) for r in snap.values())
        if ing == done:
            return True
        time.sleep(poll)
    return False
