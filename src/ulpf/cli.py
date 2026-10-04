"""`ulpf` command line (§16.2)."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Annotated, Any

import typer

from .config import Config, load_config

app = typer.Typer(add_completion=False, no_args_is_help=True, help="ULPF - Universal Log Pre-processing Framework")
packs_app = typer.Typer(no_args_is_help=True, help="Pack tooling")
app.add_typer(packs_app, name="packs")

ConfigOpt = Annotated[Path | None, typer.Option("--config", "-c", help="configs/ulpf.yaml (default: $ULPF_CONFIG)")]
DataOpt = Annotated[Path | None, typer.Option("--data-dir", help="move every /data/... path under this directory")]


def _cfg(config: Path | None, data_dir: Path | None, bus: str | None = None) -> Config:
    cfg = load_config(config)
    base = data_dir or (Path("data") if not Path("/data").exists() or not os.access("/data", os.W_OK) else None)
    if base is not None:
        cfg = cfg.rebase(base.resolve())
    if bus:
        cfg.bus.kind = bus  # type: ignore[assignment]
    for d in cfg.packs.dirs:                 # the Studio's publish target must exist or workers would never watch it
        if "custom" in d:
            try:
                Path(d).mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
    cfg.packs.dirs = _pack_dirs(cfg.packs.dirs)
    return cfg


def _pack_dirs(dirs: list[str]) -> list[str]:
    """Configured pack directories that exist; the checkout's ``packs/`` is added when no built-in (non-``custom``) directory exists
    (dev, replay, bench outside a container), so the shipped packs are never lost just because only ``custom/`` was created."""
    here = Path(__file__).resolve().parents[2] / "packs"
    ok = [d for d in dirs if Path(d).exists()]
    if here.exists() and not any("custom" not in d for d in ok):
        ok.insert(0, str(here))
    return ok
def _redis_errors() -> tuple[type[BaseException], ...]:
    import redis

    return (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError)


def _ensure_key(cfg: Config) -> None:
    from .pipeline.runtime import ensure_signing_key

    ensure_signing_key(cfg)


# ----------------------------------------------------------------------------------------------- replay
@app.command()
def replay(
    file: Annotated[Path, typer.Option("--file", "-f", exists=True, dir_okay=False)],
    hint: Annotated[str | None, typer.Option(help="pack id / vendor tag for every line")] = None,
    rate: Annotated[str, typer.Option(help="'max' or events/second")] = "max",
    no_redis: Annotated[bool, typer.Option("--no-redis", help="in-process bus (thin slice)")] = False,
    jsonl: Annotated[bool, typer.Option(help="also write OCSF JSONL")] = True,
    workers: Annotated[int, typer.Option(help="worker processes (redis mode); 0 = in-process worker")] = 0,
    config: ConfigOpt = None,
    data_dir: DataOpt = None,
    limit: Annotated[int | None, typer.Option(help="stop after N lines")] = None,
) -> None:
    """Replay a log file through vault -> packs -> OCSF JSONL + Parquet and print the conservation ledger."""
    from .vault import verify_all

    cfg = _cfg(config, data_dir, "memory" if no_redis else None)
    cfg.sinks.jsonl.enabled = jsonl
    _ensure_key(cfg)
    t0 = time.perf_counter()
    try:
        res = run_replay(cfg, file, hint, None if rate == "max" else float(rate), limit, workers)
    except _redis_errors() as e:
        typer.echo(f"cannot reach Redis at {cfg.bus.url}: {e}\nstart one, set ULPF_BUS_URL, or use --no-redis", err=True)
        raise typer.Exit(3) from None
    dt = time.perf_counter() - t0
    led = res["ledger"]
    t = led["totals"]
    typer.echo(f"replayed {res['lines']} lines in {dt:.2f}s ({res['lines'] / max(dt, 1e-9):,.0f} eps)")
    typer.echo("conservation ledger")
    for k in ("ingested", "vaulted", "normalized_parsed", "normalized_partial", "unparsed", "sunk", "dropped", "in_flight"):
        typer.echo(f"  {k:20s} {t[k]:>10d}")
    typer.echo(f"  conserved            {led['conserved']}  (lost={led['lost']})")
    reps = list(verify_all(cfg.vault.dir))
    ok = all(r.ok for r in reps)
    typer.echo(f"vault verify: {'PASS' if ok else 'FAIL'} ({len(reps)} segments, {sum(r.frames_checked for r in reps)} frames)")
    typer.echo(f"lake: {cfg.sinks.parquet.dir}" + (f"   jsonl: {cfg.sinks.jsonl.dir}" if jsonl else ""))
    raise typer.Exit(0 if ok and led["conserved"] else 1)


def run_replay(cfg: Config, file: Path, hint: str | None, rate: float | None, limit: int | None = None,
               workers: int = 0) -> dict[str, Any]:
    """Publish ``file`` and process it to completion. ``workers == 0`` (or the memory bus): one in-process worker, publish and consume
    interleaved. ``workers >= 1`` with Redis: that many worker processes, static partitions."""
    from .bus import make_bus
    from .ingest import Publisher
    from .ingest.replay import iter_lines
    from .packs import PackRegistry
    from .pipeline import MemoryClusterStore, Worker, backlog, make_tail, report
    from .pipeline.runtime import WorkerPool, wait_drained

    bus = make_bus(cfg.bus.kind, cfg.bus.url, cfg.bus.partitions, cfg.bus.maxlen)
    pub = Publisher(bus, cfg.node_id, max_event_bytes=cfg.ingest.max_event_bytes, batch_max=cfg.ingest.batch_max)
    n = 0
    t0 = time.perf_counter()
    if cfg.bus.kind == "memory" or workers == 0:
        reg = PackRegistry(cfg.packs.dirs, cfg.pipeline.default_tz)
        w = Worker(cfg, bus, reg, 0, 1, tail=make_tail(bus), cluster_store=MemoryClusterStore(), shard=False)
        for ln in iter_lines(file):
            pub.ingest(ln, "replay", "", 0, hint)
            n += 1
            if pub.pending == 0 and n % 5000 == 0:
                w.step(0)         # interleave publish and consume so memory stays bounded for big files
            if rate:
                lag = n / rate - (time.perf_counter() - t0)
                if lag > 0.005:
                    pub.flush()
                    time.sleep(lag)
            if limit and n >= limit:
                break
        pub.flush()
        w.drain()
        w.close()
    else:
        pool = WorkerPool(cfg, workers)
        pool.start()
        try:
            t0 = time.perf_counter()
            for ln in iter_lines(file):
                pub.ingest(ln, "replay", "", 0, hint)
                n += 1
                if rate:
                    lag = n / rate - (time.perf_counter() - t0)
                    if lag > 0.005:
                        pub.flush()
                        time.sleep(lag)
                if limit and n >= limit:
                    break
            pub.flush()
            wait_drained(bus)
        finally:
            pool.stop()
    return {"lines": n, "ledger": report(bus.ledger.snapshot(), backlog(bus), int(time.time() * 1000))}


# ----------------------------------------------------------------------------------------------- verify / keygen / validate
@app.command()
def verify(
    segment: Annotated[str | None, typer.Option("--segment", "-s")] = None,
    all_: Annotated[bool, typer.Option("--all")] = False,
    pubkey: Annotated[Path | None, typer.Option(help="pin the trusted Ed25519 public key (hex file)")] = None,
    config: ConfigOpt = None,
    data_dir: DataOpt = None,
    vault_dir: Annotated[Path | None, typer.Option(help="verify this vault directory directly")] = None,
) -> None:
    """Recompute every frame hash, the hash chain and signatures; exit 1 on the first failure and say where."""
    from .vault import verify_all

    d = str(vault_dir) if vault_dir else _cfg(config, data_dir).vault.dir
    pk = bytes.fromhex(pubkey.read_text().strip()) if pubkey else None
    n = frames = 0
    bad = None
    t0 = time.perf_counter()
    for r in verify_all(d, pk, None if (all_ or not segment) else segment):
        n += 1
        frames += r.frames_checked
        st = "OK " if r.ok else "BAD"
        sig = "" if r.signature_ok is None else (" sig=ok" if r.signature_ok else " sig=BAD")
        typer.echo(f"{st} {r.segment} blocks={r.blocks_checked} frames={r.frames_checked} {'sealed' if r.sealed else 'open'}{sig}")
        for note in r.notes:
            typer.echo(f"    note: {note}")
        if not r.ok:
            typer.echo(f"    -> segment {r.segment} block {r.error_block} frame {r.error_frame}: {r.error}")
            bad = bad or r
    typer.echo(f"{n} segments, {frames} frames in {time.perf_counter() - t0:.2f}s: {'FAILED' if bad else 'PASS'}")
    if n == 0:
        typer.echo("no segments found")
    raise typer.Exit(1 if bad else 0)


@app.command()
def keygen(path: Annotated[Path, typer.Argument(help="where to write the Ed25519 seed; <path>.pub gets the public key")]
           = Path("ulpf_ed25519")) -> None:
    """Generate the vault signing key (mount it as a secret)."""
    from .vault import generate_keypair

    p, pub = generate_keypair(path)
    typer.echo(f"private key: {p} (0600)\npublic key:  {pub}")


@app.command()
def validate(events: Annotated[Path, typer.Option("--events", exists=True)]) -> None:
    """OCSF conformance check of a JSONL file of normalized events."""
    from .normalize.validate import validate_event

    n = bad = 0
    shown = 0
    for ln, line in enumerate(events.read_text().splitlines(), 1):
        if not line.strip():
            continue
        n += 1
        try:
            v = validate_event(json.loads(line))
        except ValueError as e:
            v = []
            typer.echo(f"line {ln}: not JSON ({e})")
            bad += 1
            continue
        if v:
            bad += 1
            if shown < 20:
                shown += 1
                typer.echo(f"line {ln}: " + "; ".join(map(str, v)))
    typer.echo(f"{n} events, {bad} with violations")
    raise typer.Exit(1 if bad else 0)


# ----------------------------------------------------------------------------------------------- packs
@packs_app.command("lint")
def packs_lint(path: Annotated[Path, typer.Argument()] = Path("packs"),
               min_tests: Annotated[int, typer.Option()] = 5,
               allow_verified: Annotated[bool, typer.Option(help="skip the R12 `verified: false` rule")] = False) -> None:
    """Lint packs: unknown ops/OCSF paths, ReDoS-prone regexes, derived paths, missing tests."""
    from .packs import lint_file, pack_files

    errs = 0
    for f in pack_files(path):
        issues = lint_file(f, min_tests=min_tests, require_unverified=not allow_verified)
        e = [i for i in issues if i.level == "error"]
        errs += len(e)
        typer.echo(f"{'FAIL' if e else 'ok  '} {f}")
        for i in issues:
            typer.echo(f"    {i}")
    raise typer.Exit(1 if errs else 0)


@packs_app.command("test")
def packs_test(path: Annotated[Path, typer.Argument()] = Path("packs")) -> None:
    """Run every pack's golden vectors through the production engine."""
    from .packs import compile_pack, load_pack_doc, pack_files, run_pack_tests

    bad = 0
    for f in pack_files(path):
        try:
            p = compile_pack(load_pack_doc(f))
        except Exception as e:  # noqa: BLE001
            typer.echo(f"FAIL {f}: {e}")
            bad += 1
            continue
        fails = run_pack_tests(p)
        bad += len(fails)
        typer.echo(f"{'FAIL' if fails else 'ok  '} {p.id:28s} {len(p.doc.tests)} vectors")
        for x in fails:
            typer.echo(f"    {x}")
    raise typer.Exit(1 if bad else 0)


# ----------------------------------------------------------------------------------------------- run / bench / demo
@app.command()
def run(
    role: Annotated[str, typer.Option(help="api | ingest | worker | all")] = "all",
    workers: Annotated[int | None, typer.Option(help="worker processes for --role all (default: pipeline.workers)")] = None,
    no_redis: Annotated[bool, typer.Option("--no-redis", help="in-process bus: --role all runs everything in this process")] = False,
    config: ConfigOpt = None,
    data_dir: DataOpt = None,
) -> None:
    """Run a node: syslog/file/HTTP ingest, workers, API + UI (docker/compose.yml runs one role per container)."""
    from .pipeline.runtime import run_node

    cfg = _cfg(config, data_dir, "memory" if no_redis else None)
    try:
        run_node(cfg, role, workers)
    except _redis_errors() as e:
        typer.echo(f"cannot reach Redis at {cfg.bus.url}: {e}\nstart one, set ULPF_BUS_URL, or use --no-redis", err=True)
        raise typer.Exit(3) from None
    except ValueError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(2) from None


@app.command()
def bench(
    events: Annotated[int, typer.Option(help="corpus size (lines)")] = 200_000,
    workers: Annotated[str, typer.Option(help="worker counts to measure, comma separated")] = "1,2",
    mix: Annotated[str, typer.Option()] = "fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10",
    seed: Annotated[int, typer.Option()] = 1,
    latency_secs: Annotated[float, typer.Option(help="seconds of paced load for the latency run (0 = skip)")] = 20.0,
    partitions: Annotated[int, typer.Option()] = 16,
    out: Annotated[Path, typer.Option()] = Path("bench/results.json"),
    redis_url: Annotated[str | None, typer.Option(help="use this Redis (it is FLUSHALL-ed!); default: a throwaway redis-server")] = None,
    config: ConfigOpt = None,
) -> None:
    """Measure sustained eps, worker scaling and ingest->queryable latency of the real pipeline; writes bench/results.json."""
    from .pipeline.bench import run_bench

    cfg = load_config(config)
    cfg.packs.dirs = _pack_dirs(cfg.packs.dirs)
    wl = [int(x) for x in workers.split(",") if x.strip()]
    res = run_bench(cfg, events=events, workers_list=wl, mix=mix, seed=seed, latency_secs=latency_secs, partitions=partitions, out=out,
                    redis_url=redis_url, log=typer.echo)
    hw = res["hardware"]
    typer.echo(f"hardware: {hw['cpu']} x{hw['cores']}, {hw['ram_gb']} GB, {hw['os']}")
    for s in res["scaling"]:
        typer.echo(f"  {s['workers']} worker(s): {s['eps']:,.0f} eps")
    if "latency_ms" in res:
        typer.echo(f"  latency p50/p99: {res['latency_ms']['p50']:.0f} / {res['latency_ms']['p99']:.0f} ms")
    raise typer.Exit(0 if res["ledger"]["conserved"] else 1)


@app.command()
def demo(
    url: Annotated[str | None, typer.Option(help="a running node's base URL; default http://127.0.0.1:8080 when reachable")] = None,
    scenario: Annotated[Path, typer.Option()] = Path("tools/loggen/scenarios/demo.yaml"),
    eps: Annotated[float, typer.Option(help="simulated baseline events/s of the scenario")] = 100.0,
    rate: Annotated[float, typer.Option(help="wall-clock events/s sent to the node (0 = as fast as possible)")] = 3000.0,
    token: Annotated[str | None, typer.Option(envvar="ULPF_API_TOKEN")] = None,
    align_now: Annotated[bool, typer.Option("--align-now/--scenario-clock", help="shift the scenario so it ends now (the UI's default time ranges "
                                            "show it); --scenario-clock keeps the scenario file's fixed start")] = True,
    serve: Annotated[bool, typer.Option(help="standalone mode: serve the API/UI over the result when done")] = True,
    config: ConfigOpt = None,
    data_dir: DataOpt = None,
) -> None:
    """Play the loggen demo scenario (30 simulated minutes, 3 injected incidents) into a running node.

    With no node reachable the demo is standalone: replay in-process, run the anomaly detector, print the findings and (default) serve the UI."""
    import subprocess
    import tempfile

    import httpx

    root = Path(__file__).resolve().parents[2]
    if not scenario.is_file() and (root / scenario).is_file():
        scenario = root / scenario
    if not scenario.is_file():
        typer.echo(f"scenario not found: {scenario} (run from a source checkout)", err=True)
        raise typer.Exit(2)
    log = Path(tempfile.mkdtemp(prefix="ulpf-demo-")) / "demo.log"
    typer.echo(f"generating scenario (simulated 30 min at {eps:g} eps) ...")
    start_args: list[str] = []
    if align_now:
        import datetime as dt

        import yaml

        dur = float(yaml.safe_load(scenario.read_text()).get("duration_s", 1800))
        t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=dur + 30)
        start_args = ["--start", t.strftime("%Y-%m-%dT%H:%M:%SZ")]
    subprocess.run([sys.executable, "-m", "tools.loggen", "--scenario", str(scenario), "--eps", str(eps), "--out", str(log), "--no-truth", *start_args],
                   check=True,
                   cwd=root, env={**os.environ, "PYTHONPATH": f"{root / 'src'}:{root}"}, capture_output=True)
    lines = [ln for ln in log.read_bytes().split(b"\n") if ln]
    base = (url or "http://127.0.0.1:8080").rstrip("/")
    hdr = {"Content-Type": "application/x-ndjson", **({"Authorization": f"Bearer {token}"} if token else {})}
    live = False
    try:
        live = httpx.get(base + "/api/v1/health", timeout=2).status_code == 200
    except httpx.HTTPError:
        pass
    if live:
        typer.echo(f"sending {len(lines):,} events to {base}")
        t0 = time.perf_counter()
        sent = 0
        with httpx.Client(timeout=30) as c:
            for i in range(0, len(lines), 500):
                chunk = lines[i:i + 500]
                r = c.post(base + "/ingest/raw", content=b"\n".join(chunk), headers=hdr)
                if r.status_code != 200:
                    typer.echo(f"ingest refused: HTTP {r.status_code} {r.text[:200]}", err=True)
                    raise typer.Exit(1)
                sent += len(chunk)
                if rate:
                    lag = sent / rate - (time.perf_counter() - t0)
                    if lag > 0:
                        time.sleep(lag)
        typer.echo(f"sent {sent:,} events in {time.perf_counter() - t0:.1f}s; open {base}/ and watch Live, Explorer, Detections, Integrity")
        return
    if url:
        typer.echo(f"no node reachable at {base}", err=True)
        raise typer.Exit(1)
    typer.echo("no node on 127.0.0.1:8080: standalone demo (in-process, no Redis)")
    cfg = _cfg(config, data_dir or Path("data/demo"), "memory")
    _ensure_key(cfg)
    res = run_replay(cfg, log, None, None)
    t = res["ledger"]["totals"]
    typer.echo(f"replayed {res['lines']:,} lines; ledger conserved={res['ledger']['conserved']} sunk={t['sunk']:,} unparsed={t['unparsed']:,}")
    from .pipeline.analysis import AnalyticsRunner

    r = AnalyticsRunner(cfg.lake_dir, cfg.node_id, cfg.analytics.window_s, Path(cfg.data_dir) / "analytics_state.json").run_once()
    typer.echo(f"analytics: {r}")
    typer.echo(f"data: {cfg.data_dir}")
    if serve:
        from .pipeline.runtime import run_node

        typer.echo("serving on http://127.0.0.1:8080 (Ctrl-C to stop)")
        cfg.bus.kind = "memory"
        run_node(cfg, "api")


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
