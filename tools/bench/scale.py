"""Scale conservation + tamper + ground-truth accuracy through the REAL pipeline (Redis Streams bus, worker processes, vault, Parquet).

  python -m tools.bench.scale --n 1000000 --workers 2 --out /tmp/scale.json

Used by ``tests/integration/test_scale.py`` (default 100k events, ``ULPF_SCALE_N`` to override) and run by hand at 1M (§1.2).

Phases, each measured independently of the pipeline's own ledger so the ledger is checked rather than trusted:

1. corpus: loggen mix of all nine formats with ground truth; every ``junk_every``-th line is replaced by an unparseable or byte-mutated
   variant (never scored for accuracy, but it must be ingested, vaulted and sunk like any other event). The SHA-256 multiset of every
   input line is kept.
2. run: all lines published (per-device peers so the bus spreads over partitions), N worker processes drain them.
3. conservation: ledger totals; Parquet row count / distinct event_id / status counts / SHA multiset == input multiset; vault frame count,
   frame SHA multiset == input multiset, every lake ``raw_ref`` resolves to a vault frame and the set of vault frames == the set of lake refs;
   ``ulpf verify`` equivalent (``verify_all``) passes; zero dropped.
4. accuracy: lake ``event`` joined to truth by raw SHA-256 -> ``tools.loggen.accuracy.score`` (per vendor and ALL).
5. tamper: copy the vault, flip ONE byte inside one block, run the real ``ulpf verify`` CLI on the copy (must exit 1 and name the segment,
   block and frame), read every lake raw_ref through the tampered vault (failures must be confined to the tampered block) and hit the HTTP raw
   and explain endpoints for a victim and a bystander.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MIX = "fortigate:20,asa:20,suricata:15,cef:10,pfsense:10,squid:10,zeek:5,leef:5,dnsmasq:5"
JUNK = [b"totally unknown chatter 10.1.1.1 port 99", b"\xff\xfe\x00binary\x80", b"{not json", b"<999>garbage", b"CEF:0|a|b",
        b"%ASA-9-999999: nothing", b"\t\t\t", b"x" * 3000]


def mutate(b: bytes, rnd: random.Random) -> bytes:
    a = bytearray(b)
    k = rnd.randrange(4)
    if k == 0 and a:
        a[rnd.randrange(len(a))] ^= 0xFF
    elif k == 1 and a:
        del a[rnd.randrange(len(a)):]
    elif k == 2 and a:
        i = rnd.randrange(len(a))
        a[i:i] = bytes(a[i:i + 1]) * 3
    else:
        a[:0] = b"\x00"
    return bytes(a) or b"\x00"


def build_corpus(n: int, seed: int, junk_every: int, tmp: Path) -> dict[str, Any]:
    """Returns {lines: [(peer, bytes)], digests: Counter[bytes], truth_path, clean: int, junk: int}."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    from tools.loggen import generator

    rnd = random.Random(seed)
    lines: list[tuple[str, bytes]] = []
    digests: collections.Counter[bytes] = collections.Counter()
    seen: set[bytes] = set()
    cols: dict[str, list] = {"sha": [], "source": [], "assumed": [], "expect": []}
    writer = None
    clean = junk = 0
    truth_path = tmp / "truth.parquet"

    def flush() -> None:
        nonlocal writer
        if not cols["sha"]:
            return
        t = pa.table({k: pa.array(v) for k, v in cols.items()})
        if writer is None:
            writer = pq.ParquetWriter(truth_path, t.schema)
        writer.write_table(t)
        for v in cols.values():
            v.clear()

    for i, (_dev, line, rec) in enumerate(generator.generate(mix=MIX, seed=seed, count=n)):
        raw = line.encode()
        peer = f"10.{(i // 20) % 251}.{(i // 5020) % 251}.1"
        if junk_every and i % junk_every == junk_every - 1:
            raw = JUNK[(i // junk_every) % len(JUNK)] if (i // junk_every) % 3 == 0 else mutate(raw, rnd)
            junk += 1
        else:
            h = hashlib.sha256(raw).digest()
            if h not in seen:
                seen.add(h)
                cols["sha"].append(h.hex())
                cols["source"].append(rec["source"])
                cols["assumed"].append(bool(rec.get("assumed_time")))
                cols["expect"].append(json.dumps(rec["expect"]))
            clean += 1
        lines.append((peer, raw))
        digests[hashlib.sha256(raw).digest()] += 1
        if len(cols["sha"]) >= 50_000:
            flush()
    flush()
    if writer:
        writer.close()
    return {"lines": lines, "digests": digests, "truth_path": truth_path, "clean": clean, "junk": junk}


def _flip_one_byte(vault: Path, rnd: random.Random) -> dict[str, Any]:
    """Flip one byte in the middle of one block of one segment; returns where."""
    from ulpf.vault import format as fmt
    from ulpf.vault.integrity import iter_segments

    segs = iter_segments(vault)
    seg = segs[rnd.randrange(len(segs))]
    with open(seg, "rb") as f:
        size = seg.stat().st_size
        _, first = fmt.decode_header(f.read(min(size, 1 << 16)))
        limit = size
        f.seek(size - fmt.TRAILER_SIZE)
        t = fmt.decode_trailer(f.read(fmt.TRAILER_SIZE))
        if t is not None:
            limit = max(first, size - fmt.TRAILER_SIZE - t[1] - t[0])
        blocks, _ = fmt.scan_blocks(f, first, limit)
    bi = rnd.randrange(len(blocks))
    loc = blocks[bi]
    buf = bytearray(seg.read_bytes())
    # Prefer the hard case: a flip that still decompresses AND silently changes a frame's raw bytes (only the frame hash catches it).
    # Next best: decompresses but changes only metadata (chain hash catches it). Last resort: the midpoint of the block (zstd breaks).
    orig = fmt.decode_block_payload(bytes(buf[loc.payload_offset:loc.payload_offset + loc.comp_len]), loc.n_frames)[0]
    orig_data = [bytes(f[fmt.F_DATA]) for f in orig]
    off, kind = loc.payload_offset + loc.comp_len // 2, "undecodable"
    fallback = None
    for _ in range(3000):
        cand = loc.payload_offset + rnd.randrange(loc.comp_len)
        buf[cand] ^= 0x01
        try:
            frames = fmt.decode_block_payload(bytes(buf[loc.payload_offset:loc.payload_offset + loc.comp_len]), loc.n_frames)[0]
            changed = [bytes(f[fmt.F_DATA]) for f in frames] != orig_data
        except Exception:  # noqa: BLE001
            buf[cand] ^= 0x01
            continue
        buf[cand] ^= 0x01
        if changed:
            off, kind = cand, "raw_bytes_changed"
            break
        fallback = fallback or cand
    else:
        if fallback is not None:
            off, kind = fallback, "metadata_only"
    buf[off] ^= 0x01
    seg.write_bytes(bytes(buf))
    return {"segment": seg.name[: -len(fmt.SEG_SUFFIX)], "block": bi, "offset": off, "n_frames": loc.n_frames, "kind": kind}


def run_scale(n: int, workers: int, redis_url: str, work: Path, seed: int = 1, junk_every: int = 500, jsonl: bool = False,
              tamper: bool = True, log=print) -> dict[str, Any]:
    import duckdb

    from tools.loggen import accuracy
    from ulpf.bus import make_bus
    from ulpf.config import Config
    from ulpf.ingest import Publisher
    from ulpf.pipeline import backlog, report
    from ulpf.pipeline.runtime import WorkerPool, ensure_signing_key, wait_drained
    from ulpf.vault import VaultReader, verify_all
    from ulpf.vault.integrity import IntegrityError

    out: dict[str, Any] = {"n": n, "workers": workers, "seed": seed}
    work.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    corpus = build_corpus(n, seed, junk_every, work)
    lines, digests = corpus["lines"], corpus["digests"]
    out["corpus"] = {"lines": len(lines), "clean": corpus["clean"], "junk_or_mutated": corpus["junk"], "seconds": round(time.perf_counter() - t0, 1)}
    log(f"corpus {out['corpus']}")

    cfg = Config().rebase(work / "node")
    cfg.bus.kind, cfg.bus.url, cfg.bus.partitions = "redis", redis_url, 16
    cfg.packs.dirs = [str(ROOT / "packs")]
    cfg.sinks.jsonl.enabled = jsonl
    cfg.analytics.enabled = False
    cfg.vault.signing_key = str(work / "keys" / "ulpf_ed25519")
    ensure_signing_key(cfg)
    bus = make_bus("redis", redis_url, 16, cfg.bus.maxlen)
    bus.r.flushall()
    pub = Publisher(bus, cfg.node_id, max_event_bytes=cfg.ingest.max_event_bytes, batch_max=cfg.ingest.batch_max)
    t1 = time.perf_counter()
    for peer, raw in lines:
        pub.ingest(raw, "replay", peer, 0, None)
    pub.flush()
    out["publish_seconds"] = round(time.perf_counter() - t1, 1)
    pool = WorkerPool(cfg, workers)
    t2 = time.perf_counter()
    pool.start()
    try:
        drained = wait_drained(bus, timeout=max(600.0, n / 300))
    finally:
        pool.stop()
    out["drain_seconds"] = round(time.perf_counter() - t2, 1)
    out["drain_eps"] = round(n / out["drain_seconds"])
    led = report(bus.ledger.snapshot(), backlog(bus), int(time.time() * 1000))
    out["ledger"] = {"totals": led["totals"], "conserved": led["conserved"], "lost": led["lost"], "dropped_by_reason": led["dropped_by_reason"],
                     "sunk_by_sink": led["sunk_by_sink"], "drained": drained}
    t = led["totals"]
    log(f"ledger {out['ledger']}")

    # ---- independent counts (not the ledger)
    lake = f"{cfg.lake_dir}/**/*.parquet"
    con = duckdb.connect()
    con.execute(f"create view lk as select * from read_parquet('{lake}', hive_partitioning=false)")
    rows, dist_ev, dist_ref = con.execute("select count(*), count(distinct event_id), count(distinct raw_ref) from lk").fetchone()
    status = dict(con.execute("select status, count(*) from lk group by 1").fetchall())
    lake_sha = collections.Counter({bytes.fromhex(s): c for s, c in con.execute("select raw_sha256, count(*) from lk group by 1").fetchall()})
    reps = list(verify_all(cfg.vault.dir))
    frames = sum(r.frames_checked for r in reps)
    rd = VaultReader(cfg.vault.dir)
    vault_sha: collections.Counter[bytes] = collections.Counter()
    vault_refs: set[str] = set()
    for r in reps:
        for b in range(r.blocks_checked):
            for i, fr in enumerate(rd.iter_block_frames(r.segment, b)):
                data = bytes(fr[6])
                h = hashlib.sha256(data).digest()
                assert h == bytes(fr[5])
                vault_sha[h] += 1
                vault_refs.add(f"{r.segment}/{b}/{i}")
        rd.invalidate()
    lake_refs = {x for (x,) in con.execute("select raw_ref from lk").fetchall()}
    jsonl_lines = None
    if jsonl:
        jsonl_lines = sum(sum(1 for _ in open(p, "rb")) for p in Path(cfg.sinks.jsonl.dir).glob("*.jsonl"))
    out["conservation"] = {
        "input": n, "ledger_ingested": t["ingested"], "ledger_vaulted": t["vaulted"],
        "ledger_normalized_parsed": t["normalized_parsed"], "ledger_normalized_partial": t["normalized_partial"],
        "ledger_unparsed": t["unparsed"], "ledger_sunk": t["sunk"], "ledger_dropped": t["dropped"],
        "lake_rows": rows, "lake_distinct_event_id": dist_ev, "lake_distinct_raw_ref": dist_ref, "lake_status": status,
        "vault_segments": len(reps), "vault_frames": frames, "vault_all_ok": all(r.ok for r in reps),
        "vault_sealed": sum(1 for r in reps if r.sealed),
        "lake_sha_multiset_equals_input": lake_sha == digests, "vault_sha_multiset_equals_input": vault_sha == digests,
        "vault_refs_equal_lake_refs": vault_refs == lake_refs, "jsonl_lines": jsonl_lines,
    }
    c = out["conservation"]
    out["conservation_ok"] = bool(
        t["ingested"] == t["vaulted"] == t["sunk"] == n and t["normalized_parsed"] + t["normalized_partial"] + t["unparsed"] == n
        and t["dropped"] == 0 and led["conserved"] and led["lost"] == 0 and rows == dist_ev == dist_ref == n
        and sum(status.values()) == n and frames == n and c["vault_all_ok"] and c["lake_sha_multiset_equals_input"]
        and c["vault_sha_multiset_equals_input"] and c["vault_refs_equal_lake_refs"] and (jsonl_lines in (None, n)))
    log(f"conservation {json.dumps(c)} -> ok={out['conservation_ok']}")

    # ---- accuracy vs ground truth, joined by raw sha256
    cur = con.execute(f"select t.source, t.assumed, t.expect, l.event, l.status from read_parquet('{corpus['truth_path']}') t "
                      f"join lk l on l.raw_sha256 = t.sha")
    unparsed_clean = 0
    st_by_src: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)

    def pairs():
        nonlocal unparsed_clean
        while True:
            batch = cur.fetchmany(20_000)
            if not batch:
                return
            for src, assumed, expect, event, stt in batch:
                st_by_src[src][stt] += 1
                yield {"source": src, "assumed_time": assumed, "expect": json.loads(expect)}, json.loads(event)

    out["accuracy"] = accuracy.score(pairs())
    out["clean_status_by_source"] = {k: dict(v) for k, v in st_by_src.items()}
    tot = collections.Counter()
    for v in st_by_src.values():
        tot.update(v)
    out["clean_parse_rate"] = round(1 - tot["unparsed"] / max(sum(tot.values()), 1), 6)
    log("accuracy " + json.dumps({k: (round(v["precision"], 5), round(v["recall"], 5)) for k, v in out["accuracy"].items()}))

    # ---- tamper
    if tamper:
        tv = work / "vault_tampered"
        shutil.copytree(cfg.vault.dir, tv)
        where = _flip_one_byte(tv, random.Random(seed))
        env = {**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}"}
        exe = shutil.which("ulpf") or str(Path(sys.executable).with_name("ulpf"))
        cp = subprocess.run([exe, "verify", "--vault-dir", str(tv)], capture_output=True, text=True, env=env)
        bad_lines = [ln for ln in cp.stdout.splitlines() if "-> segment" in ln]
        rd2 = VaultReader(tv)
        failed_blocks: collections.Counter[tuple[str, int]] = collections.Counter()
        okreads = 0
        failed_refs: list[str] = []
        for (ref,) in con.execute("select raw_ref from lk").fetchall():
            try:
                rd2.read(ref)
                okreads += 1
            except IntegrityError as e:
                failed_blocks[(e.segment, e.block)] += 1
                failed_refs.append(ref)
        rep_bad = next((r for r in verify_all(tv) if not r.ok), None)
        out["tamper"] = {
            "flipped": where, "cli_exit": cp.returncode, "cli_pinpoint": bad_lines,
            "verify_error": {"segment": rep_bad.segment, "block": rep_bad.error_block, "frame": rep_bad.error_frame, "msg": rep_bad.error} if rep_bad else None,
            "reads_ok": okreads, "reads_failed": sum(failed_blocks.values()), "failed_blocks": {f"{s}/{b}": c2 for (s, b), c2 in failed_blocks.items()},
        }
        out["tamper_ok"] = bool(
            cp.returncode == 1 and bad_lines and rep_bad and rep_bad.segment == where["segment"] and rep_bad.error_block == where["block"]
            and f"segment {where['segment']} block {where['block']}" in bad_lines[0]
            and set(failed_blocks) <= {(where["segment"], where["block"])} and okreads + sum(failed_blocks.values()) == n
            and okreads >= n - where["n_frames"])
        # HTTP: victim fails, bystander verifies
        try:
            from fastapi.testclient import TestClient

            from ulpf.api.app import create_app
            from ulpf.bus import MemoryBus
            from ulpf.packs import PackRegistry
            from ulpf.sinks import MemoryTail

            cfg2 = cfg.model_copy(deep=True)
            cfg2.vault.dir = str(tv)
            cfg2.bus.kind = "memory"
            reg = PackRegistry(cfg2.packs.dirs or [str(ROOT / "packs")])
            cl = TestClient(create_app(cfg2, bus=MemoryBus(4), registry=reg, tail=MemoryTail()))
            seg, blk = where["segment"], where["block"]
            vic = con.execute("select event_id from lk where raw_ref = any(?) and status = 'parsed' limit 1", [failed_refs]).fetchone()
            byst = con.execute("select event_id from lk where raw_ref not like ? and status = 'parsed' limit 1", [f"{seg}/{blk}/%"]).fetchone()
            rb = cl.get(f"/api/v1/events/{byst[0]}/raw")
            h: dict[str, Any] = {"bystander_raw": [rb.status_code, rb.json().get("verified")]}
            out["tamper"]["http"] = h
            ok = h["bystander_raw"][1] is True
            if vic is not None:          # absent when the flip only touched metadata: the raw bytes are intact and the chain hash alone flags it
                rv, ev = cl.get(f"/api/v1/events/{vic[0]}/raw"), cl.get(f"/api/v1/events/{vic[0]}/explain")
                h["victim_raw"] = [rv.status_code, rv.json().get("verified"), (rv.json().get("error") or {}).get("code")]
                h["victim_explain"] = [ev.status_code, (ev.json().get("error") or {}).get("code")]
                ok = ok and h["victim_raw"][1] is False and h["victim_raw"][2] == "IntegrityError" and h["victim_explain"][0] == 409
            out["tamper_ok"] = bool(out["tamper_ok"] and ok)
        except Exception as e:  # noqa: BLE001
            out["tamper"]["http_error"] = repr(e)
            out["tamper_ok"] = False
        log("tamper " + json.dumps(out["tamper"]))
    bus.close()
    out["total_seconds"] = round(time.perf_counter() - t0, 1)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n", type=int, default=1_000_000)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--junk-every", type=int, default=500)
    ap.add_argument("--jsonl", action="store_true")
    ap.add_argument("--no-tamper", action="store_true")
    ap.add_argument("--work", default=None)
    ap.add_argument("--out", default="scale-report.json")
    a = ap.parse_args(argv)
    from ulpf.pipeline.bench import ThrowawayRedis

    work = Path(a.work or tempfile.mkdtemp(prefix="ulpf-scale-"))
    work.mkdir(parents=True, exist_ok=True)
    r = ThrowawayRedis(work)
    try:
        res = run_scale(a.n, a.workers, r.url, work, a.seed, a.junk_every, a.jsonl, not a.no_tamper, log=lambda s: print(s, flush=True))
    finally:
        r.stop()
    Path(a.out).write_text(json.dumps(res, indent=2, default=str))
    ok = res["conservation_ok"] and res.get("tamper_ok", True)
    print("RESULT", "PASS" if ok else "FAIL", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
    raise SystemExit(main())
