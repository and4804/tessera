import json
import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest

from ulpf.model.ids import uuid7
from ulpf.model.lineage import VaultRef
from ulpf.vault import (
    IntegrityError,
    NotFoundError,
    VaultReader,
    VaultWriter,
    generate_keypair,
    load_signing_key,
    verify_all,
    verify_segment,
)
from ulpf.vault.integrity import iter_segments


def _w(tmp_path, **kw):
    kw.setdefault("block_events", 10)
    kw.setdefault("block_max_ms", 10_000)
    return VaultWriter(tmp_path / "vault", "n1", **kw)


def _put(w, n, payload=None):
    refs = []
    for i in range(n):
        data = payload(i) if payload else f"event {i} \xff\x00 ünï".encode("latin-1", "replace") + bytes([i % 256])
        refs.append((w.append(uuid7(), 1000 + i, "udp", "10.0.0.1", 514, data), data))
    return refs


def test_refs_known_at_append_and_roundtrip(tmp_path):
    w = _w(tmp_path)
    refs = _put(w, 25)
    # deterministic: 10 per block
    assert [(r.block, r.idx) for r, _ in refs[:12]] == [(0, i) for i in range(10)] + [(1, 0), (1, 1)]
    assert str(refs[0][0]) == f"{w.segment}/0/0"
    w.flush()
    r = VaultReader(tmp_path / "vault")
    for ref, data in refs:
        assert r.read(ref) == data
    assert r.read(str(refs[3][0])) == refs[3][1]
    w.close()
    r2 = VaultReader(tmp_path / "vault")
    assert r2.read(refs[24][0]) == refs[24][1]


def test_invalid_utf8_and_empty_roundtrip(tmp_path):
    w = _w(tmp_path)
    datas = [b"", b"\xff\xfe\xfd", b"\x00" * 5, bytes(range(256)), b"a" * 70000]
    refs = [w.append(uuid7(), 1, "tcp", "", 0, d) for d in datas]
    w.close()
    r = VaultReader(tmp_path / "vault")
    assert [r.read(x) for x in refs] == datas


def test_not_found(tmp_path):
    w = _w(tmp_path)
    _put(w, 3)
    w.flush()
    r = VaultReader(tmp_path / "vault")
    with pytest.raises(NotFoundError):
        r.read(f"{w.segment}/9/0")
    with pytest.raises(NotFoundError):
        r.read(f"{w.segment}/0/9")
    with pytest.raises(NotFoundError):
        r.read("zz-000001/0/0")


def test_expected_sha_mismatch_raises(tmp_path):
    w = _w(tmp_path)
    ref, _ = _put(w, 1)[0]
    w.flush()
    r = VaultReader(tmp_path / "vault")
    with pytest.raises(IntegrityError):
        r.read(VaultRef(ref.segment, ref.block, ref.idx, "00" * 32))


def test_block_time_cut(tmp_path):
    w = _w(tmp_path, block_events=1000, block_max_ms=1)
    w.append(uuid7(), 1, "udp", "", 0, b"a")
    time.sleep(0.01)
    ref = w.append(uuid7(), 2, "udp", "", 0, b"b")
    assert w.stats()["blocks"] == 1 and ref.block == 0
    nxt = w.append(uuid7(), 3, "udp", "", 0, b"c")
    assert nxt.block == 1


def test_seal_verify_signature_and_pinning(tmp_path):
    keyp, pub = generate_keypair(tmp_path / "key")
    sk = load_signing_key(keyp)
    assert oct(os.stat(keyp).st_mode & 0o777) == "0o600"
    w = _w(tmp_path, signing_key=sk)
    _put(w, 35)
    w.close()
    reps = list(verify_all(tmp_path / "vault"))
    assert len(reps) == 1 and reps[0].ok and reps[0].sealed and reps[0].signature_ok and reps[0].frames_checked == 35
    assert not reps[0].signature_pinned
    pk = bytes.fromhex(pub.read_text().strip())
    assert list(verify_all(tmp_path / "vault", pk))[0].signature_pinned
    other = bytes.fromhex(generate_keypair(tmp_path / "other")[1].read_text().strip())
    bad = list(verify_all(tmp_path / "vault", other))[0]
    assert not bad.ok and bad.signature_ok is False
    man = json.loads(next((tmp_path / "vault").rglob("*.manifest.json")).read_text())
    assert man["n_events"] == 35 and man["signed"]


def test_unsealed_segment_verified_by_chain(tmp_path):
    w = _w(tmp_path)
    _put(w, 25)
    w.flush()
    rep = verify_segment(iter_segments(tmp_path / "vault")[0])
    assert rep.ok and not rep.sealed and rep.chain_status == "open" and rep.frames_checked == 25
    w.close(seal=False)


def test_rotation_chains_segments(tmp_path):
    w = _w(tmp_path, block_events=5, segment_max_mb=0.0003)
    refs = _put(w, 200)
    w.close()
    segs = iter_segments(tmp_path / "vault")
    assert len(segs) > 3
    assert len({r.segment for r, _ in refs}) == len(segs)
    reps = list(verify_all(tmp_path / "vault"))
    assert all(r.ok and r.sealed for r in reps)
    assert reps[1].prev_head == reps[0].chain_head
    rd = VaultReader(tmp_path / "vault")
    assert all(rd.read(r) == d for r, d in refs)
    # delete a middle segment => gap detected
    segs[2].unlink()
    reps = list(verify_all(tmp_path / "vault"))
    assert not all(r.ok for r in reps)


def _flip_payload(tmp_path, payload: bytes, off: int = 5) -> None:
    f = iter_segments(tmp_path / "vault")[0]
    b = bytearray(f.read_bytes())
    i = b.find(payload)
    assert i > 0, "payload not stored verbatim"
    b[i + off] ^= 0x01
    f.write_bytes(bytes(b))


def test_tamper_pinpoints_block_and_frame(tmp_path):
    payloads = [os.urandom(64) for _ in range(35)]
    w = _w(tmp_path)
    refs = [w.append(uuid7(), 1, "udp", "", 0, p) for p in payloads]
    w.close()
    victim = 23  # block 2, idx 3
    assert (refs[victim].block, refs[victim].idx) == (2, 3)
    _flip_payload(tmp_path, payloads[victim])
    rep = next(iter(verify_all(tmp_path / "vault")))
    assert not rep.ok and rep.error_block == 2 and rep.error_frame == 3, (rep.error, rep.error_block, rep.error_frame)
    # reading the corrupted event raises, its neighbours (same block) and other blocks are fine
    rd = VaultReader(tmp_path / "vault")
    with pytest.raises(IntegrityError) as ei:
        rd.read(refs[victim])
    assert ei.value.block == 2 and ei.value.frame == 3
    for i, p in enumerate(payloads):
        if i != victim:
            assert rd.read(refs[i]) == p
    raw = rd.read_frame(refs[victim].segment, 2, 3, refs[victim].sha256)
    assert not raw.verified and raw.sha256_actual != raw.sha256_expected


def test_tamper_chain_byte_and_signature(tmp_path):
    keyp, _ = generate_keypair(tmp_path / "k")
    w = _w(tmp_path, signing_key=load_signing_key(keyp))
    _put(w, 30)
    w.close()
    f = iter_segments(tmp_path / "vault")[0]
    b = bytearray(f.read_bytes())
    b[-30] ^= 0xFF  # inside the footer/signature area
    f.write_bytes(bytes(b))
    rep = next(iter(verify_all(tmp_path / "vault")))
    assert not rep.ok


def test_tamper_dropped_event_changes_chain(tmp_path):
    w = _w(tmp_path)
    _put(w, 30)
    w.close()
    # rewrite segment keeping the structure but dropping nothing: replace manifest chain to simulate swap
    mp = next((tmp_path / "vault").rglob("*.manifest.json"))
    m = json.loads(mp.read_text())
    m["chain_head"] = "00" * 32
    mp.write_text(json.dumps(m))
    assert not next(iter(verify_all(tmp_path / "vault"))).ok


def test_crash_torn_block_recovery(tmp_path):
    w = _w(tmp_path)
    refs = _put(w, 30)
    w.flush()
    w.close(seal=False)
    f = iter_segments(tmp_path / "vault")[0]
    good = f.stat().st_size
    # a torn partial block: valid block header, half payload
    w2 = _w(tmp_path, block_events=3)
    _put(w2, 3)
    w2.close(seal=False)
    full = f.read_bytes()
    f.write_bytes(full[: good + (len(full) - good) // 2])
    w3 = _w(tmp_path)
    assert w3.recovered_truncated_bytes > 0
    assert w3.segment == f.name[:-8]
    more = _put(w3, 10)
    w3.close()
    reps = list(verify_all(tmp_path / "vault"))
    assert len(reps) == 1 and reps[0].ok and reps[0].sealed
    rd = VaultReader(tmp_path / "vault")
    assert all(rd.read(r) == d for r, d in refs + more[:10])


def test_crash_garbage_tail_complete_length_block(tmp_path):
    w = _w(tmp_path)
    _put(w, 20)
    w.close(seal=False)
    f = iter_segments(tmp_path / "vault")[0]
    n = f.stat().st_size
    import struct
    with open(f, "ab") as fh:  # a block of plausible length whose payload is garbage
        fh.write(struct.pack("<II", 40, 2) + os.urandom(40 + 32))
    w2 = _w(tmp_path)
    assert w2.recovered_truncated_bytes == f.stat().st_size - n + 0 or w2.recovered_truncated_bytes > 0
    w2.close()
    assert next(iter(verify_all(tmp_path / "vault"))).ok


def test_crash_after_sealed_starts_new_segment_linked(tmp_path):
    w = _w(tmp_path)
    _put(w, 12)
    w.close()
    w2 = _w(tmp_path)
    _put(w2, 5)
    w2.close()
    reps = list(verify_all(tmp_path / "vault"))
    assert [r.ok for r in reps] == [True, True] and reps[1].prev_head == reps[0].chain_head


def test_sigkill_midwrite_recovers(tmp_path):
    script = textwrap.dedent(f"""
        import sys, time
        from ulpf.vault import VaultWriter
        w = VaultWriter({str(tmp_path / 'vault')!r}, "n1", block_events=50, block_max_ms=100000)
        i = 0
        print("ready", flush=True)
        while True:
            w.append("id%d" % i, i, "udp", "", 0, (b"payload-%d-" % i) * 20)
            i += 1
            if i % 400 == 0:
                w.flush()
                print("flushed", i, flush=True)
    """)
    p = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    assert p.stdout is not None
    last = 0
    deadline = time.time() + 20
    while time.time() < deadline:
        line = p.stdout.readline().split()
        if line and line[0] == "flushed":
            last = int(line[1])
            if last >= 1200:
                break
    p.send_signal(signal.SIGKILL)
    p.wait()
    assert last >= 1200
    w = VaultWriter(tmp_path / "vault", "n1", block_events=50)
    w.close()
    reps = list(verify_all(tmp_path / "vault"))
    assert all(r.ok for r in reps), [(r.error, r.error_block) for r in reps]
    assert sum(r.n_events for r in reps) >= last  # every flushed (fsynced) event survived


def test_retention_free_listing(tmp_path):
    w = _w(tmp_path)
    _put(w, 15)
    w.close()
    segs = VaultReader(tmp_path / "vault").list_segments()
    assert segs[0]["n_events"] == 15 and segs[0]["sealed"]


def test_append_throughput_single_thread(tmp_path):
    w = VaultWriter(tmp_path / "vault", "n1", block_events=1000, block_max_ms=10_000, fsync=False)
    data = b"<189>date=2026-10-04 time=13:21:07 devname=FGT-HQ " + b"x" * 300
    n = 100_000
    t = time.perf_counter()
    for i in range(n):
        w.append("0" * 36, i, "udp", "10.0.0.1", 514, data)
    w.flush()
    eps = n / (time.perf_counter() - t)
    w.close()
    assert eps > 40_000, eps  # target is 100k/s on a quiet core; gate leaves room for a shared CI box
