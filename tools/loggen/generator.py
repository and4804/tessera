"""Deterministic multi-vendor log generator with ground truth.

  python -m tools.loggen --mix fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10 --count 100000 --seed 1 --out /tmp/mix.log
  python -m tools.loggen --scenario tools/loggen/scenarios/demo.yaml --out /tmp/demo.log          # 30 simulated minutes, 3 incidents
  python -m tools.loggen --heldout mikrotik --count 60 --out /tmp/mikrotik.log                    # onboarding demo (no pack shipped)

Output: <out> (one raw event per line, no trailing blank) and <out>.truth.jsonl (same order, one JSON record per line):
  {"n": 0, "source": "fortigate", "expect": {"src_endpoint.ip": ...}, "tag": "port_scan"?, "assumed_time": true?}
Same seed + same arguments => byte-identical output.
"""
from __future__ import annotations

import argparse
import heapq
import json
import os
import random
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from . import core
from .core import BASELINE
from .formats import REGISTRY

DEFAULT_HOSTS = {
    "fortigate": ("FGT-HQ", {"devid": "FGT60F0000000001"}),
    "asa": ("ASA-EDGE", {}),
    "suricata": ("suri-01", {}),
    "cef": ("FW-CEF1", {}),
    "pfsense": ("pfSense.corp.local", {"pid": 85432, "wan_if": "igb0"}),
    "squid": ("squid-px", {}),
    "zeek": ("zeek-01", {}),
    "windows": ("DC01.corp.local", {}),
    "leef": ("FW-LEEF1", {}),
    "dnsmasq": ("gw-dns", {"pid": 1234}),
}
# which baseline kinds a format emits (weights)
DEFAULT_KINDS = {
    "fortigate": {"conn": 1.0}, "asa": {"conn": 0.97, "auth": 0.03}, "suricata": {"conn": 0.8, "alert": 0.2}, "cef": {"conn": 1.0},
    "pfsense": {"conn": 1.0}, "squid": {"http": 1.0}, "zeek": {"conn": 1.0}, "windows": {"auth": 1.0}, "leef": {"conn": 1.0}, "dnsmasq": {"dns": 1.0},
}


class Device:
    def __init__(self, did: str, fmt: str, host: str | None = None, weight: float = 1.0, kinds: dict[str, float] | None = None, **extra: Any):
        self.id, self.fmt, self.mod = did, fmt, REGISTRY[fmt]
        h, ex = DEFAULT_HOSTS[fmt]
        self.dev = {"host": host or h, "devid": "FGT60F0000000001", "pid": 1000, "wan_if": "igb0", **ex, **extra}
        self.weight = weight
        self.kinds = kinds or DEFAULT_KINDS[fmt]
        ks = sorted(self.kinds)
        tot = sum(self.kinds[k] for k in ks)
        acc, self._cum = 0.0, []
        for k in ks:
            acc += self.kinds[k] / tot
            self._cum.append((acc, k))

    def pick_kind(self, rng: random.Random) -> str:
        r = rng.random()
        for c, k in self._cum:
            if r <= c:
                return k
        return self._cum[-1][1]

    def render(self, ev: dict) -> list[tuple[str, dict, dict]]:
        return self.mod.render(ev, self.dev)


def parse_mix(s: str) -> list[Device]:
    devs = []
    for part in s.split(","):
        name, _, w = part.partition(":")
        name = name.strip()
        if name not in REGISTRY:
            raise SystemExit(f"unknown format {name!r}; known: {', '.join(REGISTRY)}")
        devs.append(Device(name, name, weight=float(w or 1)))
    return devs


# ------------------------------------------------------------------------------------------------ incidents
def _find(devs: list[Device], ids: list[str]) -> list[Device]:
    m = {d.id: d for d in devs}
    return [m[i] for i in ids if i in m]


def incident_events(spec: dict, devs: list[Device], start_ms: int, rng: random.Random) -> list[tuple[int, int, Device, dict]]:
    """Return (ts, tiebreak, device, canonical-event) tuples for one incident."""
    t0 = start_ms + int(spec["at_s"] * 1000)
    dur = int(spec.get("duration_s", 60) * 1000)
    typ = spec["type"]
    tag = spec.get("tag", typ)
    out: list[tuple[int, int, Device, dict]] = []
    targets = _find(devs, spec.get("devices", []))
    if not targets:
        return out
    n = 0

    def add(ts: int, dv: Device, ev: dict) -> None:
        nonlocal n
        ev["tag"] = ev.get("tag") or tag
        out.append((ts, n, dv, ev))
        n += 1

    if typ == "port_scan":
        src = spec.get("src", core.SCANNER_IP)
        victim = spec.get("victim", "10.1.2.15")
        ports = int(spec.get("ports", 1500))
        for dv in targets:
            for i in range(ports):
                ts = t0 + (i * dur) // ports + rng.randrange(0, 20)
                if dv.fmt == "suricata":
                    if i % 50 == 0:
                        add(ts, dv, core.alert(ts, src, core.eport(rng), victim, 1 + i, "TCP", 2009582, "ET SCAN NMAP -sS window 1024", "Attempted Information Leak", 2))
                    continue
                if dv.fmt == "fortigate" and i % 100 == 0:
                    add(ts, dv, {**core.alert(ts, src, 0, victim, 0, "TCP", 0, "tcp_port_scan", "anomaly", 1), "tag": "scan_alert"})
                add(ts, dv, core.conn(ts, src, core.eport(rng), victim, 1 + i, 6, False, policy=0))
    elif typ == "ssh_bruteforce":
        src = spec.get("src", core.BRUTE_IP)
        victim = spec.get("victim", "10.1.2.22")
        attempts = int(spec.get("attempts", 600))
        users = ["admin", "root", "administrator", "test", "oracle", "ubuntu", "postgres", "guest"]
        for i in range(attempts):
            ts = t0 + (i * dur) // attempts + rng.randrange(0, 40)
            dv = targets[i % len(targets)]
            if dv.fmt == "windows":
                add(ts, dv, core.auth(ts, users[rng.randrange(len(users))], src, dv.dev["host"], False, 10, core.eport(rng)))
            elif dv.fmt == "asa" and i % 5 == 0:
                add(ts, dv, core.auth(ts, users[rng.randrange(len(users))], src, "ASA", False, 3, i))
            else:
                add(ts, dv, core.conn(ts, src, core.eport(rng), victim, 22, 6, False, policy=0))
    elif typ == "exfiltration":
        src = spec.get("src", core.EXFIL_SRC)
        dst = spec.get("dst", core.EXFIL_DST)
        sessions = int(spec.get("sessions", 40))
        per = int(spec.get("bytes_total_mb", 600) * 1_000_000 / sessions)
        for i in range(sessions):
            ts = t0 + (i * dur) // sessions + rng.randrange(0, 500)
            for dv in targets:
                if dv.fmt == "squid":
                    add(ts, dv, core.http(ts, src, "CONNECT", f"{dst}:443", 200, per, "svc-backup", dst, 4000 + rng.randrange(5000), "TCP_TUNNEL", "-"))
                else:
                    sp = core.eport(rng)
                    add(ts, dv, core.conn(ts, src, sp, dst, 443, 6, True, per, rng.randrange(2000, 9000), per // 1400, 20 + per // 2_000_000,
                                          30 + rng.randrange(60), policy=2, closed=True))
    else:
        raise SystemExit(f"unknown incident type {typ!r}")
    return out


# ------------------------------------------------------------------------------------------------ core iterator
def iter_events(devices: list[Device], seed: int, start_ms: int, eps: float, count: int | None = None, duration_s: float | None = None,
                incidents: list[dict] | None = None) -> Iterator[tuple[Device, str, dict]]:
    """Yield (device, line, truth_record_without_n) in time order."""
    rng = random.Random(seed)
    inc_rng = random.Random(seed * 7919 + 1)
    inc: list[tuple[int, int, int, Device, dict]] = []
    for si, spec in enumerate(incidents or []):
        for ts, n, dv, ev in incident_events(spec, devices, start_ms, inc_rng):
            inc.append((ts, si, n, dv, ev))
    heapq.heapify(inc)
    cum, acc = [], 0.0
    tot = sum(d.weight for d in devices)
    for d in devices:
        acc += d.weight / tot
        cum.append((acc, d))
    total_ms = None if duration_s is None else int(duration_s * 1000)
    i = 0
    emitted = 0

    def emit(dv: Device, ev: dict):
        for line, exp, flags in dv.render(ev):
            rec = {"source": dv.fmt, "expect": exp}
            if ev.get("tag"):
                rec["tag"] = ev["tag"]
            if flags.get("time_assumed"):
                rec["assumed_time"] = True
            yield dv, line, rec

    while True:
        ts = start_ms + int(i * 1000 / eps)
        if count is not None and emitted >= count and not inc:
            break
        if total_ms is not None and ts - start_ms >= total_ms and not inc:
            break
        while inc and inc[0][0] <= ts:
            _, _, _, dv, ev = heapq.heappop(inc)
            for item in emit(dv, ev):
                emitted += 1
                yield item
        if (count is not None and emitted >= count) or (total_ms is not None and ts - start_ms >= total_ms):
            if not inc:
                break
            i += 1
            continue
        r = rng.random()
        dv = next(d for c, d in cum if r <= c) if r <= cum[-1][0] else cum[-1][1]
        for _try in range(8):
            ev = BASELINE[dv.pick_kind(rng)](rng, ts)
            ev["closed"] = rng.random() < 0.7
            if "closed" in ev and ev["k"] == "conn" and dv.fmt == "asa":
                ev["closed"] = rng.random() < 0.5
            items = list(emit(dv, ev))
            if items:
                for item in items:
                    emitted += 1
                    yield item
                break
        i += 1


def load_scenario(path: str | Path) -> dict:
    import yaml
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def scenario_devices(sc: dict) -> list[Device]:
    out = []
    for d in sc["devices"]:
        d = dict(d)
        out.append(Device(d.pop("id"), d.pop("format"), d.pop("host", None), d.pop("weight", 1.0), d.pop("kinds", None), **d))
    return out


def generate(mix: str | None = None, scenario: str | None = None, seed: int = 1, count: int | None = None, eps: float | None = None,
             duration_s: float | None = None, start: str | None = None) -> Iterator[tuple[Device, str, dict]]:
    """Library entry point used by tests, bench and analytics."""
    if scenario:
        sc = load_scenario(scenario)
        devs = scenario_devices(sc)
        return iter_events(devs, seed if seed is not None else sc.get("seed", 1), core.parse_start(start or sc.get("start", core.DEFAULT_START)),
                           eps or sc.get("baseline_eps", 2000), count, duration_s if duration_s is not None else sc.get("duration_s"),
                           sc.get("incidents"))
    devs = parse_mix(mix or "fortigate:30,asa:20,suricata:15,cef:10,pfsense:15,squid:10")
    return iter_events(devs, seed, core.parse_start(start or core.DEFAULT_START), eps or 1000, count or 1000, duration_s)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.loggen", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--start", default=None, help="simulated start, e.g. 2026-10-04T13:00:00Z")
    ap.add_argument("--mix", default=None, help="fortigate:30,asa:20,... (formats: %s)" % ",".join(REGISTRY))
    ap.add_argument("--scenario", default=None)
    ap.add_argument("--count", type=int, default=None, help="number of log lines (mix mode)")
    ap.add_argument("--eps", type=float, default=None, help="simulated events/second (controls timestamps, not wall-clock pacing)")
    ap.add_argument("--duration", type=float, default=None, help="simulated seconds")
    ap.add_argument("--out", default="-", help="log file ('-' = stdout)")
    ap.add_argument("--no-truth", action="store_true")
    ap.add_argument("--split", default=None, help="also write one file per format into this dir (for hint-based replay)")
    ap.add_argument("--heldout", choices=["mikrotik", "sophos_kv", "juniper_srx"], default=None, help="generate an unseen-source sample instead")
    ap.add_argument("--syslog", action="store_true", help="(mikrotik) prefix an RFC3164 header")
    args = ap.parse_args(argv)

    out = sys.stdout.buffer if args.out == "-" else open(args.out, "wb", buffering=1 << 20)
    truth = None if (args.no_truth or args.out == "-") else open(args.out + ".truth.jsonl", "wb", buffering=1 << 20)
    split: dict[str, Any] = {}
    n = 0
    if args.heldout:
        from .heldout import HELDOUT
        kw: dict[str, Any] = {"seed": args.seed, "n": args.count or 60}
        if args.heldout == "mikrotik":
            kw["syslog"] = args.syslog
        for line, exp in HELDOUT[args.heldout](**kw):
            out.write(line.encode() + b"\n")
            if truth:
                truth.write(json.dumps({"n": n, "source": args.heldout, "expect": exp}, separators=(",", ":")).encode() + b"\n")
            n += 1
    else:
        for dv, line, rec in generate(args.mix, args.scenario, args.seed, args.count, args.eps, args.duration, args.start):
            b = line.encode() + b"\n"
            out.write(b)
            if truth:
                rec["n"] = n
                truth.write(json.dumps(rec, separators=(",", ":")).encode() + b"\n")
            if args.split:
                f = split.get(dv.fmt)
                if f is None:
                    os.makedirs(args.split, exist_ok=True)
                    f = split[dv.fmt] = open(os.path.join(args.split, f"{dv.fmt}.log"), "wb")
                f.write(b)
            n += 1
    for f in (out, truth, *split.values()):
        if f and f is not sys.stdout.buffer:
            f.close()
    print(f"wrote {n} events", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
