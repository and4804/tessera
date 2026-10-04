"""dnsmasq query log over RFC 3164 syslog (no year => time_assumed) (illustrative)."""
from __future__ import annotations

from ..core import bsd_ts

NAME = "dnsmasq"
PACK = "dns.dnsmasq"
KINDS = ("dns",)


def render(ev: dict, dev: dict, rng=None):
    ts = ev["ts"]
    pre = f'<30>{bsd_ts(ts)} {dev["host"]} dnsmasq[{dev["pid"]}]: '
    out = []
    q = {"class_uid": 4003, "activity_id": 1, "time": ts, "severity_id": 1, "query.hostname": ev["qname"], "query.type": ev["qtype"],
         "src_endpoint.ip": ev["client"], "device.hostname": dev["host"]}
    out.append((f'{pre}query[{ev["qtype"]}] {ev["qname"]} from {ev["client"]}', q, {"time_assumed": True}))
    if ev["answer"]:
        r = {"class_uid": 4003, "activity_id": 2, "time": ts, "severity_id": 1, "query.hostname": ev["qname"], "device.hostname": dev["host"]}
        out.append((f'{pre}reply {ev["qname"]} is {ev["answer"]}', r, {"time_assumed": True}))
    return out
