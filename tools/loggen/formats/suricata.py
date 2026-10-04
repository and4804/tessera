"""Suricata EVE JSON (illustrative)."""
from __future__ import annotations

import json

from ..core import iso_z

NAME = "suricata"
PACK = "suricata.eve"
KINDS = ("alert", "conn")
_SEV = {1: 4, 2: 3, 3: 2}


def _ts(ms: int) -> str:
    return iso_z(ms, 3, "000+0000")  # Suricata style: 2026-10-04T13:21:07.123000+0000


def render(ev: dict, dev: dict, rng=None):
    ts = ev["ts"]
    if ev["k"] == "alert":
        obj = {"timestamp": _ts(ts), "flow_id": 1000000000 + (ts * 31 + ev["sport"]) % 900000000, "in_iface": "eth0", "event_type": "alert",
               "src_ip": ev["src"], "src_port": ev["sport"], "dest_ip": ev["dst"], "dest_port": ev["dport"], "proto": ev["proto"],
               "alert": {"action": "blocked" if ev["blocked"] else "allowed", "gid": 1, "signature_id": ev["sid"], "rev": 3,
                         "signature": ev["sig"], "category": ev["cat"], "severity": ev["sev"]}, "host": dev["host"]}
        a = 2 if ev["blocked"] else 1
        exp = {"class_uid": 2004, "activity_id": 1, "time": ts, "severity_id": _SEV[ev["sev"]], "action_id": a, "disposition_id": a,
               "finding_info.title": ev["sig"], "finding_info.uid": str(ev["sid"]), "src_endpoint.ip": ev["src"],
               "src_endpoint.port": ev["sport"], "dst_endpoint.ip": ev["dst"], "dst_endpoint.port": ev["dport"],
               "connection_info.protocol_name": ev["proto"].lower(), "device.hostname": dev["host"]}
        return [(json.dumps(obj, separators=(",", ":")), exp, {})]
    if not ev["allowed"]:
        return []
    proto = "TCP" if ev["proto"] == 6 else "UDP"
    obj = {"timestamp": _ts(ts), "flow_id": 1000000000 + (ts * 17 + ev["sport"]) % 900000000, "in_iface": "eth0", "event_type": "flow",
           "src_ip": ev["src"], "src_port": ev["sport"], "dest_ip": ev["dst"], "dest_port": ev["dport"], "proto": proto,
           "flow": {"pkts_toserver": ev["pout"], "pkts_toclient": ev["pin"], "bytes_toserver": ev["bout"], "bytes_toclient": ev["bin"],
                    "start": _ts(ts - ev["dur"] * 1000), "end": _ts(ts), "age": ev["dur"], "state": "closed", "reason": "timeout", "alerted": False},
           "host": dev["host"]}
    exp = {"class_uid": 4001, "activity_id": 6, "time": ts, "severity_id": 1, "src_endpoint.ip": ev["src"], "src_endpoint.port": ev["sport"],
           "dst_endpoint.ip": ev["dst"], "dst_endpoint.port": ev["dport"], "connection_info.protocol_name": proto.lower(),
           "traffic.bytes_out": ev["bout"], "traffic.bytes_in": ev["bin"], "traffic.packets_out": ev["pout"],
           "traffic.packets_in": ev["pin"], "duration": ev["dur"] * 1000, "device.hostname": dev["host"]}
    return [(json.dumps(obj, separators=(",", ":")), exp, {})]
