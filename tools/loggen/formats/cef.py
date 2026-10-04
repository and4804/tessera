"""Generic CEF firewall over RFC 3164 syslog (illustrative). CEF `in`/`out` are relative to src->dst."""
from __future__ import annotations

from ..core import PROTO_NAME, SERVICES, bsd_ts

NAME = "cef"
PACK = "cef.generic_firewall"
KINDS = ("conn",)
SEV_MAP = {"0": 2, "1": 2, "2": 2, "3": 2, "4": 3, "5": 3, "6": 3, "7": 4, "8": 4, "9": 5, "10": 5}


def _esc_ext(v: str) -> str:
    return v.replace("\\", "\\\\").replace("=", "\\=")


def render(ev: dict, dev: dict, rng=None):
    ts = ev["ts"]
    allowed = ev["allowed"]
    sev = 3 if allowed else 5
    proto = PROTO_NAME[ev["proto"]].upper()
    ext = (f'rt={ts} src={ev["src"]} spt={ev["sport"]} dst={ev["dst"]} dpt={ev["dport"]} proto={proto} act={"allow" if allowed else "deny"} '
           f'deviceInboundInterface={"lan" if ev["src"].startswith("10.") else "wan"} deviceOutboundInterface={"wan" if ev["src"].startswith("10.") else "dmz"} '
           f'dvchost={dev["host"]} app={_esc_ext(SERVICES.get(ev["dport"], "other"))}')
    exp = {"class_uid": 4001, "activity_id": 6, "time": ts, "severity_id": SEV_MAP[str(sev)], "action_id": 1 if allowed else 2,
           "disposition_id": 1 if allowed else 2, "src_endpoint.ip": ev["src"], "src_endpoint.port": ev["sport"],
           "dst_endpoint.ip": ev["dst"], "dst_endpoint.port": ev["dport"], "connection_info.protocol_name": proto.lower(),
           "src_endpoint.interface_name": "lan" if ev["src"].startswith("10.") else "wan",
           "dst_endpoint.interface_name": "wan" if ev["src"].startswith("10.") else "dmz", "device.hostname": dev["host"]}
    if allowed:
        ext += f' in={ev["bout"]} out={ev["bin"]} cnt=1'
        exp["traffic.bytes_out"] = ev["bout"]
        exp["traffic.bytes_in"] = ev["bin"]
    sigid, name = (100, "Traffic Allowed") if allowed else (101, "Traffic Denied")
    return [(f'<134>{bsd_ts(ts)} {dev["host"]} CEF:0|Acme|NetFW|2.1|{sigid}|{name}|{sev}|{ext}', exp, {})]
