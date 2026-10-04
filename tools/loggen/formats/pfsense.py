"""pfSense filterlog (positional CSV) over RFC 5424 syslog (illustrative)."""
from __future__ import annotations

from ..core import PROTO_NAME, iso_z

NAME = "pfsense"
PACK = "pfsense.filterlog"
KINDS = ("conn",)
_FLAGS = ("S", "SA", "A", "PA", "FA", "R")


def _v6(ip: str) -> bool:
    return ":" in ip


def render(ev: dict, dev: dict, rng=None):
    ts = ev["ts"]
    src, dst, sp, dp = ev["src"], ev["dst"], ev["sport"], ev["dport"]
    allowed = ev["allowed"]
    proto = PROTO_NAME[ev["proto"]]
    iface = dev.get("wan_if", "igb0")
    direction = "in"
    tracker = 1000000103 if not allowed else 1000000105
    head = f'5,,,{tracker},{iface},match,{"pass" if allowed else "block"},{direction}'
    length = 60 if ev["proto"] == 6 else 76
    ident = (ts * 13 + sp) % 65535
    if _v6(src):
        l3 = f'6,0x0,0x00000,64,{proto},{ev["proto"]},{length},{src},{dst}'
    else:
        l3 = f'4,0x0,,64,{ident},0,none,{ev["proto"]},{proto},{length},{src},{dst}'
    if ev["proto"] == 6:
        seq = (ts * 7919 + sp) % 4294967295
        l4 = f'{sp},{dp},0,S,{seq},,64240,,mss;sackOK;TS;nop;wscale'
    else:
        l4 = f'{sp},{dp},{length - 28}'
    msg = f"{head},{l3},{l4}"
    line = f'<134>1 {iso_z(ts, 3, "+00:00")} {dev["host"]} filterlog {dev["pid"]} - - {msg}'
    exp = {"class_uid": 4001, "activity_id": 6, "time": ts, "severity_id": 1 if allowed else 2, "action_id": 1 if allowed else 2,
           "disposition_id": 1 if allowed else 2, "src_endpoint.ip": src, "src_endpoint.port": sp, "src_endpoint.interface_name": iface,
           "dst_endpoint.ip": dst, "dst_endpoint.port": dp, "connection_info.protocol_num": ev["proto"],
           "connection_info.protocol_name": proto, "device.hostname": dev["host"]}
    return [(line, exp, {})]
