"""Generic LEEF 2.0 firewall events (illustrative)."""
from __future__ import annotations

from ..core import PROTO_NAME

NAME = "leef"
PACK = "leef.generic"
KINDS = ("conn",)
SEV_MAP = {"0": 2, "1": 2, "2": 2, "3": 2, "4": 3, "5": 3, "6": 3, "7": 4, "8": 4, "9": 5, "10": 5}


def render(ev: dict, dev: dict, rng=None):
    ts = ev["ts"]
    allowed = ev["allowed"]
    sev = 2 if allowed else 6
    proto = PROTO_NAME[ev["proto"]].upper()
    kv = [("devTime", str(ts)), ("devName", dev["host"]), ("src", ev["src"]), ("dst", ev["dst"]), ("srcPort", str(ev["sport"])),
          ("dstPort", str(ev["dport"])), ("proto", proto), ("action", "allow" if allowed else "deny"), ("sev", str(sev))]
    exp = {"class_uid": 4001, "activity_id": 6, "time": ts, "severity_id": SEV_MAP[str(sev)], "action_id": 1 if allowed else 2,
           "disposition_id": 1 if allowed else 2, "src_endpoint.ip": ev["src"], "src_endpoint.port": ev["sport"],
           "dst_endpoint.ip": ev["dst"], "dst_endpoint.port": ev["dport"], "connection_info.protocol_name": proto.lower(),
           "device.hostname": dev["host"]}
    if allowed:
        kv += [("srcBytes", str(ev["bout"])), ("dstBytes", str(ev["bin"])), ("srcPackets", str(ev["pout"])), ("dstPackets", str(ev["pin"]))]
        exp.update({"traffic.bytes_out": ev["bout"], "traffic.bytes_in": ev["bin"], "traffic.packets_out": ev["pout"], "traffic.packets_in": ev["pin"]})
    body = "^".join(f"{k}={v}" for k, v in kv)
    return [(f'LEEF:2.0|Acme|NetFW|2.1|{"FwAllow" if allowed else "FwDeny"}|^|{body}', exp, {})]
