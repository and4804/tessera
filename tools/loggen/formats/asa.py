"""Cisco ASA syslog (illustrative). Time carries a year (`logging timestamp`)."""
from __future__ import annotations

from ..core import asa_ts

NAME = "asa"
PACK = "cisco.asa"
KINDS = ("conn", "auth")
_SEV = {"0": 6, "1": 5, "2": 5, "3": 4, "4": 3, "5": 2, "6": 1, "7": 1}
_PROTO_NUM = {"tcp": 6, "udp": 17}


def _if(ip: str) -> str:
    return "inside" if ip.startswith("10.1.1.") else ("dmz" if ip.startswith("10.1.2.") or ip.startswith("10.1.3.") else "outside")


def _hdr(ev, dev, sev: int, msgid: int) -> str:
    return f'<{160 + sev}>{asa_ts(ev["ts"])} {dev["host"]} : %ASA-{sev}-{msgid}: '


def _base(ev, dev, sev: str, activity: int, action: int) -> dict:
    return {"class_uid": 4001, "activity_id": activity, "time": ev["ts"] // 1000 * 1000, "severity_id": _SEV[sev], "action_id": action,
            "disposition_id": action, "device.hostname": dev["host"], "metadata.original_time": asa_ts(ev["ts"])}


def _hms(sec: int) -> str:
    return f"{sec // 3600}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


def render(ev: dict, dev: dict, rng=None):
    ts = ev["ts"]
    if ev["k"] == "auth":  # failed VPN/AAA auth
        if ev["ok"]:
            return []
        msgid = 113005 if ev["port"] % 2 == 0 else 113015
        if msgid == 113005:
            body = f'AAA user authentication Rejected : reason = Invalid password : server = 10.1.2.5 : user = {ev["user"]} : user IP = {ev["src"]}'
        else:
            body = f'AAA user authentication Rejected : reason = User was not found : local database : user = {ev["user"]} : user IP = {ev["src"]}'
        exp = {"class_uid": 3002, "activity_id": 1, "time": ts // 1000 * 1000, "severity_id": 1, "status_id": 2, "user.name": ev["user"],
               "src_endpoint.ip": ev["src"], "device.hostname": dev["host"], "metadata.original_time": asa_ts(ts)}
        return [(_hdr(ev, dev, 6, msgid) + body, exp, {})]
    src, dst, sport, dport = ev["src"], ev["dst"], ev["sport"], ev["dport"]
    proto = "tcp" if ev["proto"] == 6 else "udp"
    PROTO = proto.upper()
    sif, dif = _if(src), _if(dst)
    inbound = sif == "outside" or (sif == "dmz" and dif == "inside")
    cid = (ts * 7 + sport) % 9000000 + 1000000
    if not ev["allowed"]:
        r = (sport + dport) % 3
        if r == 0:
            body = f'Deny {proto} src {sif}:{src}/{sport} dst {dif}:{dst}/{dport} by access-group "{sif}_in" [0x0, 0x0]'
            exp = _base(ev, dev, "4", 5, 2)
            msgid, sev = 106023, 4
        elif r == 1:
            body = f'access-list {sif}_in denied {proto} {sif}/{src}({sport}) -> {dif}/{dst}({dport}) hit-cnt 1 first hit [0x8c4b2a1, 0x0]'
            exp = _base(ev, dev, "6", 5, 2)
            msgid, sev = 106100, 6
        else:
            body = f'{PROTO} access denied by ACL from {src}/{sport} to {dif}:{dst}/{dport}'
            exp = _base(ev, dev, "4", 5, 2)
            msgid, sev = 710003, 4
        exp.update({"src_endpoint.ip": src, "src_endpoint.port": sport, "dst_endpoint.ip": dst, "dst_endpoint.port": dport,
                    "connection_info.protocol_name": proto, "connection_info.protocol_num": _PROTO_NUM[proto]})
        if msgid != 710003:
            exp["src_endpoint.interface_name"] = sif
            exp["dst_endpoint.interface_name"] = dif
        else:
            exp["dst_endpoint.interface_name"] = dif
        return [(_hdr(ev, dev, sev, msgid) + body, exp, {})]
    udp = proto == "udp"
    if not ev["closed"]:  # Built
        msgid = 302015 if udp else 302013
        d = "inbound" if inbound else "outbound"
        # ASA prints the *foreign* host first for outbound connections
        fa, fp, fi, ta, tp, ti = (src, sport, sif, dst, dport, dif) if inbound else (dst, dport, dif, src, sport, sif)
        body = f'Built {d} {PROTO} connection {cid} for {fi}:{fa}/{fp} ({fa}/{fp}) to {ti}:{ta}/{tp} ({ta}/{tp})'
        exp = _base(ev, dev, "6", 1, 1)
        exp.update({"src_endpoint.ip": src, "src_endpoint.port": sport, "src_endpoint.interface_name": sif,
                    "dst_endpoint.ip": dst, "dst_endpoint.port": dport, "dst_endpoint.interface_name": dif,
                    "connection_info.protocol_name": proto, "connection_info.protocol_num": _PROTO_NUM[proto],
                    "connection_info.uid": str(cid)})
        return [(_hdr(ev, dev, 6, msgid) + body, exp, {})]
    msgid = 302016 if udp else 302014
    # Teardown does not say inbound/outbound: endpoints follow ASA's "for ... to ..." order (documented limitation).
    fa, fp, fi, ta, tp, ti = (src, sport, sif, dst, dport, dif) if inbound else (dst, dport, dif, src, sport, sif)
    total = ev["bout"] + ev["bin"]
    tail = "" if udp else " TCP FINs"
    body = f'Teardown {PROTO} connection {cid} for {fi}:{fa}/{fp} to {ti}:{ta}/{tp} duration {_hms(ev["dur"])} bytes {total}{tail}'
    exp = _base(ev, dev, "6", 2, 1)
    exp.update({"src_endpoint.ip": fa, "src_endpoint.port": fp, "src_endpoint.interface_name": fi,
                "dst_endpoint.ip": ta, "dst_endpoint.port": tp, "dst_endpoint.interface_name": ti,
                "connection_info.protocol_name": proto, "connection_info.protocol_num": _PROTO_NUM[proto],
                "connection_info.uid": str(cid), "traffic.bytes": total})
    return [(_hdr(ev, dev, 6, msgid) + body, exp, {})]
