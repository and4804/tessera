"""FortiGate key=value over syslog (illustrative)."""
from __future__ import annotations

from ..core import PROTO_NAME, SERVICES, ymd_hms

NAME = "fortigate"
PACK = "fortinet.fortigate"
KINDS = ("conn", "alert")
TZ_OFF = 19800  # +0530
_LEVEL_SEV = {"debug": 1, "information": 1, "notice": 1, "warning": 2, "error": 3, "alert": 4, "critical": 5, "emergency": 6}


def _intf(ip: str) -> str:
    return "lan" if ip.startswith("10.1.1.") else ("dmz" if ip.startswith("10.1.2.") or ip.startswith("10.1.3.") else "wan1")


def render(ev: dict, dev: dict):
    ts = ev["ts"]
    d, t = ymd_hms(ts, TZ_OFF)
    head = f'<{189 if ev["k"] == "conn" and ev["allowed"] else 188}>date={d} time={t} devname="{dev["host"]}" devid="{dev["devid"]}"'
    if ev["k"] == "alert" or ev.get("tag") == "scan_alert":
        src, dst = ev["src"], ev["dst"]
        attack = ev.get("sig") or "tcp_port_scan"
        logid = "0720018432"
        line = (f'{head} logid="{logid}" type="utm" subtype="anomaly" eventtype="anomaly" level="alert" vd="root" '
                f'eventtime={ts * 1000000} tz="+0530" severity="critical" srcip={src} dstip={dst} srcintf="{_intf(src)}" '
                f'dstintf="{_intf(dst)}" sessionid=0 action="detected" proto=6 service="tcp" attack="{attack}" count=1 '
                f'msg="anomaly: {attack}, 1 > threshold 1"')
        exp = {"class_uid": 2004, "activity_id": 1, "time": ts, "severity_id": 4, "finding_info.title": attack,
               "finding_info.uid": logid, "src_endpoint.ip": src, "dst_endpoint.ip": dst, "device.hostname": dev["host"]}
        return [(line, exp, {})]
    src, dst = ev["src"], ev["dst"]
    allowed = ev["allowed"]
    action = ("close" if ev["closed"] else "accept") if allowed else "deny"
    level = "notice" if allowed else "warning"
    svc = SERVICES.get(ev["dport"], "ALL")
    parts = [head, f'logid="{"0000000013" if allowed else "0000000011"}" type="traffic" subtype="forward" level="{level}" vd="root" '
             f'eventtime={ts * 1000000} tz="+0530" srcip={src} srcport={ev["sport"]} srcintf="{_intf(src)}" '
             f'dstip={dst} dstport={ev["dport"]} dstintf="{_intf(dst)}" proto={ev["proto"]} action="{action}" '
             f'policyid={ev["policy"]} service="{svc}"']
    exp = {"class_uid": 4001, "activity_id": 6, "time": ts, "severity_id": _LEVEL_SEV[level],
           "action_id": 1 if allowed else 2, "disposition_id": 1 if allowed else 2,
           "src_endpoint.ip": src, "src_endpoint.port": ev["sport"], "src_endpoint.interface_name": _intf(src),
           "dst_endpoint.ip": dst, "dst_endpoint.port": ev["dport"], "dst_endpoint.interface_name": _intf(dst),
           "connection_info.protocol_num": ev["proto"], "connection_info.protocol_name": PROTO_NAME[ev["proto"]],
           "device.hostname": dev["host"], "metadata.original_time": f"{d} {t}"}
    if allowed:
        parts.append(f'duration={ev["dur"]} sentbyte={ev["bout"]} rcvdbyte={ev["bin"]} sentpkt={ev["pout"]} rcvdpkt={ev["pin"]}')
        exp.update({"duration": ev["dur"] * 1000, "traffic.bytes_out": ev["bout"], "traffic.bytes_in": ev["bin"],
                    "traffic.packets_out": ev["pout"], "traffic.packets_in": ev["pin"]})
    return [(" ".join(parts), exp, {})]
