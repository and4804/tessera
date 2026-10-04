"""Held-out sources used ONLY for onboarding demo + evaluator. There is deliberately NO shipped pack for any of them.

Each generator yields (line, expect) where `expect` is the truth OCSF mapping a hand-written pack should produce.
Formats are illustrative (R12).
"""
from __future__ import annotations

import random
from collections.abc import Iterator

from .core import DEFAULT_START, PROTO_NAME, bsd_ts, eport, ext_ip, iso_z, lan_ip, parse_start, ymd_hms

# ----------------------------------------------------------------------------------------------- MikroTik
_FLAGS = ["SYN", "ACK", "SYN,ACK", "FIN,ACK", "RST", "PSH,ACK", "RST,ACK"]
_PREFIX = ["", "", "", "DROP-IN ", "ACCEPT-FWD ", "WAN-IN "]


def mikrotik(seed: int = 7, n: int = 60, syslog: bool = False, start: str = DEFAULT_START) -> Iterator[tuple[str, dict]]:
    rng = random.Random(seed)
    t0 = parse_start(start)
    macs = ["00:0c:29:aa:bb:cc", "52:54:00:12:34:56", "dc:a6:32:01:02:03", "b8:27:eb:11:22:33", "08:00:27:de:ad:01"]
    for i in range(n):
        ts = t0 + i * 700 + rng.randrange(0, 500)
        chain = ("forward", "input", "output", "forward")[rng.randrange(4)]
        proto = ("TCP", "TCP", "UDP", "ICMP")[rng.randrange(4)]
        if chain == "input":
            src, dst = ext_ip(rng) if rng.random() < 0.6 else "203.0.113.50", "192.168.88.1"
            ifin, ifout = "ether1", "(unknown 0)"
        elif chain == "output":
            src, dst = "192.168.88.1", ext_ip(rng)
            ifin, ifout = "(unknown 0)", "ether1"
        else:
            src, dst = f"192.168.88.{rng.randrange(2, 250)}", ext_ip(rng)
            ifin, ifout = "bridge", "ether1"
        mac = macs[rng.randrange(len(macs))]
        sp, dp = eport(rng), (443, 80, 53, 22, 8291, 123)[rng.randrange(6)]
        prefix = _PREFIX[rng.randrange(len(_PREFIX))]
        len_ = rng.randrange(40, 1500)
        if proto == "ICMP":
            body = f"proto ICMP (type 8, code 0), {src}->{dst}, len {len_}"
        else:
            pr = f"TCP ({_FLAGS[rng.randrange(len(_FLAGS))]})" if proto == "TCP" else "UDP"
            body = f"proto {pr}, {src}:{sp}->{dst}:{dp}, len {len_}"
            if rng.random() < 0.08:
                body = body.replace(f", len {len_}", f", NAT {src}:{sp}->(203.0.113.1:{sp})->{dst}:{dp}, len {len_}")
        line = f"firewall,info {prefix}{chain}: in:{ifin} out:{ifout}, src-mac {mac}, {body}"
        exp = {"class_uid": 4001, "activity_id": 6, "severity_id": 1, "src_endpoint.ip": src, "dst_endpoint.ip": dst, "src_endpoint.mac": mac,
               "connection_info.protocol_name": proto.lower(), "connection_info.direction_id": {"input": 1, "output": 2, "forward": 3}[chain],
               "traffic.bytes": len_, "src_endpoint.interface_name": ifin}
        if ifout != "(unknown 0)":
            exp["dst_endpoint.interface_name"] = ifout
        if proto != "ICMP":
            exp["src_endpoint.port"] = sp
            exp["dst_endpoint.port"] = dp
        if syslog:
            line = f"<134>{bsd_ts(ts)} MikroTik {line}"
        yield line, exp


# ----------------------------------------------------------------------------------------------- Sophos-style kv
def sophos_kv(seed: int = 11, n: int = 60, start: str = DEFAULT_START) -> Iterator[tuple[str, dict]]:
    rng = random.Random(seed)
    t0 = parse_start(start)
    users = ["alice", "bob", "carol", ""]
    for i in range(n):
        ts = t0 + i * 900
        d, t = ymd_hms(ts)
        allowed = rng.random() < 0.8
        proto = ("TCP", "TCP", "UDP")[rng.randrange(3)]
        src, dst = lan_ip(rng), ext_ip(rng)
        sp, dp = eport(rng), (443, 80, 53, 22)[rng.randrange(4)]
        user = users[rng.randrange(4)]
        sb, rb = rng.randrange(100, 90000), rng.randrange(100, 900000)
        sp_, rp_ = 1 + sb // 900, 1 + rb // 1200
        line = (f'date={d} time={t} timezone="UTC" device_name="XGS2100" device_id=C1234567890 log_id=010101600001 log_type="Firewall" '
                f'log_component="Firewall Rule" log_subtype="{"Allowed" if allowed else "Denied"}" status="{"Allow" if allowed else "Deny"}" '
                f'priority=Information duration={rng.randrange(0, 300)} fw_rule_id={rng.randrange(1, 9)} user_name="{user}" '
                f'in_interface="Port2" out_interface="Port1" src_mac=00:0c:29:aa:bb:cc src_ip={src} dst_ip={dst} protocol="{proto}" '
                f'src_port={sp} dst_port={dp} sent_pkts={sp_} recv_pkts={rp_} sent_bytes={sb} recv_bytes={rb}')
        dur = int(line.split("duration=")[1].split(" ")[0])
        exp = {"class_uid": 4001, "activity_id": 6, "time": ts, "severity_id": 1, "action_id": 1 if allowed else 2,
               "disposition_id": 1 if allowed else 2, "src_endpoint.ip": src, "src_endpoint.port": sp,
               "dst_endpoint.ip": dst, "dst_endpoint.port": dp, "connection_info.protocol_name": proto.lower(), "traffic.bytes_out": sb,
               "traffic.bytes_in": rb, "traffic.packets_out": sp_, "traffic.packets_in": rp_, "duration": dur * 1000,
               "src_endpoint.interface_name": "Port2", "dst_endpoint.interface_name": "Port1", "src_endpoint.mac": "00:0c:29:aa:bb:cc",
               "device.hostname": "XGS2100"}
        if user:
            exp["user.name"] = user
        yield line, exp


# ----------------------------------------------------------------------------------------------- Juniper SRX-style RFC 5424 SD
def juniper_srx(seed: int = 13, n: int = 60, start: str = DEFAULT_START) -> Iterator[tuple[str, dict]]:
    rng = random.Random(seed)
    t0 = parse_start(start)
    for i in range(n):
        ts = t0 + i * 800
        proto = (6, 6, 17)[rng.randrange(3)]
        src, dst = lan_ip(rng), ext_ip(rng)
        sp, dp = eport(rng), (443, 80, 53)[rng.randrange(3)]
        sb, rb = rng.randrange(100, 90000), rng.randrange(100, 900000)
        pc, ps = 1 + sb // 900, 1 + rb // 1200
        el = rng.randrange(0, 200)
        close = rng.random() < 0.8
        tag = "RT_FLOW_SESSION_CLOSE" if close else "RT_FLOW_SESSION_CREATE"
        sd = (f'[junos@2636.1.1.1.2.129 {"reason=" + chr(34) + "TCP FIN" + chr(34) + " " if close else ""}source-address="{src}" source-port="{sp}" '
              f'destination-address="{dst}" destination-port="{dp}" connection-tag="0" service-name="junos-https" '
              f'nat-source-address="203.0.113.1" nat-source-port="{sp}" nat-destination-address="{dst}" nat-destination-port="{dp}" '
              f'src-nat-rule-name="None" dst-nat-rule-name="None" protocol-id="{proto}" policy-name="allow-out" '
              f'source-zone-name="trust" destination-zone-name="untrust" session-id-32="{(ts * 7) % 99999999}"')
        if close:
            sd += (f' packets-from-client="{pc}" bytes-from-client="{sb}" packets-from-server="{ps}" bytes-from-server="{rb}" '
                   f'elapsed-time="{el}"')
        sd += ' application="UNKNOWN" nested-application="UNKNOWN" username="N/A" roles="N/A" packet-incoming-interface="ge-0/0/1.0" encrypted="UNKNOWN"]'
        line = f"<14>1 {iso_z(ts, 3)} SRX-1 RT_FLOW - {tag} {sd}"
        exp = {"class_uid": 4001, "activity_id": 6, "time": ts, "severity_id": 1, "action_id": 1, "src_endpoint.ip": src, "src_endpoint.port": sp,
               "dst_endpoint.ip": dst, "dst_endpoint.port": dp, "connection_info.protocol_num": proto,
               "connection_info.protocol_name": PROTO_NAME[proto], "connection_info.uid": str((ts * 7) % 99999999),
               "device.hostname": "SRX-1"}
        if close:
            exp.update({"traffic.bytes_out": sb, "traffic.bytes_in": rb, "traffic.packets_out": pc, "traffic.packets_in": ps,
                        "duration": el * 1000})
        yield line, exp


HELDOUT = {"mikrotik": mikrotik, "sophos_kv": sophos_kv, "juniper_srx": juniper_srx}
