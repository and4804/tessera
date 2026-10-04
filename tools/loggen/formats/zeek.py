"""Zeek conn.log TSV data lines (default field order; illustrative)."""
from __future__ import annotations

NAME = "zeek"
PACK = "zeek.conn"
KINDS = ("conn",)
FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes",
          "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
          "tunnel_parents"]
HEADER = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#open\t2026-10-04-13-00-00\n"
          "#fields\t" + "\t".join(FIELDS) + "\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]")
_SVC = {80: "http", 443: "ssl", 53: "dns", 22: "ssh", 25: "smtp", 123: "ntp"}
_UID = "CDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _uid(ts: int, sp: int) -> str:
    n = ts * 2654435761 + sp
    out = ["C"]
    for _ in range(16):
        out.append(_UID[n % len(_UID)])
        n //= len(_UID)
        n += 7
    return "".join(out)


def render(ev: dict, dev: dict, rng=None):
    ts = ev["ts"]
    proto = "tcp" if ev["proto"] == 6 else "udp"
    dur = ev["dur"] + (ts % 1000) / 1000.0 if ev["allowed"] else None
    state = "SF" if ev["allowed"] else "S0"
    svc = _SVC.get(ev["dport"], "-")
    dstr = f"{dur:.6f}" if dur is not None else "-"
    ob = str(ev["bout"]) if ev["allowed"] else "-"
    rb = str(ev["bin"]) if ev["allowed"] else "-"
    hist = "ShADadFf" if ev["allowed"] else "S"
    row = [f"{ts // 1000}.{ts % 1000:03d}000", _uid(ts, ev["sport"]), ev["src"], str(ev["sport"]), ev["dst"], str(ev["dport"]), proto, svc,
           dstr, ob, rb, state, "T" if ev["src"].startswith("10.") else "F", "F", "0", hist, str(ev["pout"] or 1), str(ev["bout"] + 40),
           str(ev["pin"]), str(ev["bin"] + 40), "(empty)"]
    exp = {"class_uid": 4001, "activity_id": 6, "time": ts, "severity_id": 1, "src_endpoint.ip": ev["src"], "src_endpoint.port": ev["sport"],
           "dst_endpoint.ip": ev["dst"], "dst_endpoint.port": ev["dport"], "connection_info.protocol_name": proto, "connection_info.uid": row[1],
           "traffic.packets_out": ev["pout"] or 1, "traffic.packets_in": ev["pin"]}
    if ev["allowed"]:
        exp.update({"duration": int(float(dstr) * 1000), "traffic.bytes_out": ev["bout"], "traffic.bytes_in": ev["bin"]})
    return [("\t".join(row), exp, {})]
