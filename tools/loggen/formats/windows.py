"""Windows Security 4624/4625 event XML, one event per line (illustrative)."""
from __future__ import annotations

from ..core import iso_z

NAME = "windows"
PACK = "windows.event_xml"
KINDS = ("auth",)
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def render(ev: dict, dev: dict, rng=None):
    ts = ev["ts"]
    ok = ev["ok"]
    eid = 4624 if ok else 4625
    stamp = iso_z(ts, 3, "4567Z")  # 7 fractional digits like real Windows (…07.1234567Z)
    rec = (ts * 3) % 90000000
    data = [("SubjectUserSid", "S-1-0-0"), ("SubjectUserName", "-"), ("SubjectDomainName", "-"), ("SubjectLogonId", "0x0"),
            ("TargetUserSid", "S-1-0-0" if not ok else "S-1-5-21-1-2-3-1105"), ("TargetUserName", ev["user"]),
            ("TargetDomainName", ev["domain"])]
    if not ok:
        data += [("Status", "0xc000006d"), ("FailureReason", "%%2313"), ("SubStatus", "0xc000006a")]
    data += [("LogonType", str(ev["ltype"])), ("LogonProcessName", "NtLmSsp "), ("AuthenticationPackageName", "NTLM"),
             ("WorkstationName", f'WS-{ev["src"].split(".")[-1]}'), ("IpAddress", ev["src"]), ("IpPort", str(ev["port"] or "-"))]
    ed = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data)
    xml = (f'<Event xmlns="{_NS}"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>'
           f'<EventID>{eid}</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>'
           f'<Keywords>{"0x8020000000000000" if ok else "0x8010000000000000"}</Keywords><TimeCreated SystemTime="{stamp}"/>'
           f'<EventRecordID>{rec}</EventRecordID><Correlation/><Execution ProcessID="652" ThreadID="4120"/><Channel>Security</Channel>'
           f'<Computer>{dev["host"]}</Computer><Security/></System><EventData>{ed}</EventData></Event>')
    exp = {"class_uid": 3002, "activity_id": 1, "time": ts, "severity_id": 1 if ok else 2, "status_id": 1 if ok else 2,
           "user.name": ev["user"], "user.domain": ev["domain"], "logon_type_id": ev["ltype"], "src_endpoint.ip": ev["src"],
           "src_endpoint.hostname": f'WS-{ev["src"].split(".")[-1]}', "dst_endpoint.hostname": dev["host"], "auth_protocol": "NTLM"}
    if ev["port"]:
        exp["src_endpoint.port"] = ev["port"]
    return [(xml, exp, {})]
