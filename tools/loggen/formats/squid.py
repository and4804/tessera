"""Squid native access.log (illustrative)."""
from __future__ import annotations

NAME = "squid"
PACK = "squid.access"
KINDS = ("http",)
ACTIVITY = {"CONNECT": 1, "DELETE": 2, "GET": 3, "HEAD": 4, "OPTIONS": 5, "POST": 6, "PUT": 7, "TRACE": 8, "PATCH": 9}


def render(ev: dict, dev: dict, rng=None):
    ts = ev["ts"]
    user = ev["user"] or "-"
    hit = ev["result"] in ("TCP_HIT",)
    peer = "-" if hit or ev["result"] == "TCP_DENIED" else ev["dst"]
    hier = "HIER_NONE" if peer == "-" else "HIER_DIRECT"
    mime = ev["mime"]
    line = (f'{ts // 1000}.{ts % 1000:03d} {ev["elapsed"]:6d} {ev["client"]} {ev["result"]}/{ev["status"]} {ev["size"]} {ev["method"]} '
            f'{ev["url"]} {user} {hier}/{peer} {mime}')
    denied = ev["result"] == "TCP_DENIED"
    exp = {"class_uid": 4002, "activity_id": ACTIVITY.get(ev["method"], 99), "time": ts, "severity_id": 1,
           "action_id": 2 if denied else 1, "disposition_id": 2 if denied else 1, "src_endpoint.ip": ev["client"],
           "http_request.http_method": ev["method"], "http_request.url.text": ev["url"], "http_response.code": ev["status"],
           "traffic.bytes_in": ev["size"], "duration": ev["elapsed"]}
    if peer != "-":
        exp["dst_endpoint.ip"] = peer
    if ev["user"]:
        exp["actor.user.name"] = ev["user"]
    return [(line, exp, {})]
