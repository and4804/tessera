"""Shared primitives: topology, time formatting, event constructors."""
from __future__ import annotations

import random
import time

# ----------------------------------------------------------------------------------------------
# time helpers (cached per second; pure functions, deterministic, UTC only)
# ----------------------------------------------------------------------------------------------
_MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_cache: dict[tuple[str, int], str] = {}


def _tm(sec: int) -> time.struct_time:
    return time.gmtime(sec)


def _cached(kind: str, sec: int, fn) -> str:
    k = (kind, sec)
    v = _cache.get(k)
    if v is None:
        if len(_cache) > 4096:
            _cache.clear()
        v = _cache[k] = fn(_tm(sec))
    return v


def ymd_hms(ms: int, offset_s: int = 0) -> tuple[str, str]:
    """('2026-10-04', '13:21:07') in UTC+offset."""
    s = _cached("ymdhms%d" % offset_s, ms // 1000 + offset_s,
                lambda t: f"{t.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}")
    d, h = s.split(" ")
    return d, h


def iso_z(ms: int, frac: int = 3, suffix: str = "Z") -> str:
    base = _cached("iso", ms // 1000, lambda t: f"{t.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d}T{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}")
    f = ms % 1000
    if frac == 0:
        return base + suffix
    if frac == 3:
        return f"{base}.{f:03d}{suffix}"
    return f"{base}.{f:03d}{'0' * (frac - 3)}{suffix}"


def bsd_ts(ms: int, pad_day: str = " ") -> str:
    """RFC 3164: 'Oct  4 13:21:07'."""
    def f(t):
        day = f"{t.tm_mday:2d}" if pad_day == " " else f"{t.tm_mday:02d}"
        return f"{_MON[t.tm_mon - 1]} {day} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"
    return _cached("bsd" + pad_day, ms // 1000, f)


def asa_ts(ms: int) -> str:
    """Cisco ASA with `logging timestamp`: 'Oct 04 2026 13:21:07'."""
    return _cached("asa", ms // 1000, lambda t: f"{_MON[t.tm_mon - 1]} {t.tm_mday:02d} {t.tm_year:04d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}")


def parse_start(s: str) -> int:
    """'2026-10-04T13:00:00Z' -> epoch ms."""
    import calendar
    t = time.strptime(s.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
    return calendar.timegm(t) * 1000


DEFAULT_START = "2026-10-04T13:00:00Z"

# ----------------------------------------------------------------------------------------------
# topology (RFC 1918 inside, RFC 5737 documentation addresses for attackers)
# ----------------------------------------------------------------------------------------------
SCANNER_IP = "203.0.113.50"
BRUTE_IP = "198.51.100.77"
EXFIL_SRC = "10.1.1.42"
EXFIL_DST = "192.0.2.99"

EXTERNAL_IPS = [
    "142.250.77.14", "142.250.183.110", "172.217.160.78", "93.184.216.34", "151.101.1.69", "104.16.132.229",
    "13.107.42.14", "52.96.108.34", "20.190.159.4", "31.13.72.36", "157.240.22.35", "199.232.69.194",
    "23.45.200.17", "34.117.65.55", "54.239.28.85", "17.253.144.10", "185.199.108.153", "140.82.112.3",
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "104.18.32.47", "2.16.4.51", "40.126.31.71", "13.226.52.12", "35.186.224.25",
]
EXTERNAL_V6 = ["2607:f8b0:4004:c07::71", "2a00:1450:4001:81a::200e", "2620:1ec:46::48"]
DOMAINS = [
    "www.example.com", "mail.example.org", "update.vendor-sw.net", "cdn.static-assets.io", "api.cloudsvc.com",
    "login.corp-sso.com", "news.dailyreport.com", "docs.wiki-host.org", "img.photoshare.net", "video.streamly.tv",
    "repo.opensrc.dev", "telemetry.appstats.io", "files.sharebox.com", "search.finder.com", "shop.megastore.com",
]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "niaj", "olivia", "peggy"]
URL_PATHS = ["/", "/index.html", "/api/v1/items", "/static/app.js", "/img/logo.png", "/login", "/search?q=test", "/download/report.pdf", "/css/site.css"]
USER_AGENTS = ["Mozilla/5.0", "curl/8.4.0", "python-requests/2.31"]
SERVICES = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 25: "SMTP", 123: "NTP", 3389: "RDP", 445: "SMB", 8080: "HTTP-ALT", 993: "IMAPS"}
COMMON_PORTS = [80, 443, 443, 443, 53, 22, 25, 123, 8080, 993, 3389, 445]


def lan_ip(rng: random.Random) -> str:
    return f"10.1.1.{rng.randrange(10, 200)}"


def server_ip(rng: random.Random) -> str:
    return f"10.1.2.{rng.randrange(10, 40)}"


def ext_ip(rng: random.Random) -> str:
    return EXTERNAL_IPS[rng.randrange(len(EXTERNAL_IPS))]


def eport(rng: random.Random) -> int:
    return rng.randrange(32768, 61000)


# ----------------------------------------------------------------------------------------------
# canonical events (vendor-neutral). Renderers turn these into (line, truth) pairs.
# kinds: conn | auth | dns | http | alert
# ----------------------------------------------------------------------------------------------

def conn(ts: int, src: str, sport: int, dst: str, dport: int, proto: int = 6, allowed: bool = True, bout: int = 0, bin_: int = 0,
         pout: int = 0, pin: int = 0, dur: int = 0, policy: int = 1, tag: str | None = None, closed: bool = True) -> dict:
    return {"k": "conn", "ts": ts, "src": src, "sport": sport, "dst": dst, "dport": dport, "proto": proto, "allowed": allowed,
            "bout": bout, "bin": bin_, "pout": pout, "pin": pin, "dur": dur, "policy": policy, "tag": tag, "closed": closed}


def auth(ts: int, user: str, src: str, host: str, ok: bool, ltype: int = 3, port: int = 0, tag: str | None = None, domain: str = "CORP") -> dict:
    return {"k": "auth", "ts": ts, "user": user, "src": src, "host": host, "ok": ok, "ltype": ltype, "port": port, "tag": tag, "domain": domain}


def dns(ts: int, client: str, qname: str, qtype: str = "A", answer: str | None = None, tag: str | None = None) -> dict:
    return {"k": "dns", "ts": ts, "client": client, "qname": qname, "qtype": qtype, "answer": answer, "tag": tag}


def http(ts: int, client: str, method: str, url: str, status: int, size: int, user: str | None, dst: str, elapsed: int, result: str = "TCP_MISS",
         mime: str = "text/html", tag: str | None = None) -> dict:
    return {"k": "http", "ts": ts, "client": client, "method": method, "url": url, "status": status, "size": size, "user": user,
            "dst": dst, "elapsed": elapsed, "result": result, "mime": mime, "tag": tag}


def alert(ts: int, src: str, sport: int, dst: str, dport: int, proto: str, sid: int, sig: str, cat: str, sev: int, blocked: bool = False,
          tag: str | None = None) -> dict:
    return {"k": "alert", "ts": ts, "src": src, "sport": sport, "dst": dst, "dport": dport, "proto": proto, "sid": sid, "sig": sig,
            "cat": cat, "sev": sev, "blocked": blocked, "tag": tag}


PROTO_NAME = {1: "icmp", 6: "tcp", 17: "udp"}


def baseline_conn(rng: random.Random, ts: int) -> dict:
    """Typical outbound/inbound business connection."""
    r = rng.random()
    if r < 0.70:
        dport = COMMON_PORTS[rng.randrange(len(COMMON_PORTS))]
        proto = 17 if dport in (53, 123) else 6
        bout = rng.randrange(200, 20000)
        bin_ = rng.randrange(200, 400000)
        return conn(ts, lan_ip(rng), eport(rng), ext_ip(rng), dport, proto, True, bout, bin_,
                    max(1, bout // 800), max(1, bin_ // 1200), rng.randrange(1, 300), policy=rng.randrange(1, 6))
    if r < 0.85:  # inbound to server
        dport = (22, 443, 443, 80)[rng.randrange(4)]
        bout = rng.randrange(200, 5000)
        bin_ = rng.randrange(200, 50000)
        return conn(ts, ext_ip(rng), eport(rng), server_ip(rng), dport, 6, True, bout, bin_, 3 + bout // 900, 3 + bin_ // 1200,
                    rng.randrange(1, 120), policy=rng.randrange(6, 9))
    if r < 0.95:  # internet noise denied
        return conn(ts, ext_ip(rng), eport(rng), server_ip(rng), (23, 445, 3389, 22, 8080)[rng.randrange(5)], 6, False, policy=0)
    return conn(ts, lan_ip(rng), eport(rng), ext_ip(rng), 443, 6, False, policy=0)  # blocked by policy


def baseline_auth(rng: random.Random, ts: int) -> dict:
    ok = rng.random() < 0.94
    return auth(ts, USERS[rng.randrange(len(USERS))], lan_ip(rng), "DC01", ok, (3, 2, 10)[rng.randrange(3)], eport(rng))


def baseline_dns(rng: random.Random, ts: int) -> dict:
    qt = ("A", "A", "A", "AAAA", "MX", "TXT")[rng.randrange(6)]
    return dns(ts, lan_ip(rng), DOMAINS[rng.randrange(len(DOMAINS))], qt, ext_ip(rng) if qt == "A" else None)


def baseline_http(rng: random.Random, ts: int) -> dict:
    dom = DOMAINS[rng.randrange(len(DOMAINS))]
    m = ("GET", "GET", "GET", "POST", "GET", "HEAD", "CONNECT")[rng.randrange(7)]
    if m == "CONNECT":
        url = f"{dom}:443"
        status = 200
    else:
        url = f"http://{dom}{URL_PATHS[rng.randrange(len(URL_PATHS))]}"
        status = (200, 200, 200, 304, 404, 302, 403, 500)[rng.randrange(8)]
    denied = status == 403 and rng.random() < 0.5
    return http(ts, lan_ip(rng), m, url, status, rng.randrange(0, 600000), USERS[rng.randrange(len(USERS))] if rng.random() < 0.6 else None,
                ext_ip(rng), rng.randrange(1, 4000), "TCP_DENIED" if denied else ("TCP_MISS", "TCP_HIT", "TCP_TUNNEL" if m == "CONNECT" else "TCP_MISS")[rng.randrange(3)],
                ("text/html", "application/json", "image/png", "-")[rng.randrange(4)])


def baseline_alert(rng: random.Random, ts: int) -> dict:
    sigs = [(2013504, "ET POLICY GNU/Linux APT User-Agent Outbound", "Not Suspicious Traffic", 3),
            (2024897, "ET MALWARE Possible Win32/Agent Checkin", "A Network Trojan was detected", 1),
            (2001219, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2),
            (2100498, "GPL ATTACK_RESPONSE id check returned root", "Potentially Bad Traffic", 2)]
    s = sigs[rng.randrange(len(sigs))]
    return alert(ts, ext_ip(rng), eport(rng), server_ip(rng), (80, 443, 22)[rng.randrange(3)], "TCP", s[0], s[1], s[2], s[3], rng.random() < 0.2)


BASELINE = {"conn": baseline_conn, "auth": baseline_auth, "dns": baseline_dns, "http": baseline_http, "alert": baseline_alert}
