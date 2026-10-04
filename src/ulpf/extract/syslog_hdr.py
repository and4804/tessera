"""RFC 3164 / RFC 5424 syslog header parsing, once per event (§7.4). Pure; operates on ``str`` decoded with surrogateescape.

Exposes ``syslog.pri``, ``syslog.host``, ``syslog.app``, ``syslog.pid``, ``syslog.ts`` (ISO-8601 string) and
``syslog.time_quality``. RFC 3164 has no year or zone: the year is inferred from receive time with Dec/Jan rollover handling
and the quality is ``assumed_tz``.
"""
from __future__ import annotations

import calendar
import re
from typing import Any

_RFC5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\](?= |$)|(?:\[.*?\])+)(?: (.*))?$", re.S)
_RFC3164 = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) (.*)$", re.S)
_TAG = re.compile(r"^([\w./-]+)(?:\[(\d+)\])?:(?: (.*))?$", re.S)
_PRI = re.compile(r"^<(\d{1,3})>")
_MON = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}

_year_cache: tuple[int, int] = (0, 0)   # (recv_ms // 86_400_000 day, year)


def _year_of(recv_ms: int) -> int:
    global _year_cache
    day = recv_ms // 86_400_000
    if _year_cache[0] == day:
        return _year_cache[1]
    y = calendar.timegm((1970, 1, 1, 0, 0, 0))  # placeholder to keep calendar imported for timegm below
    del y
    from datetime import UTC, datetime

    year = datetime.fromtimestamp(recv_ms / 1000, tz=UTC).year
    _year_cache = (day, year)
    return year


def parse_syslog(text: str, recv_ms: int) -> tuple[str, dict[str, Any]]:
    """Return ``(message, ctx)``; ``ctx`` holds the ``syslog.*`` keys that were recognised (empty when there is no header)."""
    ctx: dict[str, Any] = {}
    rest = text
    if rest[:1] == "<":
        m = _PRI.match(rest)
        if m:
            ctx["syslog.pri"] = int(m.group(1))
            rest = rest[m.end():]
    c0 = rest[:1]
    if c0 == "1" and rest[1:2] == " ":
        m5 = _RFC5424.match(rest)
        if m5:
            ts, host, app, pid, _mid, sd, msg = m5.groups()
            ctx["syslog.ts"] = None if ts == "-" else ts
            if host != "-":
                ctx["syslog.host"] = host
            if app != "-":
                ctx["syslog.app"] = app
            if pid != "-":
                ctx["syslog.pid"] = pid
            sd = sd if sd != "-" else ""
            return ((sd + " " + (msg or "")).strip() if sd else (msg or "")), ctx
        return rest, ctx
    if "A" <= c0 <= "Z":
        m3 = _RFC3164.match(rest)
        if m3:
            mon, day, hh, mm, ss, tail = m3.groups()
            year = _year_of(recv_ms)
            try:
                ts = calendar.timegm((year, _MON[mon], int(day), int(hh), int(mm), int(ss)))
                if ts * 1000 > recv_ms + 86400_000 * 2:  # December log received in January -> previous year
                    year -= 1
            except (KeyError, ValueError):
                pass
            ctx["syslog.ts"] = f"{year:04d}-{_MON.get(mon, 1):02d}-{int(day):02d}T{hh}:{mm}:{ss}Z"
            ctx["syslog.time_quality"] = "assumed_tz"
            mt = _TAG.match(tail)
            if mt:  # "tag[pid]: msg" without host (pfSense quirk)
                ctx["syslog.app"], pid3, msg3 = mt.group(1), mt.group(2), mt.group(3) or ""
                if pid3:
                    ctx["syslog.pid"] = pid3
                return msg3, ctx
            parts = tail.split(" ", 1)
            if len(parts) == 2:
                ctx["syslog.host"] = parts[0]
                mt = _TAG.match(parts[1])
                if mt:
                    ctx["syslog.app"], pid3, msg3 = mt.group(1), mt.group(2), mt.group(3) or ""
                    if pid3:
                        ctx["syslog.pid"] = pid3
                    return msg3, ctx
                return parts[1], ctx
            return tail, ctx
    return rest, ctx  # no recognisable header (e.g. FortiGate "<189>date=...")
