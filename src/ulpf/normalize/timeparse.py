"""Hand-written fast time parsers (§7.7). ``strptime`` stays off the hot path: the common shapes parse via a precompiled regex plus
a per-day epoch cache, and anything unusual falls back to the stdlib with the same result. All results are epoch milliseconds (UTC)."""
from __future__ import annotations

import calendar
import re
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_MONTHS = {m.lower(): i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}

_day_cache: dict[tuple[int, int, int], int] = {}


def day_epoch_s(y: int, m: int, d: int) -> int | None:
    """Seconds since the epoch at 00:00:00 UTC of a *valid* calendar day, else None (cached)."""
    k = (y, m, d)
    v = _day_cache.get(k)
    if v is not None:
        return v
    try:
        date(y, m, d)
    except ValueError:
        return None
    if len(_day_cache) > 4096:
        _day_cache.clear()
    v = _day_cache[k] = calendar.timegm((y, m, d, 0, 0, 0))
    return v


_ISO_FAST = re.compile(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?(Z|[+-]\d\d:?\d\d)?")
_ISO_TRUNC = re.compile(r"^(.*?\.\d{6})\d+(.*)$")


def parse_iso8601(s: str) -> int | None:
    """ISO-8601 -> epoch ms; naive times are taken as UTC. None when unparseable."""
    s = s.strip()
    m = _ISO_FAST.fullmatch(s)
    if m is not None:
        y, mo, d, hh, mi, ss, frac, tz = m.groups()
        h, mn, sc = int(hh), int(mi), int(ss)
        if h < 24 and mn < 60 and sc < 60:
            base = day_epoch_s(int(y), int(mo), int(d))
            if base is not None:
                off = 0
                ok = True
                if tz is not None and tz != "Z":
                    oh, om = int(tz[1:3]), int(tz[-2:])
                    if oh < 24 and om < 60:
                        off = (oh * 3600 + om * 60) * (1 if tz[0] == "+" else -1)
                    else:
                        ok = False
                if ok:
                    ms = int((frac + "00")[:3]) if frac else 0
                    return (base + h * 3600 + mn * 60 + sc - off) * 1000 + ms
    # slow path (identical to the reference semantics)
    s2 = s.replace("Z", "+00:00")
    mt = _ISO_TRUNC.match(s2)
    if mt:
        s2 = mt.group(1) + mt.group(2)
    try:
        dt = datetime.fromisoformat(s2)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return calendar.timegm(dt.utctimetuple()) * 1000 + dt.microsecond // 1000


_TZ_OFF = re.compile(r"([+-])(\d\d):?(\d\d)")


@lru_cache(maxsize=256)
def _zone(name: str) -> ZoneInfo | None:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def tz_offset_s(tz: object) -> int:
    """Fixed offset in seconds for ``None``/``UTC``/``Z``/``GMT``/``+0530``/``+05:30``. Raises ValueError otherwise (callers -> null).
    IANA names are resolved by :func:`naive_to_utc_ms`."""
    if tz is None:
        return 0
    s = str(tz).strip()
    if s.upper() in ("UTC", "Z", "GMT", ""):
        return 0
    m = _TZ_OFF.fullmatch(s)
    if not m:
        raise ValueError(tz)
    return (1 if m.group(1) == "+" else -1) * (int(m.group(2)) * 3600 + int(m.group(3)) * 60)


def naive_to_utc_ms(naive_epoch_s: int, tz: object) -> int:
    """Interpret a wall-clock time (given as seconds as if UTC) in ``tz`` and convert to UTC epoch ms."""
    if tz is not None:
        s = str(tz).strip()
        if s and s.upper() not in ("UTC", "Z", "GMT") and not _TZ_OFF.fullmatch(s):
            z = _zone(s)
            if z is None:
                raise ValueError(tz)
            wall = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=naive_epoch_s)
            local = wall.replace(tzinfo=z)
            off = local.utcoffset()
            return (naive_epoch_s - int(off.total_seconds() if off else 0)) * 1000
    return (naive_epoch_s - tz_offset_s(tz)) * 1000


# ----------------------------------------------------------------------------- strptime
_DIRECTIVES = {
    "Y": r"(?P<Y>\d{4})",
    "y": r"(?P<y>\d\d)",
    "m": r"(?P<m>1[0-2]|0[1-9]|[1-9])",
    "d": r"(?P<d>3[0-1]|[1-2]\d|0[1-9]|[1-9]| [1-9])",
    "H": r"(?P<H>2[0-3]|[0-1]\d|\d)",
    "M": r"(?P<M>[0-5]\d|\d)",
    "S": r"(?P<S>6[0-1]|[0-5]\d|\d)",
    "b": r"(?P<b>" + "|".join(_MONTHS) + ")",
}


class StrptimeSpec:
    """A ``strptime`` format compiled once. Supported directives take the fast path; others use ``datetime.strptime``."""

    __slots__ = ("fmt", "rx", "generic")

    def __init__(self, fmt: str) -> None:
        self.fmt = fmt
        self.rx: re.Pattern[str] | None = None
        self.generic = False
        out: list[str] = []
        i = 0
        while i < len(fmt):
            c = fmt[i]
            if c == "%":
                if i + 1 >= len(fmt):
                    self.generic = True
                    return
                d = fmt[i + 1]
                if d == "%":
                    out.append("%")
                elif d in _DIRECTIVES:
                    out.append(_DIRECTIVES[d])
                else:
                    self.generic = True
                    return
                i += 2
            elif c.isspace():
                out.append(r"\s+")
                while i < len(fmt) and fmt[i].isspace():
                    i += 1
            else:
                out.append(re.escape(c))
                i += 1
        self.rx = re.compile("".join(out), re.IGNORECASE)

    def parse_naive_s(self, s: str, default_year: int = 1900) -> int | None:
        """Wall clock as seconds-since-epoch-if-UTC, or None when ``s`` does not match/validate."""
        if self.rx is not None:
            m = self.rx.fullmatch(s)
            if m is None:
                return None
            g = m.groupdict()
            if "Y" in g:
                y = int(g["Y"])
            elif "y" in g:
                yy = int(g["y"])
                y = 1900 + yy if yy >= 69 else 2000 + yy  # POSIX pivot, as the stdlib
            else:
                y = default_year
            mo = _MONTHS[g["b"].lower()] if "b" in g else int(g.get("m") or 1)
            d = int(g["d"]) if "d" in g else 1
            h = int(g["H"]) if "H" in g else 0
            mi = int(g["M"]) if "M" in g else 0
            sc = int(g["S"]) if "S" in g else 0
            if sc > 59:
                return None
            base = day_epoch_s(y, mo, d)
            if base is None:
                return None
            return base + h * 3600 + mi * 60 + sc
        try:
            dt = datetime.strptime(s, self.fmt)
        except ValueError:
            return None
        return calendar.timegm(dt.timetuple())


@lru_cache(maxsize=128)
def strptime_spec(fmt: str) -> StrptimeSpec:
    return StrptimeSpec(fmt)


def strptime_ms(s: str, fmt: str, tz: object = None) -> int | None:
    n = strptime_spec(fmt).parse_naive_s(s)
    if n is None:
        return None
    try:
        return naive_to_utc_ms(n, tz)
    except ValueError:
        return None

