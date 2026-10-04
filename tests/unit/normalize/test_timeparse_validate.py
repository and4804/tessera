import calendar
from datetime import datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ulpf.normalize import timeparse as tp
from ulpf.normalize.validate import validate_event


def ms(y, mo, d, h=0, mi=0, s=0):
    return calendar.timegm((y, mo, d, h, mi, s)) * 1000


@pytest.mark.parametrize("s,want", [
    ("2026-10-04T13:21:07Z", ms(2026, 10, 4, 13, 21, 7)),
    ("2026-10-04 13:21:07", ms(2026, 10, 4, 13, 21, 7)),
    ("2026-10-04T13:21:07.123Z", ms(2026, 10, 4, 13, 21, 7) + 123),
    ("2026-10-04T13:21:07.123456789+05:30", ms(2026, 10, 4, 7, 51, 7) + 123),
    ("2026-10-04T13:21:07-0800", ms(2026, 10, 4, 21, 21, 7)),
    ("2026-02-30T00:00:00Z", None), ("garbage", None), ("2026-10-04T25:00:00Z", None),
])
def test_iso8601(s, want):
    assert tp.parse_iso8601(s) == want


@pytest.mark.parametrize("tz,off", [(None, 0), ("UTC", 0), ("Z", 0), ("+0530", 19800), ("-08:00", -28800)])
def test_tz_offset(tz, off):
    assert tp.tz_offset_s(tz) == off


def test_tz_bad_and_iana():
    with pytest.raises(ValueError):
        tp.tz_offset_s("nonsense")
    n = tp.day_epoch_s(2026, 7, 1)
    assert tp.naive_to_utc_ms(n, "Asia/Kolkata") == (n - 19800) * 1000
    with pytest.raises(ValueError):
        tp.naive_to_utc_ms(n, "Not/AZone")
    assert tp.day_epoch_s(2026, 2, 29) is None


def test_strptime_fast_and_generic_agree():
    fmt = "%b %d %Y %H:%M:%S"
    assert tp.strptime_ms("Oct  4 2026 13:21:07", fmt, "UTC") == ms(2026, 10, 4, 13, 21, 7)
    assert tp.strptime_ms("Oct 04 2026 13:21:07", fmt, "+0530") == ms(2026, 10, 4, 7, 51, 7)
    assert tp.strptime_ms("Feb 30 2026 00:00:00", fmt) is None
    assert tp.strptime_ms("26-10-04", "%y-%m-%d") == ms(2026, 10, 4)
    g = tp.strptime_ms("Sun Oct  4 13:21:07 2026", "%a %b %d %H:%M:%S %Y")       # %a -> stdlib fallback path
    assert g == ms(2026, 10, 4, 13, 21, 7)
    assert tp.strptime_spec("%a %b").generic is True


@given(st.datetimes(min_value=datetime(1971, 1, 1), max_value=datetime(2099, 12, 31)))
def test_strptime_matches_stdlib(dt):
    s = dt.strftime("%Y-%m-%d %H:%M:%S")
    assert tp.strptime_ms(s, "%Y-%m-%d %H:%M:%S") == calendar.timegm(dt.timetuple()) * 1000


@given(st.text(max_size=40))
def test_timeparse_never_raises(s):
    tp.parse_iso8601(s)
    tp.strptime_ms(s, "%Y-%m-%d %H:%M:%S", "UTC")


def good():
    return {
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "time": 1790000000000, "severity_id": 1,
        "action_id": 1, "src_endpoint": {"ip": "10.0.0.1", "port": 1}, "dst_endpoint": {"ip": "::1", "port": 65535},
        "unmapped": {}, "ulpf": {"event_id": "a:0", "raw_ref": "s/0/0", "raw_sha256": "x", "source_id": "p", "status": "parsed",
                                  "coverage": 1.0, "time_quality": "source_tz", "schema": "ocsf-1.3.0"},
    }


def test_validator_accepts_good_and_flags_each_defect():
    assert validate_event(good()) == []
    cases = {
        "type_uid": lambda e: e.update(type_uid=1), "category_uid": lambda e: e.update(category_uid=3),
        "time": lambda e: e.update(time=1.5), "action_id": lambda e: e.update(action_id=77),
        "src_endpoint.ip": lambda e: e["src_endpoint"].update(ip="999.1.1.1"),
        "dst_endpoint.port": lambda e: e["dst_endpoint"].update(port=70000),
        "activity_id": lambda e: e.update(activity_id=55), "unmapped": lambda e: e.update(unmapped=[]),
        "ulpf.event_id": lambda e: e["ulpf"].pop("event_id"), "ulpf.status": lambda e: e["ulpf"].update(status="weird"),
        "class_uid": lambda e: e.update(class_uid=1234),
    }
    for field, mut in cases.items():
        e = good()
        mut(e)
        assert field in {v.field for v in validate_event(e)}, field
    e = good()
    e["time"] = True
    assert validate_event(e)
