import pytest
from hypothesis import given
from hypothesis import strategies as st

from ulpf.api.query_dsl import QueryError, compile_query


def test_empty_and_simple():
    assert compile_query("") == ("TRUE", []) and compile_query(None) == ("TRUE", [])
    w, p = compile_query("src_ip:10.1.1.15 action:denied dst_port:22,2222 \"free text\" -status:unparsed")
    assert p == ["10.1.1.15", 2, 22, 2222, "%free text%", "unparsed"]
    assert w.count("?") == len(p) and w.startswith("COALESCE(src_ip = ?") and "NOT COALESCE(status = ?" in w


def test_forms():
    assert compile_query("bytes_in:>=5")[0] == "COALESCE(bytes_in >= ?, FALSE)"
    w, p = compile_query("dst_port:1000..2000")
    assert "BETWEEN ? AND ?" in w and p == [1000, 2000]
    w, p = compile_query("src_ip:10.0.0.0/8")
    assert "BETWEEN ? AND ?" in w and p == [167772160, 184549375]
    w, p = compile_query("src_ip:10.1.*")
    assert "LIKE ? ESCAPE" in w and p == ["10.1.%"]
    w, p = compile_query('url:"a b*" time:>=2026-10-04')
    assert p[0] == "a b%" and p[1] == 1791072000000 and "to_timestamp(? / 1000.0)" in w
    assert compile_query("device_host:FW*")[1] == ["FW%"] and "ILIKE" in compile_query("device_host:FW*")[0]


@pytest.mark.parametrize("q", ["bogus:1", "src_ip:", "src_ip:999.1.1.1", "dst_port:x", "action:zzz", "status:nope", "url:>3", 'a:"b',
                               "src_ip:::1/64", "time:>=notatime"])
def test_rejections(q):
    with pytest.raises(QueryError):
        compile_query(q)


@given(st.text(max_size=120))
def test_user_text_never_reaches_sql_and_parser_never_crashes(s):
    try:
        w, p = compile_query(s)
    except QueryError:
        return
    assert w.count("?") == len(p)
    # the SQL text is built only from whitelisted column names and operators
    import re

    assert re.fullmatch(r"[A-Za-z0-9_ ?(),.=<>%'/*:|\\-]*", w), w


def test_injection_strings_become_parameters():
    evil = "x'); DROP TABLE t; --"
    w, p = compile_query(f'url:"{evil}" "{evil}"')
    assert evil not in w and any(evil.lower() in str(x).lower() for x in p)
