import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ulpf.extract import build_text_extractor, make_extractor, parse_syslog
from ulpf.extract.tsv_zeek import ZeekState
from ulpf.onboard import refengine as ref

RECV = ref.RECV_MS


# ---------------------------------------------------------------- kv
def kv(text, **o):
    return build_text_extractor("kv", o)(text)


def test_kv_basic_quotes_and_dups():
    assert kv('a=1 b="two words" c="say \\"hi\\"" a=3 a=4 empty= q=x') == {
        "a": "1", "b": "two words", "c": 'say "hi"', "a_2": "3", "a_3": "4", "empty": "", "q": "x"}


def test_kv_skips_bare_tokens_and_handles_unterminated():
    assert kv("junk a=1 more junk b=2") == {"a": "1", "b": "2"}
    assert kv('a="never ends') == {"a": "never ends"}
    assert kv("") is None and kv("no pairs here") is None


def test_kv_custom_separators():
    assert kv("a:1;b:'x;y';c:3", pair_sep=";", kv_sep=":", quote="'") == {"a": "1", "b": "x;y", "c": "3"}


@settings(max_examples=400, deadline=None)
@given(st.text(alphabet=st.sampled_from(list('ab =\\"\'x1,;\t')), max_size=60))
def test_kv_matches_reference(t):
    assert kv(t) == ref.ex_kv(t, {})


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet=st.sampled_from(list('ab=;:\\\'x1 ')), max_size=50))
def test_kv_matches_reference_custom(t):
    o = {"pair_sep": ";", "kv_sep": ":", "quote": "'"}
    assert kv(t, **o) == ref.ex_kv(t, o)


# ---------------------------------------------------------------- regex
ASA = {"anchor": r"^(?P<pre>.*?)%ASA-(?P<sev>\d)-(?P<msgid>\d{6}): (?P<body>.*)$", "dispatch_on": "msgid",
       "patterns": {"106023": r"Deny (?P<proto>\w+) src (?P<sif>[\w-]+):(?P<sip>[\d.]+)/(?P<sport>\d+)"}}


def test_regex_dispatch_and_residual():
    f = build_text_extractor("regex", ASA)
    out = f("x %ASA-4-106023: Deny tcp src outside:1.2.3.4/55 trailing bits")
    assert out["proto"] == "tcp" and out["sip"] == "1.2.3.4" and out["_residual"] == " trailing bits"
    out = f("%ASA-4-999999: unknown")
    assert out["body"] == "unknown" and "proto" not in out  # unknown id: anchor fields only
    assert f("nothing") is None


def test_regex_alternatives_first_match_wins_and_search_for_unanchored():
    o = {"anchor": r"^A (?P<x>\d+)$", "alternatives": [r"^B (?P<x>\d+)$", r"C (?P<x>\d+)"]}
    f = build_text_extractor("regex", o)
    assert f("A 1") == {"x": "1"} and f("B 2") == {"x": "2"} and f("zz C 3 zz") == {"x": "3"} and f("D 4") is None


def test_regex_residual_group_dropped_when_empty_and_none_groups_skipped():
    f = build_text_extractor("regex", {"anchor": r"^(?P<a>\w+)(?: (?P<b>\w+))?(?P<_residual>.*)$"})
    assert f("one") == {"a": "one"}
    assert f("one two !") == {"a": "one", "b": "two", "_residual": " !"}


@settings(max_examples=150, deadline=None)
@given(st.text(max_size=80))
def test_regex_asa_matches_reference(t):
    assert build_text_extractor("regex", ASA)(t) == ref.ex_regex(t, ASA)


# ---------------------------------------------------------------- json
def test_json_flatten_lists_and_failures():
    f = build_text_extractor("json", {})
    assert f('{"a":{"b":1,"c":[1,2]},"d":"x","e":{}}') == {"a.b": 1, "a.c": [1, 2], "d": "x"}
    assert f("[1,2]") is None and f("{bad") is None and f("") is None
    assert f('{"big": 123456789012345678901234567890}') == {"big": 123456789012345678901234567890}


# ---------------------------------------------------------------- csv
PF = {"sep": ",", "columns": ["rule", "ver"], "branch": {"field": "ver", "cases": {
    "4": {"columns": ["proto", "src"], "branch": {"field": "proto", "cases": {"tcp": {"columns": ["sport", "dport"]}, "udp": {"columns": ["sport"]}}, "default": {"columns": []}}},
    "6": {"columns": ["src6"]}}}}


def test_csv_layout_branches_quote_aware_and_extra():
    f = build_text_extractor("csv", PF)
    assert f("5,4,tcp,1.1.1.1,80,443") == {"rule": "5", "ver": "4", "proto": "tcp", "src": "1.1.1.1", "sport": "80", "dport": "443"}
    assert f("5,4,udp,1.1.1.1,53,extra1,extra2")["_extra"] == "extra1,extra2"
    assert f('5,6,"a,b"')["src6"] == "a,b"
    assert f("5,4,gre,1.1.1.1") == {"rule": "5", "ver": "4", "proto": "gre", "src": "1.1.1.1"}
    assert f("only") is None
    assert "sport" not in f("5,4,tcp,1.1.1.1,,443")  # empty column not extracted


@settings(max_examples=150, deadline=None)
@given(st.text(alphabet=st.sampled_from(list('456tcpud,"1.')), max_size=40))
def test_csv_matches_reference(t):
    assert build_text_extractor("csv", PF)(t) == ref.ex_csv(t, PF)


# ---------------------------------------------------------------- cef / leef
CEF = r"CEF:0|Acme\|Corp|FW\\1|1.0|100|Deny \| rule|5|src=1.1.1.1 dst=2.2.2.2 msg=a\=b c d cs1=x src=9.9.9.9"


def test_cef_escapes_and_dups():
    out = build_text_extractor("cef", {})("<134>Oct 4 host " + CEF)
    assert out["cef.vendor"] == "Acme|Corp" and out["cef.product"] == "FW\\1" and out["cef.name"] == "Deny | rule"
    assert out["src"] == "1.1.1.1" and out["src_2"] == "9.9.9.9" and out["msg"] == "a=b c d" and out["cs1"] == "x"
    assert build_text_extractor("cef", {})("CEF:0|too|few") is None and build_text_extractor("cef", {})("nope") is None


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("CEF:0|\\= ab1")), max_size=60))
def test_cef_matches_reference(t):
    assert build_text_extractor("cef", {})("CEF:" + t) == ref.ex_cef("CEF:" + t, {})


def test_leef_v1_and_v2_delim():
    f = build_text_extractor("leef", {})
    out = f("LEEF:1.0|Vendor|Prod|1.0|Evt|src=1.1.1.1\tdst=2.2.2.2\tmsg=hi there")
    assert out["src"] == "1.1.1.1" and out["msg"] == "hi there" and out["leef.event_id"] == "Evt"
    out = f("LEEF:2.0|Vendor|Prod|1.0|Evt|^|src=1.1.1.1^dst=2.2.2.2")
    assert out["dst"] == "2.2.2.2"
    out = f("LEEF:2.0|V|P|1|E|x09|a=1\tb=2")
    assert out["b"] == "2"
    assert f("LEEF:1.0|too|few") is None


# ---------------------------------------------------------------- xml
WIN = '<Event xmlns="urn:x"><System><EventID>4625</EventID><TimeCreated SystemTime="2026-10-04T13:21:07Z"/></System><EventData><Data Name="IpAddress">1.2.3.4</Data><Data Name="X">y</Data></EventData></Event>'


def test_xml_flatten_attrs_named_children():
    out = build_text_extractor("xml", {"named_children": {"Data": "Name"}})(WIN)
    assert out == {"System.EventID": "4625", "System.TimeCreated.@SystemTime": "2026-10-04T13:21:07Z", "EventData.IpAddress": "1.2.3.4", "EventData.X": "y"}


@pytest.mark.parametrize("evil", [
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><Event><A>&b;</A></Event>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Event><A>&xxe;</A></Event>',
    '<!doctype x><Event><A>1</A></Event>',
])
def test_xml_rejects_dtd_and_entities(evil):
    assert build_text_extractor("xml", {})(evil) is None


def test_xml_malformed_and_deep():
    f = build_text_extractor("xml", {})
    assert f("<Event><A>") is None and f("") is None and f("not xml") is None
    deep = "<E>" + "<a>" * 200 + "x" + "</a>" * 200 + "</E>"
    assert f(deep) is not None or True  # must not raise or recurse unbounded


# ---------------------------------------------------------------- zeek
def test_zeek_header_state_and_defaults():
    z = ZeekState()
    f = build_text_extractor("tsv_zeek", {"fields": ["ts", "uid"]})
    assert f("1.0\tC1\t9") == {"ts": "1.0", "uid": "C1", "_extra": "9"}  # no header: pack default fields
    for h in ("#separator \\x09", "#fields\tts\tid.orig_h\tservice", "#types\ttime\taddr\tstring", "#unset_field\t-", "#empty_field\t(empty)"):
        assert z.update(h)
    assert not z.update("1.0\t1.1.1.1\t-")
    assert f("1.0\t1.1.1.1\t-", z) == {"ts": "1.0", "id.orig_h": "1.1.1.1"}
    assert f("#fields\tx") is None


# ---------------------------------------------------------------- syslog header
@pytest.mark.parametrize("raw", [
    "<189>date=2026-10-04 time=13:21:07 devname=x",
    "<134>1 2026-10-04T13:21:07+00:00 pfSense.corp.local filterlog 85432 - - 5,,,x",
    "<134>1 2026-10-04T13:21:07Z h app - ID47 [exampleSDID@32473 iut=\"3\"] BOMmsg",
    "<13>Oct  4 13:21:07 host1 sshd[123]: Failed password",
    "<13>Oct  4 13:21:07 filterlog[85432]: 5,,,1",
    "<13>Dec 31 23:59:59 host app: msg",
    "no header at all", "", "<999>", "<13>Foo  4 13:21:07 x", "<13>1 broken",
])
def test_syslog_header_matches_reference(raw):
    assert parse_syslog(raw, RECV) == ref.parse_syslog(raw, RECV)


def test_syslog_3164_year_rollover():
    import calendar

    jan = calendar.timegm((2027, 1, 1, 0, 5, 0)) * 1000
    msg, ctx = parse_syslog("<13>Dec 31 23:59:59 h app: m", jan)
    assert ctx["syslog.ts"].startswith("2026-12-31") and ctx["syslog.time_quality"] == "assumed_tz" and msg == "m"
    assert ctx["syslog.host"] == "h" and ctx["syslog.app"] == "app" and ctx["syslog.pri"] == 13


@given(st.binary(max_size=200))
def test_make_extractor_never_raises_on_bytes(b):
    for kind, o in [("kv", {}), ("json", {}), ("cef", {}), ("leef", {}), ("xml", {}), ("csv", {"columns": ["a", "b"]}),
                    ("regex", {"anchor": r"(?P<x>\d+)"}), ("tsv_zeek", {"fields": ["a"]})]:
        make_extractor(kind, o)(b)


def test_surrogateescape_roundtrip_into_fields():
    out = make_extractor("kv")(b"a=\xff\xfe b=ok")
    assert out["a"].encode("utf-8", "surrogateescape") == b"\xff\xfe"


def test_csv_extractor_rejects_bare_cr_instead_of_raising():
    from ulpf.extract.csv_ import build_csv

    assert build_csv({"sep": ","})("\r,") is None
