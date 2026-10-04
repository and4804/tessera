from hypothesis import given
from hypothesis import strategies as st

from ulpf.ingest.framing import Deframer


def feed_all(d, chunks):
    out = []
    for c in chunks:
        out += d.feed(c)
    out += d.close()
    return out


def test_newline_basic_crlf_and_blank():
    d = Deframer()
    assert feed_all(d, [b"<13>a\n<13>b\r\n\n<13>c"]) == [(b"<13>a", False), (b"<13>b", False), (b"<13>c", False)]
    assert d.detected == "newline"


def test_octet_counting():
    d = Deframer()
    msgs = [b"<13>hello world", b"<14>second\nwith newline", b"x" * 300]
    wire = b"".join(b"%d %s" % (len(m), m) for m in msgs)
    assert [m for m, _ in feed_all(d, [wire])] == msgs
    assert d.detected == "octet"


def test_octet_partial_reads_byte_by_byte():
    msgs = [b"<13>one", b"<13>two two", b"<13>3"]
    wire = b"".join(b"%d %s" % (len(m), m) for m in msgs)
    d = Deframer()
    assert [m for m, _ in feed_all(d, [wire[i : i + 1] for i in range(len(wire))])] == msgs


def test_newline_partial_reads():
    wire = b"alpha\nbeta\ngamma\n"
    d = Deframer()
    assert [m for m, _ in feed_all(d, [wire[i : i + 3] for i in range(0, len(wire), 3)])] == [b"alpha", b"beta", b"gamma"]


def test_digit_leading_lines_stay_newline_framed():
    d = Deframer()
    out = feed_all(d, [b"1790000000.123 5 10.0.0.1 TCP_MISS/200 12 GET http://x/ - HIER_DIRECT/1.2.3.4 text/html\n"])
    assert len(out) == 1 and d.detected == "newline"
    d2 = Deframer()
    assert [m for m, _ in feed_all(d2, [b"12 users logged in\nnext\n"])] == [b"12 users logged in", b"next"]


def test_oversize_newline_is_truncated_and_flagged_not_dropped():
    d = Deframer(max_bytes=10)
    out = feed_all(d, [b"0123456789ABCDEF\nshort\n"])
    assert out == [(b"0123456789", True), (b"short", False)]
    d = Deframer(max_bytes=10)
    out = d.feed(b"0123456789ABCDEF") + d.feed(b"GHI\nok\n")  # oversize arriving in pieces
    assert out == [(b"0123456789", True), (b"ok", False)]


def test_oversize_octet_flagged():
    d = Deframer(max_bytes=8)
    wire = b"20 " + b"A" * 20 + b"3 abc"
    out = feed_all(d, [wire[:10], wire[10:]])
    assert out == [(b"A" * 8, True), (b"abc", False)]


def test_unterminated_tail_flushed_on_close():
    d = Deframer()
    assert d.feed(b"abc\npartial") == [(b"abc", False)]
    assert d.close() == [(b"partial", False)]


def test_forced_modes():
    assert Deframer(framing="newline").feed(b"5 hello\n") == [(b"5 hello", False)]
    assert Deframer(framing="octet").feed(b"5 hello") == [(b"hello", False)]


def test_invalid_utf8_preserved():
    d = Deframer()
    assert d.feed(b"\xff\xfe\x00bin\n") == [(b"\xff\xfe\x00bin", False)]


@given(st.lists(st.binary(min_size=1, max_size=60).filter(lambda b: b"\n" not in b and b"\r" not in b), min_size=1, max_size=20),
       st.lists(st.integers(1, 17), min_size=1, max_size=10), st.booleans())
def test_any_chunking_yields_same_messages(msgs, cuts, octet):
    # avoid messages whose leading digits make newline framing ambiguous: prefix like syslog
    msgs = [b"<13>" + m for m in msgs]
    wire = b"".join((b"%d %s" % (len(m), m)) if octet else m + b"\n" for m in msgs)
    chunks, i, k = [], 0, 0
    while i < len(wire):
        c = cuts[k % len(cuts)]
        chunks.append(wire[i : i + c])
        i += c
        k += 1
    d = Deframer(framing="octet" if octet else "newline")
    assert [m for m, _ in feed_all(d, chunks)] == msgs
