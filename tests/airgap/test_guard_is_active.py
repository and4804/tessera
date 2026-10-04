"""The suite-wide egress guard (tests/conftest.py) is on for every unit/integration test: non-loopback connects and DNS lookups fail."""
import socket

import pytest


def test_external_tcp_connect_is_refused_by_the_suite_guard():
    s = socket.socket()
    with pytest.raises(AssertionError, match="egress"):
        s.connect(("1.1.1.1", 443))
    s.close()


def test_external_dns_lookup_and_create_connection_are_refused():
    with pytest.raises(AssertionError, match="egress"):
        socket.getaddrinfo("example.com", 443)
    with pytest.raises(AssertionError, match="egress"):
        socket.create_connection(("example.com", 80), timeout=1)


def test_external_udp_send_is_refused():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with pytest.raises(AssertionError, match="egress"):
        s.sendto(b"x", ("8.8.8.8", 53))
    s.close()


def test_private_but_non_loopback_is_refused_too():
    s = socket.socket()
    with pytest.raises(AssertionError, match="egress"):
        s.connect(("10.255.255.1", 80))
    s.close()


def test_loopback_still_works():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    c = socket.socket()
    c.connect(srv.getsockname())
    c.close()
    srv.close()
    assert socket.getaddrinfo("localhost", 80)
