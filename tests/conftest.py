"""Shared fixtures. A throwaway local redis-server is started once per session (loopback only)."""
import ipaddress
import shutil
import socket
import subprocess
import time

import pytest

# --- R5 / section 10: suite-wide egress guard. Any connect/sendto/DNS lookup that is not loopback fails the test that made it. Installed at
# import time (not per test) so fixtures, threads and session-scoped servers are covered; child processes spawned by tests are not.

_real = {"connect": socket.socket.connect, "connect_ex": socket.socket.connect_ex, "sendto": socket.socket.sendto,
         "getaddrinfo": socket.getaddrinfo}


def _is_loopback(host) -> bool:
    if isinstance(host, bytes):
        host = host.decode("latin-1")
    if host in ("localhost", "", "ip6-localhost"):
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback or host == "0.0.0.0"
    except ValueError:
        return False


def _check(sock, address) -> None:
    if sock.family in (socket.AF_INET, socket.AF_INET6) and isinstance(address, tuple) and not _is_loopback(address[0]):
        raise AssertionError(f"egress blocked by the air-gap test guard: connect/send to {address[0]!r}")


def _guarded(name):
    real = _real[name]

    def wrapper(self, *a, **k):
        addr = a[-1] if name == "sendto" else (a[0] if a else None)
        _check(self, addr)
        return real(self, *a, **k)
    wrapper.__name__ = name
    return wrapper


def _gai(host, *a, **k):
    if host is not None and not _is_loopback(host):
        raise AssertionError(f"egress blocked by the air-gap test guard: DNS lookup of {host!r}")
    return _real["getaddrinfo"](host, *a, **k)


socket.socket.connect = _guarded("connect")          # type: ignore[method-assign]
socket.socket.connect_ex = _guarded("connect_ex")    # type: ignore[method-assign]
socket.socket.sendto = _guarded("sendto")            # type: ignore[method-assign]
socket.getaddrinfo = _gai                            # type: ignore[assignment]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def redis_url(tmp_path_factory):
    exe = shutil.which("redis-server")
    if not exe:
        pytest.skip("redis-server not installed")
    port = _free_port()
    d = tmp_path_factory.mktemp("redis")
    p = subprocess.Popen([exe, "--port", str(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", str(d)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import redis

    url = f"redis://127.0.0.1:{port}/0"
    for _ in range(100):
        try:
            redis.Redis.from_url(url).ping()
            break
        except redis.ConnectionError:
            time.sleep(0.05)
    else:
        p.kill()
        pytest.skip("redis-server did not start")
    yield url
    p.terminate()
    p.wait(timeout=5)


@pytest.fixture(params=["memory", "redis"])
def bus(request):
    """Same conformance suite against both bus implementations."""
    from ulpf.bus import MemoryBus, RedisBus

    if request.param == "memory":
        b = MemoryBus(partitions=4)
    else:
        import uuid

        import redis

        url = request.getfixturevalue("redis_url")
        r = redis.Redis.from_url(url)
        b = RedisBus(url, partitions=4, client=r, prefix="t" + uuid.uuid4().hex[:8])
        b.ledger = type(b.ledger)(r, prefix="l" + uuid.uuid4().hex[:8] + ":")
    yield b
    b.close()
