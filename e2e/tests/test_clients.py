import time

import pytest

from netbridge_e2e import clients
from netbridge_e2e.targets import PAGE, Targets
from tests import fakeproxy


@pytest.fixture
def targets():
    with Targets("127.0.0.1") as t:
        yield t


def test_socks5_http_get(targets):
    proxy = fakeproxy.socks5_proxy()
    try:
        with clients.socks5_connect(proxy.address, "127.0.0.1", targets.http_port) as s:
            assert clients.http_get(s, f"127.0.0.1:{targets.http_port}") == (200, PAGE)
    finally:
        proxy.close()


def test_socks5_refusal_carries_reply_code(targets):
    proxy = fakeproxy.socks5_proxy(fail_code=4)
    try:
        with pytest.raises(clients.ProxyError) as err:
            clients.socks5_connect(proxy.address, "127.0.0.1", targets.echo_port)
        assert err.value.code == 4
    finally:
        proxy.close()


def test_socks5_hung_proxy_times_out():
    srv, address = fakeproxy.silent_server()
    try:
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            clients.socks5_connect(address, "127.0.0.1", 9, timeout=1.0)
        assert time.monotonic() - start < 5
    finally:
        srv.close()


def test_http_connect_echo_large_block(targets):
    proxy = fakeproxy.http_proxy()
    data = bytes(range(256)) * 1024  # 256 KiB: larger than typical socket buffers
    try:
        with clients.http_connect(proxy.address, "127.0.0.1", targets.echo_port) as s:
            assert clients.echo_roundtrip(s, data) == data
    finally:
        proxy.close()


def test_http_connect_refusal_carries_status(targets):
    proxy = fakeproxy.http_proxy(refuse=True)
    try:
        with pytest.raises(clients.ProxyError) as err:
            clients.http_connect(proxy.address, "127.0.0.1", targets.echo_port)
        assert err.value.code == 403
    finally:
        proxy.close()


def test_http_forward_get(targets):
    proxy = fakeproxy.http_proxy()
    try:
        url = f"http://127.0.0.1:{targets.http_port}/"
        assert clients.http_forward_get(proxy.address, url) == (200, PAGE)
    finally:
        proxy.close()
