import hashlib
import ipaddress
import socket
import urllib.request

from netbridge_e2e import netinfo, targets
from netbridge_e2e.targets import PAGE, PAYLOAD, PAYLOAD_SHA256, Targets

NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(url):
    with NO_PROXY.open(url, timeout=10) as r:
        return r.status, r.read()


def test_payload_is_5_mib_and_position_dependent():
    assert len(PAYLOAD) == targets.PAYLOAD_SIZE == 5 * 1024 * 1024
    assert hashlib.sha256(PAYLOAD).hexdigest() == PAYLOAD_SHA256
    assert PAYLOAD[:32] != PAYLOAD[32:64]


def test_http_page_payload_and_404():
    with Targets("127.0.0.1") as t:
        assert get(f"http://127.0.0.1:{t.http_port}/") == (200, PAGE)
        status, body = get(f"http://127.0.0.1:{t.http_port}/payload")
        assert status == 200 and hashlib.sha256(body).hexdigest() == PAYLOAD_SHA256
        try:
            get(f"http://127.0.0.1:{t.http_port}/nope")
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404


def test_echo_and_blocked_listeners_echo():
    with Targets("127.0.0.1") as t:
        assert len({t.http_port, t.echo_port, t.blocked_port}) == 3
        for port in (t.echo_port, t.blocked_port):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.sendall(b"ping")
                assert s.recv(4) == b"ping"


def test_private_ipv4_is_not_loopback_or_link_local():
    ip = ipaddress.ip_address(netinfo.private_ipv4())
    assert ip.version == 4
    assert not ip.is_loopback and not ip.is_link_local


def test_port_in_use_detects_a_listener():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        port = s.getsockname()[1]
        assert netinfo.port_in_use(port)
    assert not netinfo.port_in_use(port)
