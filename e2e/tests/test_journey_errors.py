import pytest

from netbridge_e2e import clients, journey
from netbridge_e2e.targets import Targets
from tests import fakeproxy
from tests.test_journey_faults import FakeComp, FakeSock, FakeTime, clock, j  # noqa: F401  (fixtures by name)

HOST = "netbridge-e2e-nxdomain.invalid"


@pytest.mark.parametrize("code", [4, 5])
def test_fail_case_socks5_returns_the_reply_code(j, code):
    proxy = fakeproxy.socks5_proxy(fail_code=code)
    try:
        j.socks = proxy.address
        got, secs = j._fail_case("socks5", HOST, 80, 5)
    finally:
        proxy.close()
    assert got == code and secs < 5


def test_fail_case_http_front_ends_return_the_status(j):
    proxy = fakeproxy.http_proxy(connect_status=502, forward_status=504)
    try:
        j.http = proxy.address
        assert j._fail_case("http_connect", HOST, 80, 5)[0] == 502
        assert j._fail_case("http_forward", HOST, 80, 5)[0] == 504
    finally:
        proxy.close()


def test_fail_case_reports_ok_when_it_connects(j):
    with Targets("127.0.0.1") as t:
        proxy = fakeproxy.socks5_proxy()
        try:
            j.socks = proxy.address
            assert j._fail_case("socks5", "127.0.0.1", t.echo_port, 5)[0] == "ok"
        finally:
            proxy.close()


def test_fail_case_hang_is_capped_by_the_budget(j):
    srv, addr = fakeproxy.silent_server()
    try:
        j.socks = addr
        got, secs = j._fail_case("socks5", HOST, 80, 0.2)
    finally:
        srv.close()
    assert got == "hang" and 0.2 <= secs < 2


def test_fail_case_transport_error_is_reported(j):
    srv, addr = fakeproxy.silent_server()
    srv.close()                                               # nothing listens any more
    j.socks = addr
    got, _ = j._fail_case("socks5", HOST, 80, 5)
    assert str(got).startswith("error:")


class StatusRelay:
    def __init__(self, values):
        self.values, self.calls = list(values), 0

    def status(self):
        v = self.values[min(self.calls, len(self.values) - 1)]
        self.calls += 1
        return None if v is None else {"active_streams": v}


def test_wait_streams_zero_needs_consecutive_zeros(j, clock):
    ok, detail = j._wait_streams_zero(StatusRelay([3, 0, 1, 0, 0]), within=10)
    assert ok and "0" in detail


def test_wait_streams_zero_reports_the_stuck_value(j, clock):
    ok, detail = j._wait_streams_zero(StatusRelay([2]), within=5)
    assert not ok and "stuck at 2" in detail


def test_wait_streams_zero_unreadable_status_is_not_zero(j, clock):
    ok, detail = j._wait_streams_zero(StatusRelay([None]), within=3)
    assert not ok and "unreadable" in detail
