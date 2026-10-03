import contextlib
import json
from types import SimpleNamespace

import pytest

from netbridge_e2e import clients, journey
from netbridge_e2e.targets import PAGE, Targets
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
    with Targets("127.0.0.1") as t:
        j.socks = ("127.0.0.1", t.refused_port)
        got, _ = j._fail_case("socks5", HOST, 80, 5)
    assert str(got).startswith("error:")


def test_fail_case_unexpected_exception_is_not_a_hang(j, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr("netbridge_e2e.clients.socks5_connect", boom)
    got, _ = j._fail_case("socks5", HOST, 80, 5)
    assert got == "unexpected:RuntimeError"


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


TARGETS = SimpleNamespace(http_port=80, echo_port=7, blocked_port=9, refused_port=11)


def _case(j, monkeypatch, got, *, expect=4, agent_pre=(), relay_pre=(), agent_new=(), relay_new=(), **kw):
    relay, agent = FakeComp("relay"), FakeComp("agent")
    relay.logs.lines += list(relay_pre)                      # older than the marks
    agent.logs.lines += list(agent_pre)

    def fail_case(front, host, port, budget):
        agent.logs.lines += list(agent_new)                  # emitted by the action
        relay.logs.lines += list(relay_new)
        return got, 0.2

    monkeypatch.setattr(j, "_fail_case", fail_case)
    return j._error_case(relay, agent, "socks5", "h", 80, expect, 10, **kw)()


def test_error_case_passes_on_pinned_reply_and_fresh_agent_log(j, monkeypatch):
    ok, detail = _case(j, monkeypatch, 4, agent_new=["Failed: abc -> h:80: boom"], agent_log="Failed:")
    assert ok, detail


@pytest.mark.parametrize("got", [5, 6, 1, 503, "ok", "hang", "error:ConnectionResetError"])
def test_error_case_fails_on_any_other_outcome(j, monkeypatch, got):
    ok, detail = _case(j, monkeypatch, got, agent_new=["Failed: x"], agent_log="Failed:")
    assert not ok and repr(got) in detail


def test_error_case_fails_without_the_expected_agent_log(j, monkeypatch):
    ok, detail = _case(j, monkeypatch, 4, agent_log="Destination denied")
    assert not ok and "agent log" in detail


def test_error_case_ignores_log_lines_older_than_the_mark(j, monkeypatch):
    ok, _ = _case(j, monkeypatch, 4, relay_pre=["Blocked port 9 requested by x"], relay_log=r"Blocked port 9\b")
    assert not ok                                            # stale evidence must not pass a later step
    ok, detail = _case(j, monkeypatch, 4, agent_new=["Destination denied: x"], agent_log="Destination denied",
                       relay_pre=["Blocked port 9 requested by x"], not_relay_log="Blocked port")
    assert ok, detail                                        # and must not fail the denial case either


def test_error_case_agent_denial_fails_when_the_relay_blocked_it_instead(j, monkeypatch):
    ok, detail = _case(j, monkeypatch, 4, agent_new=["Destination denied: x"], relay_new=["Blocked port 80 requested"],
                       agent_log="Destination denied", not_relay_log="Blocked port")
    assert not ok and "relay logged" in detail


class _ErrRelay(FakeComp):
    def status(self):
        return {"active_streams": 0}


def _errors_world(j, monkeypatch, replies):
    relay, agent = _ErrRelay("relay"), FakeComp("agent")

    def fail_case(front, host, port, budget):
        if port == TARGETS.blocked_port:
            relay.logs.lines.append(f"Blocked port {port} requested by t")
        elif host == "169.254.169.254":
            agent.logs.lines.append(f"Destination denied: s -> {host}:{port}: link-local")
        elif host == journey.NXDOMAIN:
            agent.logs.lines.append(f"Failed: s -> {host}:{port}: [Errno -2] Name or service not known")
        else:
            agent.logs.lines.append(f"Failed: s -> {host}:{port}: [Errno 111] Connect call failed")
        return replies(front), 0.1

    monkeypatch.setattr(j, "_fail_case", fail_case)
    monkeypatch.setattr(j, "_socks_get", lambda *a, **k: (200, PAGE))
    j.fail_case_orig = fail_case
    return relay, agent


def test_errors_group_runs_all_steps_in_order(j, monkeypatch, clock):
    relay, agent = _errors_world(j, monkeypatch, lambda front: 4 if front == "socks5" else 502)
    j._errors("10.0.0.1", TARGETS, relay, agent)
    assert [r["step"] for r in j.results] == [
        "errors_baseline_clean", "refused_socks5", "refused_http_connect", "refused_http_forward",
        "dns_failure_socks5", "dns_failure_http_connect", "dns_failure_http_forward",
        "agent_denies_socks5", "agent_denies_http_connect", "agent_denies_http_forward",
        "blocked_port_http_connect", "blocked_port_http_forward", "errors_leave_tunnel_healthy",
        "blocked_port_never_reached_agent"]
    assert all(r["ok"] for r in j.results)


def test_errors_group_fails_fast_on_a_regressed_reply(j, monkeypatch, clock):
    relay, agent = _errors_world(j, monkeypatch, lambda front: 6 if front == "socks5" else 502)
    with pytest.raises(journey.StepFailed):
        j._errors("10.0.0.1", TARGETS, relay, agent)
    assert j.results[-1]["step"] == "refused_socks5" and "6" in j.results[-1]["detail"]


def test_relay_filter_requires_exactly_0x04_and_the_relay_log(j, monkeypatch):
    relay, agent = FakeComp("relay"), FakeComp("agent")
    for code, log, want in ((0x04, True, True), (0x01, True, False), (0x04, False, False)):
        j.results.clear()

        def connect(*a, code=code, log=log, **k):
            if log:
                relay.logs.lines.append("Blocked port 9 requested by t")
            raise clients.ProxyError(code, "refused")

        monkeypatch.setattr(clients, "socks5_connect", connect)
        try:
            j._filter("10.0.0.1", TARGETS, relay, agent)
            got = True
        except journey.StepFailed:
            got = False
        assert got is want, (code, log)


def _steps_failing(j, relay, agent):
    with pytest.raises(journey.StepFailed):
        j._errors("10.0.0.1", TARGETS, relay, agent)
    return j.results[-1]["step"]


def test_dns_step_not_satisfied_by_a_refused_line_for_another_host(j, monkeypatch, clock):
    relay, agent = _errors_world(j, monkeypatch, lambda front: 4 if front == "socks5" else 502)
    base = j.fail_case_orig

    def fc(front, host, port, budget):
        out = base(front, host, port, budget)
        if host == journey.NXDOMAIN:
            agent.logs.lines[-1] = f"Failed: s -> 10.0.0.1:{port}: [Errno 111] Connect call failed"
        return out

    monkeypatch.setattr(j, "_fail_case", fc)
    assert _steps_failing(j, relay, agent) == "dns_failure_socks5"


def test_dns_step_fails_when_the_name_was_refused(j, monkeypatch, clock):
    relay, agent = _errors_world(j, monkeypatch, lambda front: 4 if front == "socks5" else 502)
    base = j.fail_case_orig

    def fc(front, host, port, budget):
        out = base(front, host, port, budget)
        if host == journey.NXDOMAIN:
            agent.logs.lines[-1] = f"Failed: s -> {host}:{port}: Connect call failed (Connection refused)"
        return out

    monkeypatch.setattr(j, "_fail_case", fc)
    assert _steps_failing(j, relay, agent) == "dns_failure_socks5"


def test_agent_denial_fails_on_the_relays_own_denial(j, monkeypatch, clock):
    relay, agent = _errors_world(j, monkeypatch, lambda front: 4 if front == "socks5" else 502)
    base = j.fail_case_orig

    def fc(front, host, port, budget):
        out = base(front, host, port, budget)
        if host == journey.LINK_LOCAL:
            relay.logs.lines.append("Destination denied for t: x")
        return out

    monkeypatch.setattr(j, "_fail_case", fc)
    assert _steps_failing(j, relay, agent) == "agent_denies_socks5"


def test_blocked_port_fails_when_the_agent_connected_anyway(j, monkeypatch, clock):
    relay, agent = _errors_world(j, monkeypatch, lambda front: 4 if front == "socks5" else 502)
    base = j.fail_case_orig

    def fc(front, host, port, budget):
        out = base(front, host, port, budget)
        if port == TARGETS.blocked_port:
            agent.logs.lines.append(f"Connected: s -> {host}:{port}")
        return out

    monkeypatch.setattr(j, "_fail_case", fc)
    assert _steps_failing(j, relay, agent) == "blocked_port_http_connect"


def test_relay_filter_fails_when_the_agent_connected_anyway(j, monkeypatch):
    relay, agent = FakeComp("relay"), FakeComp("agent")

    def connect(*a, **k):
        relay.logs.lines.append("Blocked port 9 requested by t")
        agent.logs.lines.append("Connected: s -> 10.0.0.1:9")
        raise clients.ProxyError(4, "refused")

    monkeypatch.setattr(clients, "socks5_connect", connect)
    with pytest.raises(journey.StepFailed):
        j._filter("10.0.0.1", TARGETS, relay, agent)


def test_relay_filter_ignores_a_longer_port_number(j, monkeypatch):
    relay, agent = FakeComp("relay"), FakeComp("agent")

    def connect(*a, **k):
        relay.logs.lines.append("Blocked port 9 requested by t")
        agent.logs.lines.append("Connected: s -> 10.0.0.1:90")
        raise clients.ProxyError(4, "refused")

    monkeypatch.setattr(clients, "socks5_connect", connect)
    j._filter("10.0.0.1", TARGETS, relay, agent)


def test_errors_baseline_fails_when_streams_are_stuck(j, monkeypatch, clock):
    relay, agent = _errors_world(j, monkeypatch, lambda front: 4)
    relay.status = lambda: {"active_streams": 3}
    assert _steps_failing(j, relay, agent) == "errors_baseline_clean"


@pytest.mark.parametrize("reply,streams", [((503, b"x"), 0), ((200, PAGE), 2)])
def test_tunnel_health_step_fails(j, monkeypatch, clock, reply, streams):
    relay, agent = _errors_world(j, monkeypatch, lambda front: 4 if front == "socks5" else 502)
    state = {"n": 0}

    def status():
        return {"active_streams": 0 if state["n"] == 0 else streams}

    relay.status = status
    monkeypatch.setattr(j, "_socks_get", lambda *a, **k: (state.update(n=1), reply)[1])
    assert _steps_failing(j, relay, agent) == "errors_leave_tunnel_healthy"


NONCE = "feedface"
BODY = f"netbridge-e2e-plugin {NONCE}".encode()


def _plugin_world(monkeypatch, *, body=BODY, plugins=("e2e-probe",), loaded=True, skipped=True):
    agent = FakeComp("agent")
    agent.logs.lines = ["old line"]
    start = agent.logs.mark()
    if loaded:
        agent.logs.lines.append("Plugin loaded: netbridge-e2e-probe")
    if skipped:
        agent.logs.lines.append("Skipping plugin broken: manifest missing entry_point")
    sock = FakeSock()
    monkeypatch.setattr(clients, "socks5_connect", lambda *a, **k: contextlib.closing(sock))
    monkeypatch.setattr(clients, "http_connect", lambda *a, **k: contextlib.closing(sock))

    def http_get(s, host, path="/"):
        if path == "/plugins":
            return 200, json.dumps({"plugins": [{"name": n} for n in plugins]}).encode()
        return 200, body

    monkeypatch.setattr(clients, "http_get", http_get)
    monkeypatch.setattr(clients, "http_forward_get", lambda *a, **k: (200, body))
    return agent, start


def test_plugin_steps_pass_against_a_correct_agent(j, monkeypatch):
    agent, start = _plugin_world(monkeypatch)
    j._plugins(agent, start, NONCE)
    assert [r["step"] for r in j.results] == ["plugin_loaded_log", "plugin_routable", "plugins_listed"]
    assert all(r["ok"] for r in j.results)


def test_plugin_routable_rejects_a_stale_nonce(j, monkeypatch):
    agent, start = _plugin_world(monkeypatch, body=b"netbridge-e2e-plugin oldnonce")
    with pytest.raises(journey.StepFailed):
        j._plugins(agent, start, NONCE)
    assert j.results[-1]["step"] == "plugin_routable" and "unexpected" in j.results[-1]["detail"]


def test_plugin_loaded_log_fails_without_the_load_line_and_shows_the_tail(j, monkeypatch):
    agent, start = _plugin_world(monkeypatch, loaded=False)
    with pytest.raises(journey.StepFailed):
        j._plugins(agent, start, NONCE)
    assert j.results[-1]["step"] == "plugin_loaded_log" and "agent log tail" in j.results[-1]["detail"]


def test_plugin_loaded_log_fails_without_the_skip_line(j, monkeypatch):
    agent, start = _plugin_world(monkeypatch, skipped=False)
    with pytest.raises(journey.StepFailed):
        j._plugins(agent, start, NONCE)
    assert j.results[-1]["step"] == "plugin_loaded_log"


def test_plugin_loaded_log_ignores_lines_from_before_the_start_mark(j, monkeypatch):
    agent, start = _plugin_world(monkeypatch, loaded=False, skipped=False)
    agent.logs.lines.insert(0, "Plugin loaded: netbridge-e2e-probe")
    with pytest.raises(journey.StepFailed):
        j._plugins(agent, start + 1, NONCE)


def test_plugins_listed_fails_when_the_broken_plugin_is_listed(j, monkeypatch):
    agent, start = _plugin_world(monkeypatch, plugins=("e2e-probe", "e2e-broken"))
    with pytest.raises(journey.StepFailed):
        j._plugins(agent, start, NONCE)
    assert j.results[-1]["step"] == "plugins_listed"


def test_late_agent_connect_to_the_blocked_port_fails_the_sweep(j, monkeypatch, clock):
    relay, agent = _errors_world(j, monkeypatch, lambda front: 4 if front == "socks5" else 502)
    calls = []
    base = j._wait_streams_zero

    def late(*a, **k):
        calls.append(1)
        if len(calls) == 2:   # the healthy check, after every blocked case has passed
            agent.logs.lines.append(f"Connected: s -> 10.0.0.1:{TARGETS.blocked_port}")
        return base(*a, **k)

    monkeypatch.setattr(j, "_wait_streams_zero", late)
    assert _steps_failing(j, relay, agent) == "blocked_port_never_reached_agent"


def test_fail_case_late_answer_counts_as_hang(j, monkeypatch):
    t = [0.0]
    monkeypatch.setattr(journey.time, "monotonic", lambda: t[0])

    def slow(*a, **k):
        t[0] += 10          # the reply arrives after the budget
        raise clients.ProxyError(4, "late")

    monkeypatch.setattr(journey.clients, "socks5_connect", slow)
    got, secs = j._fail_case("socks5", HOST, 80, 5)
    assert got == "hang" and secs == 10
