"""The journey's fault steps against fakes: no processes, no sockets, no real waiting."""
import re
import threading
import time
from types import SimpleNamespace

import pytest

from netbridge_e2e import clients, journey
from netbridge_e2e.stack import CONNECTED
from netbridge_e2e.targets import PAGE

TARGETS = SimpleNamespace(echo_port=7, http_port=80)
IP = "10.0.0.1"
ALL_STEPS = ["agent_cut_ends_streams", "agent_cut_recovers", "proxy_cut_ends_streams", "proxy_cut_recovers",
             "agent_blackhole_detected", "relay_unreachable_fails_fast", "relay_reachable_recovers",
             "agent_down_fails_fast", "agent_restarted"]


class FakeTime:
    """Replaces journey.time: sleep() advances monotonic() instantly."""

    def __init__(self, now: float = 1000.0, on_sleep=None):
        self.now = now
        self.sleeps: list[float] = []
        self.on_sleep = on_sleep

    def monotonic(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.now += s
        if self.on_sleep:
            self.on_sleep(self)


@pytest.fixture
def clock(monkeypatch):
    t = FakeTime()
    monkeypatch.setattr(journey, "time", t)
    return t


@pytest.fixture
def j(tmp_path):
    return journey.Journey(journey.parse_args(["--mode", "source", "--work", str(tmp_path)]))


class FakeSock:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeLogs:
    def __init__(self):
        self.lines: list[str] = []

    def text(self) -> str:
        return "\n".join(self.lines)

    def mark(self) -> int:
        return len(self.lines)

    def wait_for(self, pattern, timeout, since=None, alive=None):
        return re.search(pattern, "\n".join(self.lines[since or 0:]))

    def tail(self, n: int = 1500) -> str:
        return self.text()[-n:]


class FakeComp:
    def __init__(self, name: str):
        self.name = name
        self.logs = FakeLogs()
        self.running = True

    def connect(self):
        self.logs.lines += ["Status changed: connecting -> connected", "Connected to relay (session: s1)"]

    def stop(self):
        self.running = False

    def start(self):
        self.running = True
        self.connect()


class FakeLink:
    def __init__(self, name: str, comp=None, active: int = 1, affected: int | None = None):
        self.name, self.comp, self._active = name, comp, active
        self.affected = active if affected is None else affected
        self.refusing = self.blackholed = False
        self.calls: list[str] = []

    def active(self) -> int:
        return self._active

    def cut(self) -> int:
        self.calls.append("cut")
        self.blackholed = False
        if self.comp and not self.refusing:
            self.comp.connect()  # the client reconnects at once through the link
        return self.affected

    def blackhole(self) -> int:
        self.calls.append("blackhole")
        self.blackholed = True
        return self.affected

    def refuse(self, on: bool) -> None:
        self.refusing = on


class FakeRelay:
    def __init__(self, agent, stuck_agents: bool = False):
        self.agent, self.stuck_agents = agent, stuck_agents
        self.paired_calls = 0

    def status(self):
        return {"agents": 1 if self.agent.running or self.stuck_agents else 0, "tunnel_clients": 1}

    def wait_paired(self, timeout):
        self.paired_calls += 1
        s = self.status()
        return s if s["agents"] else None


# --- _attempt (real threads, real time; limits are tiny) --------------------

def test_attempt_classifies_refused_reply_error(j, monkeypatch):
    for exc, kind, said in ((clients.ProxyError(0x04, "x"), "refused", "SOCKS reply 0x04"),
                            (clients.ProxyError(0x01, "x"), "reply", "SOCKS reply 0x01"),
                            (ConnectionResetError("reset"), "error", "ConnectionResetError: reset")):
        def connect(*a, exc=exc, **k):
            raise exc
        monkeypatch.setattr(clients, "socks5_connect", connect)
        got, detail, _ = j._attempt(IP, TARGETS, 2)
        assert got == kind and detail.startswith(said), detail


def test_attempt_ok_closes_socket(j, monkeypatch):
    sock = FakeSock()
    monkeypatch.setattr(clients, "socks5_connect", lambda *a, **k: sock)
    kind, detail, _ = j._attempt(IP, TARGETS, 2)
    assert kind == "ok" and "connected" in detail and sock.closed


def test_attempt_hang_is_capped_by_limit(j, monkeypatch):
    release = threading.Event()

    def connect(*a, **k):
        release.wait(5)
        raise OSError("released")

    monkeypatch.setattr(clients, "socks5_connect", connect)
    start = time.monotonic()
    try:
        kind, detail, _ = j._attempt(IP, TARGETS, 0.05)
    finally:
        release.set()
    assert kind == "hang" and "no SOCKS reply" in detail
    assert time.monotonic() - start < 1


# --- _fails_fast -------------------------------------------------------------

def scripted(j, monkeypatch, clock, results):
    calls = []

    def attempt(ip, targets, limit):
        calls.append(limit)
        kind, finish = results.pop(0)
        clock.now += finish
        return kind, f"{kind} detail", clock.now

    monkeypatch.setattr(j, "_attempt", attempt)
    return calls


def test_fails_fast_refused_before_deadline(j, monkeypatch, clock):
    calls = scripted(j, monkeypatch, clock, [("refused", 2)])
    assert j._fails_fast(IP, TARGETS, clock.now + 20) == (True, "refused detail")
    assert calls == [10.0]


def test_fails_fast_refused_after_deadline(j, monkeypatch, clock):
    scripted(j, monkeypatch, clock, [("refused", 6)])
    assert j._fails_fast(IP, TARGETS, clock.now + 5)[0] is False


def test_fails_fast_retries_while_still_connected(j, monkeypatch, clock):
    calls = scripted(j, monkeypatch, clock, [("ok", 0.1), ("refused", 0.1)])
    assert j._fails_fast(IP, TARGETS, clock.now + 15)[0] is True
    assert len(calls) == 2 and clock.sleeps == [1]


@pytest.mark.parametrize("kind", ["hang", "error", "reply"])
def test_fails_fast_other_outcomes_fail_at_once(j, monkeypatch, clock, kind):
    calls = scripted(j, monkeypatch, clock, [(kind, 0.1), ("refused", 0.1)])
    assert j._fails_fast(IP, TARGETS, clock.now + 15) == (False, f"{kind} detail")
    assert len(calls) == 1


def test_fails_fast_never_refused(j, monkeypatch, clock):
    scripted(j, monkeypatch, clock, [("ok", 1)] * 10)
    ok, detail = j._fails_fast(IP, TARGETS, clock.now + 5)
    assert ok is False and "never refused" in detail and "ok detail" in detail


# --- _inject, _open_echo, _evidence -------------------------------------------

def test_inject_uses_cut_or_blackhole(j, clock):
    link = FakeLink("agent", active=2)
    assert j._inject(link, "cut") == (clock.now, 2)
    assert j._inject(link, "blackhole") == (clock.now, 2)
    assert link.calls == ["cut", "blackhole"]


@pytest.mark.parametrize("active, affected", [(0, 1), (1, 0)])
def test_inject_refuses_to_fault_nothing(j, clock, active, affected):
    with pytest.raises(RuntimeError, match="nothing to fault"):
        j._inject(FakeLink("agent", active=active, affected=affected), "cut")


def test_open_echo_closes_on_bad_round_trip(j, monkeypatch):
    sock = FakeSock()
    monkeypatch.setattr(clients, "socks5_connect", lambda *a, **k: sock)
    monkeypatch.setattr(clients, "echo_roundtrip", lambda s, data: b"garbage")
    with pytest.raises(RuntimeError, match="echo round trip failed"):
        j._open_echo(IP, TARGETS)
    assert sock.closed


def test_evidence_has_relay_status_and_log_tails(j):
    agent = FakeComp("agent")
    agent.logs.lines.append("agent said hi")
    out = j._evidence(FakeRelay(agent), agent)
    assert "'agents': 1" in out and "agent log" in out and "agent said hi" in out


# --- _await_agent_session ------------------------------------------------------

def test_await_session_returns_when_old_enough(j, clock):
    j._agent_up = clock.now - 70
    j._await_agent_session(FakeComp("agent"))
    assert clock.sleeps == []


def test_await_session_sleeps_the_remaining_time(j, clock):
    j._agent_up = clock.now - 63
    j._await_agent_session(FakeComp("agent"))
    assert clock.sleeps == [2]


def test_await_session_restarts_when_agent_reconnects(j, clock):
    agent = FakeComp("agent")
    agent.connect()
    start = clock.now
    j._agent_up = start

    def reconnect_once(t):
        if len(t.sleeps) == 1:
            agent.connect()  # a new RELAY_SESSION line appears during the first nap

    clock.on_sleep = reconnect_once
    j._await_agent_session(agent)
    assert j._agent_up == start + 5
    assert clock.now == start + 5 + 65


# --- _wait_traffic ---------------------------------------------------------------

def test_wait_traffic_success(j, monkeypatch, clock):
    relay = FakeRelay(FakeComp("agent"))
    monkeypatch.setattr(j, "_socks_get", lambda *a, **k: (200, PAGE))
    assert j._wait_traffic(IP, TARGETS, relay, clock.now + 10) == (True, "traffic flows")


def test_wait_traffic_never_paired(j, clock):
    agent = FakeComp("agent")
    agent.running = False
    relay = FakeRelay(agent)
    assert j._wait_traffic(IP, TARGETS, relay, clock.now + 10) == (False, "never paired")
    assert relay.paired_calls == 5  # every 2 s until the deadline


def test_wait_traffic_reports_last_failure(j, monkeypatch, clock):
    answers = [(503, b""), ConnectionResetError("reset")]

    def get(*a, **k):
        r = answers[0] if len(answers) == 1 else answers.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(j, "_socks_get", get)
    ok, last = j._wait_traffic(IP, TARGETS, FakeRelay(FakeComp("agent")), clock.now + 5)
    assert ok is False and last == "ConnectionResetError: reset"


def test_wait_traffic_late_success_fails(j, monkeypatch, clock):
    def slow_get(*a, **k):
        clock.now += 20
        return 200, PAGE

    monkeypatch.setattr(j, "_socks_get", slow_get)
    assert j._wait_traffic(IP, TARGETS, FakeRelay(FakeComp("agent")), clock.now + 10) == (
        False, "traffic flowed only after the deadline")


# --- _faults end to end ---------------------------------------------------------

class World:
    """agent/proxy/links/relay wired so SOCKS behaviour follows the injected faults."""

    def __init__(self, j, monkeypatch, stuck_agents=False, blackhole_error=False, stream_ends=True):
        self.agent, self.proxy = FakeComp("agent"), FakeComp("proxy")
        self.agent.connect()
        self.proxy.logs.lines.append("Connected to relay (session: p1)")
        self.agent_link = FakeLink("agent", self.agent)
        self.proxy_link = FakeLink("proxy", self.proxy)
        self.relay = FakeRelay(self.agent, stuck_agents)
        self.blackhole_error = blackhole_error
        monkeypatch.setattr(clients, "socks5_connect", self.connect)
        monkeypatch.setattr(clients, "echo_roundtrip", lambda s, data: data)
        monkeypatch.setattr(clients, "wait_closed", lambda s, timeout: stream_ends)
        monkeypatch.setattr(j, "_socks_get", lambda *a, **k: (200, PAGE))

    def connect(self, proxy, host, port, timeout=15.0):
        if self.agent_link.refusing or not self.agent.running:
            raise clients.ProxyError(0x04, "host unreachable")
        if self.agent_link.blackholed:
            if self.blackhole_error:
                raise ConnectionResetError("reset by proxy")
            raise clients.ProxyError(0x01, "general failure")
        return FakeSock()

    def run(self, j):
        j._faults(self.relay, self.agent, self.proxy, IP, TARGETS, self.agent_link, self.proxy_link)


def test_faults_all_steps_pass(j, monkeypatch, clock):
    w = World(j, monkeypatch)
    start = clock.now
    w.run(j)
    assert [r["step"] for r in j.results] == ALL_STEPS
    assert all(r["ok"] for r in j.results), j.results
    assert w.agent_link.calls == ["cut", "blackhole", "cut"] and w.proxy_link.calls == ["cut", "cut"]
    assert not w.agent_link.refusing and not w.proxy_link.refusing
    assert clock.now - start >= 65 * 2  # waited for a mature agent session before blackhole and unreachable
    assert j._agent_up == clock.now


def test_faults_agent_cut_stream_never_ends(j, monkeypatch, clock):
    w = World(j, monkeypatch, stream_ends=False)
    w.agent.logs.lines.append("agent evidence line")
    with pytest.raises(journey.StepFailed, match="agent_cut_ends_streams"):
        w.run(j)
    last = j.results[-1]
    assert last["step"] == "agent_cut_ends_streams" and not last["ok"]
    assert "relay {'agents': 1" in last["detail"] and "agent evidence line" in last["detail"]


def test_faults_blackhole_error_fails_without_recovery_wait(j, monkeypatch, clock):
    w = World(j, monkeypatch, blackhole_error=True)
    paired = {}
    real_inject = j._inject

    def inject(link, how):
        paired[how] = w.relay.paired_calls
        return real_inject(link, how)

    monkeypatch.setattr(j, "_inject", inject)
    with pytest.raises(journey.StepFailed, match="agent_blackhole_detected"):
        w.run(j)
    last = j.results[-1]
    assert last["step"] == "agent_blackhole_detected" and not last["ok"]
    assert "ConnectionResetError" in last["detail"]
    assert w.relay.paired_calls == paired["blackhole"]  # no recovery polling after a failed detection


def test_faults_agent_down_but_relay_still_counts_it(j, monkeypatch, clock):
    w = World(j, monkeypatch, stuck_agents=True)
    with pytest.raises(journey.StepFailed, match="agent_down_fails_fast"):
        w.run(j)
    last = j.results[-1]
    assert last["step"] == "agent_down_fails_fast" and not last["ok"]
    assert "relay sees 1 agent(s)" in last["detail"]


def test_faults_relay_unreachable_with_no_live_links(j, monkeypatch, clock):
    w = World(j, monkeypatch)
    real_cut = w.proxy_link.cut
    w.proxy_link.cut = lambda: 0 if w.proxy_link.refusing else real_cut()
    with pytest.raises(RuntimeError, match="relay_unreachable: cut affected"):
        w.run(j)


def test_faults_recovery_needs_the_log_line(j, monkeypatch, clock):
    w = World(j, monkeypatch)
    w.agent.connect = lambda: None  # traffic flows, but the agent never logs the reconnect
    with pytest.raises(journey.StepFailed, match="agent_cut_recovers"):
        w.run(j)
    assert f"no new '{CONNECTED}' log line" in j.results[-1]["detail"]
