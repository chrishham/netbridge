"""The journey's edge steps against fakes: no relay, no edge sockets."""
import re
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from netbridge_e2e import journey
from netbridge_e2e.edgeproxy import PROFILES
from netbridge_e2e.stack import FAULT_TUNING

CAP = int(FAULT_TUNING["RELAY_RATE_IP_CONNECTIONS_PER_MIN"])


@pytest.fixture
def j(tmp_path):
    return journey.Journey(journey.parse_args(["--mode", "source", "--work", str(tmp_path), "--edge"]))


def fake_edge(profile="arr", idle=0.0):
    return SimpleNamespace(port=4443, profile=PROFILES[profile], idle_timeout=idle, idle_closes=0,
                           bad_gateways=Counter(), ca_path=Path("ca.pem"), client_context=lambda: "CTX")


class Logs:
    def __init__(self, text=""):
        self._text = text

    def mark(self):
        return None

    def wait_for(self, pattern, timeout, since=None, alive=None):
        return re.search(pattern, self._text)

    def text(self, since=None):
        return self._text

    def tail(self, n=1500):
        return self._text[-n:]


class Stub:
    def mint(self, **kw):
        return "valid-token"


# --- arguments -----------------------------------------------------------

def test_edge_profile_defaults_to_traefik_in_source_mode(tmp_path):
    assert journey.parse_args(["--mode", "source", "--edge"]).edge_profile == "traefik"


def test_edge_profile_override(tmp_path):
    assert journey.parse_args(["--mode", "source", "--edge", "--edge-profile", "arr"]).edge_profile == "arr"


def test_edge_profile_needs_edge(capsys):
    with pytest.raises(SystemExit):
        journey.parse_args(["--mode", "source", "--edge-profile", "arr"])
    assert "--edge-profile needs --edge" in capsys.readouterr().err


def test_no_edge_by_default():
    a = journey.parse_args(["--mode", "source"])
    assert a.edge is False and a.edge_profile is None


def test_exe_mode_defaults_to_the_arr_profile():
    assert journey.EDGE_DEFAULT_PROFILE == {"source": "traefik", "exe": "arr"}


# --- client env ----------------------------------------------------------

def test_edge_client_env_forces_verification_with_the_run_ca(j):
    env = {"NETBRIDGE_VERIFY_SSL": "false", "NETBRIDGE_ALLOW_INSECURE": "1", "OTHER": "x"}
    j._edge_client_env(env, fake_edge())
    assert env == {"NETBRIDGE_CA_BUNDLE": "ca.pem", "NETBRIDGE_VERIFY_SSL": "true", "OTHER": "x"}


# --- client urls ---------------------------------------------------------

def test_client_urls_plain_without_edge(j):
    links = SimpleNamespace(url="ws://127.0.0.1:1", port=1), SimpleNamespace(url="ws://127.0.0.1:2", port=2)
    assert j._client_urls(*links, None) == ("ws://127.0.0.1:1", "ws://127.0.0.1:2")


@pytest.mark.parametrize("profile, prefix", [("traefik", ""), ("arr", "/netbridge")])
def test_client_urls_through_the_edge(j, profile, prefix):
    links = SimpleNamespace(url="ws://127.0.0.1:1", port=1), SimpleNamespace(url="ws://127.0.0.1:2", port=2)
    assert j._client_urls(*links, fake_edge(profile)) == (f"wss://127.0.0.1:1{prefix}/ws",
                                                          f"wss://127.0.0.1:2{prefix}/tunnel")


# --- edge_up -------------------------------------------------------------

def tls_fakes(monkeypatch, status=200, closed=True, on_wait=None):
    seen = {}

    @contextmanager
    def tls_connect(host, port, ctx, timeout=10.0):
        seen["connect"] = (host, port, ctx)
        yield "SOCK"

    def http_get(sock, host_header, path="/", timeout=15.0, keep_alive=False):
        seen.setdefault("gets", []).append((path, keep_alive))
        return status, b"{}"

    def wait_closed(sock, timeout):
        seen["wait"] = timeout
        if on_wait:
            on_wait()
        return closed

    monkeypatch.setattr(journey.clients, "tls_connect", tls_connect)
    monkeypatch.setattr(journey.clients, "http_get", http_get)
    monkeypatch.setattr(journey.clients, "wait_closed", wait_closed)
    return seen


def test_edge_status_uses_the_prefix_and_the_run_ca(j, monkeypatch):
    seen = tls_fakes(monkeypatch)
    ok, detail = j._edge_status(fake_edge("arr"))
    assert ok and seen["connect"] == ("127.0.0.1", 4443, "CTX") and seen["gets"] == [("/netbridge/status", False)]
    assert "HTTP 200" in detail and "arr" in detail


def test_edge_status_fails_on_non_200(j, monkeypatch):
    tls_fakes(monkeypatch, status=502)
    ok, detail = j._edge_status(fake_edge())
    assert not ok and "HTTP 502" in detail


# --- edge_client_ip ------------------------------------------------------

def fake_upgrades(monkeypatch, throttle_after=CAP, other=401, valid=101):
    calls = []
    count = {"bad": 0}

    def ws_upgrade(host, port, path, token, timeout=10, *, ssl_context=None, server_hostname=None,
                   extra_headers=None):
        entries = [e.strip() for e in extra_headers["X-Forwarded-For"].split(",")]
        assert entries[0] == journey.EDGE_SPOOF  # every request carries the spoofed leftmost entry
        client = entries[-1]
        calls.append((path, token, client, ssl_context))
        if token == "valid-token":
            return valid, ""
        if client == journey.EDGE_OTHER_CLIENT:
            return other, "Token validation failed"
        count["bad"] += 1
        return (429, "Too many") if count["bad"] > throttle_after else (401, "Token validation failed")

    monkeypatch.setattr(journey.clients, "ws_upgrade", ws_upgrade)
    return calls


def relay_with(text):
    return SimpleNamespace(logs=Logs(text))


LOGGED = f"Tunnel auth rejected for {journey.EDGE_CLIENT}: bad token"


def test_edge_client_ip_passes(j, monkeypatch):
    calls = fake_upgrades(monkeypatch)
    ok, detail = j._edge_client_ip(fake_edge("arr"), relay_with(LOGGED), Stub())
    assert ok, detail
    assert all(path == "/netbridge/tunnel" and ctx == "CTX" for path, _, _, ctx in calls)
    assert f"429 after {CAP + 1}" in detail
    assert calls[-2][2] == journey.EDGE_OTHER_CLIENT and calls[-1][1:3] == ("valid-token", journey.EDGE_CLIENT)


def test_edge_client_ip_needs_the_forwarded_ip_in_the_log(j, monkeypatch):
    fake_upgrades(monkeypatch)
    ok, detail = j._edge_client_ip(fake_edge(), relay_with("Tunnel auth rejected for 127.0.0.1: x"), Stub())
    assert not ok and "missing" in detail


def test_edge_client_ip_needs_a_429(j, monkeypatch):
    fake_upgrades(monkeypatch, throttle_after=10_000)
    ok, detail = j._edge_client_ip(fake_edge(), relay_with(LOGGED), Stub())
    assert not ok and f"within {CAP + 10}" in detail


@pytest.mark.parametrize("other, valid", [(429, 101), (401, 429)])
def test_edge_client_ip_buckets_are_per_forwarded_client(j, monkeypatch, other, valid):
    fake_upgrades(monkeypatch, other=other, valid=valid)
    ok, _ = j._edge_client_ip(fake_edge(), relay_with(LOGGED), Stub())
    assert not ok


# --- edge_appends_peer ---------------------------------------------------

def test_edge_appends_peer_passes(j, monkeypatch):
    calls = []

    def ws_upgrade(host, port, path, token, timeout=10, *, ssl_context=None, server_hostname=None,
                   extra_headers=None):
        calls.append((host, path, server_hostname, extra_headers))
        return 401, "Token validation failed"

    monkeypatch.setattr(journey.clients, "ws_upgrade", ws_upgrade)
    ok, detail = j._edge_appends_peer(fake_edge("arr"), relay_with("Tunnel auth rejected for 10.0.0.1: x"), "10.0.0.1")
    assert ok, detail
    assert calls == [("10.0.0.1", "/netbridge/tunnel", "127.0.0.1", {"X-Forwarded-For": journey.EDGE_SPOOF})]


@pytest.mark.parametrize("log", [
    "Tunnel auth rejected for 127.0.0.1: x",                                        # edge address, not the peer
    f"Tunnel auth rejected for 10.0.0.1: x\nTunnel auth rejected for {journey.EDGE_SPOOF}: x",  # spoof honoured
])
def test_edge_appends_peer_fails(j, monkeypatch, log):
    monkeypatch.setattr(journey.clients, "ws_upgrade", lambda *a, **k: (401, ""))
    ok, _ = j._edge_appends_peer(fake_edge(), relay_with(log), "10.0.0.1")
    assert not ok


def test_edge_appends_peer_needs_a_non_loopback_host(j):
    ok, detail = j._edge_appends_peer(fake_edge(), relay_with(""), "127.0.0.1")
    assert not ok and "loopback" in detail


# --- edge_relay_down_502 ------------------------------------------------

AGENT_502 = "ERROR Handshake failed: 502 Invalid response status\n"
PROXY_502 = "ERROR Reconnection failed: WebSocket handshake failed (502): Invalid response status\n"
MARKS = {"agent": None, "proxy": None}


def test_edge_relay_down_sees_both_clients(j, monkeypatch):
    edge = fake_edge()
    edge.bad_gateways.update({"/ws": 3})  # earlier 502s do not count
    before = dict(edge.bad_gateways)
    agent, proxy = SimpleNamespace(name="agent", logs=Logs()), SimpleNamespace(name="proxy", logs=Logs())

    def sleep(_):
        edge.bad_gateways.update({"/ws": 1, "/tunnel": 1})
        agent.logs, proxy.logs = Logs(AGENT_502), Logs(PROXY_502)

    monkeypatch.setattr(journey.time, "sleep", sleep)
    ok, detail = j._edge_relay_down(edge, agent, proxy, MARKS, before)
    assert ok and "agent (/ws) 1, proxy (/tunnel) 1" in detail and "agent True, proxy True" in detail


def test_edge_relay_down_fails_without_the_proxy(j, monkeypatch):
    edge = fake_edge()
    agent, proxy = SimpleNamespace(name="agent", logs=Logs(AGENT_502)), SimpleNamespace(name="proxy", logs=Logs())
    monkeypatch.setattr(journey, "EDGE_502_WAIT", 0.2)
    monkeypatch.setattr(journey.time, "sleep", lambda _: edge.bad_gateways.update({"/ws": 1}))
    ok, detail = j._edge_relay_down(edge, agent, proxy, MARKS, {})
    assert not ok and "proxy (/tunnel) 0" in detail


def test_edge_relay_down_fails_when_a_client_never_saw_the_502(j, monkeypatch):
    edge = fake_edge()
    agent = SimpleNamespace(name="agent", logs=Logs(AGENT_502))
    proxy = SimpleNamespace(name="proxy", logs=Logs("ERROR Reconnection failed: Connection failed: reset\n"))
    monkeypatch.setattr(journey, "EDGE_502_WAIT", 0.2)
    # the edge counts both 502s, but the proxy's response was lost to a reset
    monkeypatch.setattr(journey.time, "sleep", lambda _: edge.bad_gateways.update({"/ws": 1, "/tunnel": 1}))
    ok, detail = j._edge_relay_down(edge, agent, proxy, MARKS, {})
    assert not ok and "agent True, proxy False" in detail


def test_edge_relay_down_counts_502s_from_during_the_stop(j, monkeypatch):
    edge = fake_edge()
    before = dict(edge.bad_gateways)  # taken before relay.stop()
    edge.bad_gateways.update({"/ws": 1, "/tunnel": 1})  # both clients retried while the relay was stopping
    agent, proxy = SimpleNamespace(name="agent", logs=Logs(AGENT_502)), SimpleNamespace(name="proxy", logs=Logs(PROXY_502))
    monkeypatch.setattr(journey.time, "sleep", lambda _: pytest.fail("no wait needed"))
    ok, detail = j._edge_relay_down(edge, agent, proxy, MARKS, before)
    assert ok, detail


def test_reconnect_snapshots_502s_before_stopping_the_relay(j, monkeypatch):
    class Stop(Exception):
        pass

    edge = fake_edge()
    agent, proxy = SimpleNamespace(name="agent", logs=Logs(AGENT_502)), SimpleNamespace(name="proxy", logs=Logs(PROXY_502))

    def start():
        raise Stop  # the rest of _reconnect is not under test

    # both clients meet the 502 while relay.stop() is still running
    relay = SimpleNamespace(stop=lambda: edge.bad_gateways.update({"/ws": 1, "/tunnel": 1}), start=start)
    results = {}
    monkeypatch.setattr(j, "check", lambda name, fn: results.setdefault(name, fn()))
    monkeypatch.setattr(journey, "EDGE_502_WAIT", 0.2)
    monkeypatch.setattr(journey.time, "sleep", lambda _: None)
    with pytest.raises(Stop):
        j._reconnect(relay, agent, proxy, "10.0.0.1", None, edge)
    assert results["edge_relay_down_502"][0], results


def test_handshake_502_pattern_matches_both_clients():
    assert re.search(journey.HANDSHAKE_502, AGENT_502) and re.search(journey.HANDSHAKE_502, PROXY_502)
    assert not re.search(journey.HANDSHAKE_502, "Handshake failed: 401 Invalid response status")


# --- idle ----------------------------------------------------------------

def comp(name, sessions=1):
    return SimpleNamespace(name=name, logs=Logs("Connected to relay (session: abc)\n" * sessions))


def test_edge_idle_survives(j, monkeypatch):
    monkeypatch.setattr(journey.time, "sleep", lambda s: None)
    echoes = []
    monkeypatch.setattr(j, "_open_echo", lambda ip, t: echoes.append(1) or SimpleNamespace(close=lambda: None))
    ok, detail = j._edge_idle(fake_edge(idle=25.0), comp("agent"), comp("proxy"), "10.0.0.1", None)
    assert ok, detail
    assert echoes == [1] and "quiet for 30s" in detail


def test_edge_idle_fails_when_the_edge_closed_a_tunnel(j, monkeypatch):
    edge = fake_edge(idle=25.0)
    monkeypatch.setattr(journey.time, "sleep", lambda s: setattr(edge, "idle_closes", 1))
    monkeypatch.setattr(j, "_open_echo", lambda ip, t: SimpleNamespace(close=lambda: None))
    ok, detail = j._edge_idle(edge, comp("agent"), comp("proxy"), "10.0.0.1", None)
    assert not ok and "0->1" in detail


def test_edge_idle_fails_on_a_new_session(j, monkeypatch):
    agent = comp("agent")
    monkeypatch.setattr(journey.time, "sleep",
                        lambda s: setattr(agent, "logs", Logs("Connected to relay (session: abc)\n" * 2)))
    monkeypatch.setattr(j, "_open_echo", lambda ip, t: SimpleNamespace(close=lambda: None))
    ok, _ = j._edge_idle(fake_edge(idle=25.0), agent, comp("proxy"), "10.0.0.1", None)
    assert not ok


def test_dead_link_closed_by_the_edge(j, monkeypatch):
    edge = fake_edge("traefik", idle=0.0)
    seen = tls_fakes(monkeypatch, on_wait=lambda: setattr(edge, "idle_closes", 1))
    ok, detail = j._edge_dead_link(edge)
    assert ok, detail
    assert seen["gets"] == [("/status", True)] and seen["wait"] == 5.0


def test_dead_link_fails_when_nothing_closes_it(j, monkeypatch):
    tls_fakes(monkeypatch, closed=False)
    ok, _ = j._edge_dead_link(fake_edge(idle=0.0))
    assert not ok


def test_dead_link_fails_when_the_edge_did_not_count_it(j, monkeypatch):
    tls_fakes(monkeypatch)  # closed, but by someone else: the counter stays at 0
    ok, detail = j._edge_dead_link(fake_edge(idle=0.0))
    assert not ok and "counted 0" in detail
