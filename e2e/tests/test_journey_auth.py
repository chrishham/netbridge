"""The journey's auth steps against fakes: no relay, no key stub, no sockets."""
import re
from types import SimpleNamespace

import pytest

from netbridge_e2e import clients, journey
from netbridge_e2e.jwtmint import ISSUER_V2

TARGETS = SimpleNamespace(echo_port=7, http_port=80)
IP = "10.0.0.1"
CASES = ["none", "garbage", "wrong signature", "unknown kid", "expired", "not yet valid", "wrong tenant",
         "wrong issuer", "wrong audience", "no identity", "no kid", "malformed payload", "valid"]


@pytest.fixture
def j(tmp_path):
    return journey.Journey(journey.parse_args(["--mode", "source", "--work", str(tmp_path)]))


class FakeStub:
    """mint() returns a readable token: header.payload.sig with the keyword arguments in the payload."""

    kid = "k1"

    def __init__(self):
        self.fetches = 0

    def mint(self, **kw) -> str:
        return f"hdr.{sorted(kw.items())}.sig"

    def foreign_mint(self, **kw) -> str:
        return "hdr.foreign.sig"

    def requests(self) -> int:
        return self.fetches


class FakeLogs:
    def __init__(self, text: str = ""):
        self.text = text

    def wait_for(self, pattern, timeout, since=None, alive=None):
        return re.search(pattern, self.text)


class FakeRelay:
    port = 18080

    def __init__(self, logs: str = "", status: dict | None = None):
        self.logs = FakeLogs(logs)
        self._status = status

    def status(self):
        return self._status


REJECTED_LOGS = "Agent auth rejected for 127.0.0.1: x\nTunnel auth rejected for 127.0.0.1: y"


def fake_relay_auth(stub, overrides=None, on_upgrade=None):
    """A ws_upgrade that answers each case with its expected outcome, unless overridden by (case, path)."""
    by_token = {token: (case, reason) for case, token, reason in journey.Journey._auth_cases(stub)}
    calls = []

    def ws_upgrade(host, port, path, token):
        case, reason = by_token[token]
        calls.append((case, path))
        if on_upgrade:
            on_upgrade(case, path)
        if overrides and (case, path) in overrides:
            return overrides[(case, path)]
        return (101, "") if reason is None else (401, f"{reason}: details")

    return ws_upgrade, calls


def test_auth_cases_pin_the_relay_reasons():
    cases = journey.Journey._auth_cases(FakeStub())
    assert [c[0] for c in cases] == CASES
    reasons = {case: reason for case, _, reason in cases}
    assert reasons["none"] == "Missing Authorization header"
    assert reasons["not yet valid"] == "Token not yet valid"
    assert reasons["no kid"] == "No key ID in token header"
    assert reasons["malformed payload"] == "Token validation failed"
    assert reasons["valid"] is None
    tokens = {case: token for case, token, _ in cases}
    assert tokens["none"] is None and tokens["garbage"] == "not-a-jwt"
    assert tokens["wrong signature"] == "hdr.foreign.sig"
    assert tokens["malformed payload"] == "hdr.@@@not-base64@@@.sig"  # header from a real mint
    other_iss = ISSUER_V2.format(tid=journey.OTHER_TENANT)
    assert f"('iss', '{other_iss}')" in tokens["wrong tenant"] and journey.OTHER_TENANT in tokens["wrong tenant"]
    assert "('upn', None)" in tokens["no identity"]
    assert "('header', {'kid': None})" in tokens["no kid"]
    assert "matrix@netbridge.test" in tokens["valid"]


def test_auth_matrix_all_match_passes(j, monkeypatch):
    stub = FakeStub()
    upgrade, calls = fake_relay_auth(stub)
    monkeypatch.setattr(clients, "ws_upgrade", upgrade)
    ok, detail = j._auth_matrix(FakeRelay(REJECTED_LOGS), stub)
    assert ok, detail
    assert "26/26" in detail
    assert len(calls) == 26 and {p for _, p in calls} == {"/ws", "/tunnel"}


def test_auth_matrix_wrong_reason_names_the_case(j, monkeypatch):
    stub = FakeStub()
    upgrade, _ = fake_relay_auth(stub, {("expired", "/tunnel"): (401, "Invalid audience: x")})
    monkeypatch.setattr(clients, "ws_upgrade", upgrade)
    ok, detail = j._auth_matrix(FakeRelay(REJECTED_LOGS), stub)
    assert not ok
    assert "25/26" in detail and "expired /tunnel: HTTP 401 'Invalid audience: x'" in detail
    assert "expired /ws" not in detail


def test_auth_matrix_valid_token_must_upgrade(j, monkeypatch):
    stub = FakeStub()
    upgrade, _ = fake_relay_auth(stub, {("valid", "/ws"): (401, "Signing key not found: k1")})
    monkeypatch.setattr(clients, "ws_upgrade", upgrade)
    ok, detail = j._auth_matrix(FakeRelay(REJECTED_LOGS), stub)
    assert not ok and "valid /ws: HTTP 401" in detail and "want 101" in detail


def test_auth_matrix_wrong_tenant_must_not_fetch_keys(j, monkeypatch):
    stub = FakeStub()

    def fetch(case, path):
        if case == "wrong tenant" and path == "/ws":
            stub.fetches += 1

    upgrade, _ = fake_relay_auth(stub, on_upgrade=fetch)
    monkeypatch.setattr(clients, "ws_upgrade", upgrade)
    ok, detail = j._auth_matrix(FakeRelay(REJECTED_LOGS), stub)
    assert not ok
    assert "wrong tenant /ws" in detail and "fetched keys for a rejected tenant" in detail
    assert "wrong tenant /tunnel" not in detail


def test_auth_matrix_needs_both_rejection_log_lines(j, monkeypatch):
    stub = FakeStub()
    upgrade, _ = fake_relay_auth(stub)
    monkeypatch.setattr(clients, "ws_upgrade", upgrade)
    ok, detail = j._auth_matrix(FakeRelay("Agent auth rejected for 127.0.0.1: x"), stub)
    assert not ok and "no 'Tunnel auth rejected' relay log line" in detail and "Agent auth rejected'" not in detail


@pytest.mark.parametrize("logs, status, ok", [
    ("E2E: relay key URL redirected to http://127.0.0.1:5/t/keys", {"auth_required": True}, True),
    ("", {"auth_required": True}, False),
    ("E2E: relay key URL redirected to http://127.0.0.1:5/t/keys", {"auth_required": False}, False),
    ("E2E: relay key URL redirected to http://127.0.0.1:5/t/keys", None, False),
])
def test_relay_auth_on_needs_redirect_and_auth_required(j, logs, status, ok):
    stub = FakeStub()
    stub.jwks_url = "http://127.0.0.1:5/t/keys"
    got, detail = j._relay_auth_on(FakeRelay(logs, status), stub)
    assert got is ok
    assert "auth_required=" in detail
    assert ("http://127.0.0.1:5/t/keys" in detail) == bool(logs)


@pytest.mark.parametrize("logged", ["http://127.0.0.1:6/t/keys", "http://127.0.0.1:5/t/keys2"])
def test_relay_auth_on_needs_the_stub_url_exactly(j, logged):
    stub = FakeStub()
    stub.jwks_url = "http://127.0.0.1:5/t/keys"
    got, _ = j._relay_auth_on(FakeRelay(f"E2E: relay key URL redirected to {logged}", {"auth_required": True}), stub)
    assert got is False


def test_auth_matrix_reports_a_connection_error_and_carries_on(j, monkeypatch):
    stub = FakeStub()
    upgrade, calls = fake_relay_auth(stub)

    def flaky(host, port, path, token):
        if token is None and path == "/ws":
            upgrade(host, port, path, token)
            raise ConnectionResetError("reset by peer")
        return upgrade(host, port, path, token)

    monkeypatch.setattr(clients, "ws_upgrade", flaky)
    ok, detail = j._auth_matrix(FakeRelay(REJECTED_LOGS), stub)
    assert not ok
    assert "none /ws: HTTP None 'ConnectionResetError: reset by peer'" in detail
    assert len(calls) == 2 * len(CASES)


class FakeWs:
    """Answers tcp_connect from the journey user with success, from anyone else with "no agent"."""

    sessions: list["FakeWs"] = []
    agent_user = "e2e@netbridge.test"

    def __init__(self, token: str):
        self.token, self.sent, self.closed = token, [], False

    @classmethod
    def connect(cls, host, port, path, token, timeout=10):
        assert path == "/tunnel"
        ws = cls(token)
        cls.sessions.append(ws)
        return ws

    def send_json(self, obj):
        self.sent.append(obj)

    def recv_json(self, timeout):
        sid = self.sent[-1]["stream_id"]
        if f"('upn', '{journey.OTHER_USER}')" not in self.token:
            return {"type": "tcp_connect_result", "stream_id": sid, "success": True}
        return {"type": "tcp_connect_result", "stream_id": sid, "success": False, "error": journey.NO_AGENT,
                "error_code": "no_agent"}

    def close(self):
        self.closed = True


class EchoSock:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


@pytest.fixture
def tunnel(monkeypatch, j):
    FakeWs.sessions = []
    monkeypatch.setattr(clients, "WsClient", FakeWs)
    echo = EchoSock()
    monkeypatch.setattr(j, "_open_echo", lambda ip, targets: echo)
    monkeypatch.setattr(clients, "echo_roundtrip", lambda s, data: data)
    return echo


def test_user_isolation_passes(j, tunnel):
    ok, detail = j._user_isolation(FakeRelay(), FakeStub(), IP, TARGETS)
    assert ok, detail
    other, mine = FakeWs.sessions
    assert other.sent[0]["type"] == "tcp_connect" and other.sent[0]["host"] == IP and other.sent[0]["port"] == 80
    assert len(other.sent) == 1  # nothing to close: the stream never opened
    assert mine.sent[1] == {"type": "tcp_close", "stream_id": mine.sent[0]["stream_id"]}
    assert other.closed and mine.closed and tunnel.closed
    assert journey.NO_AGENT in detail and "before and after: True" in detail


def test_user_isolation_fails_without_the_no_agent_error_code(j, tunnel, monkeypatch):
    real = tunnel
    orig = j._tunnel_connect

    def no_code(*a, **k):
        r = dict(orig(*a, **k))
        r.pop("error_code", None)
        return r

    monkeypatch.setattr(j, "_tunnel_connect", no_code)
    ok, _ = j._user_isolation(FakeRelay(), FakeStub(), IP, TARGETS)
    assert not ok


def test_user_isolation_fails_when_other_user_reaches_an_agent(j, tunnel, monkeypatch):
    monkeypatch.setattr(FakeWs, "recv_json",
                        lambda self, timeout: {"type": "tcp_connect_result", "stream_id": self.sent[-1]["stream_id"],
                                               "success": True})
    ok, detail = j._user_isolation(FakeRelay(), FakeStub(), IP, TARGETS)
    assert not ok and f"{journey.OTHER_USER}: " in detail and '"success": true' in detail


def test_user_isolation_fails_when_control_fails(j, tunnel, monkeypatch):
    monkeypatch.setattr(FakeWs, "recv_json",
                        lambda self, timeout: {"type": "tcp_connect_result", "stream_id": self.sent[-1]["stream_id"],
                                               "success": False, "error": journey.NO_AGENT})
    ok, detail = j._user_isolation(FakeRelay(), FakeStub(), IP, TARGETS)
    assert not ok
    assert len(FakeWs.sessions[1].sent) == 1  # no tcp_close for a stream that never opened


def test_user_isolation_fails_when_echo_breaks_afterwards(j, tunnel, monkeypatch):
    monkeypatch.setattr(clients, "echo_roundtrip", lambda s, data: b"")
    ok, detail = j._user_isolation(FakeRelay(), FakeStub(), IP, TARGETS)
    assert not ok and "before and after: False" in detail
    assert tunnel.closed


def test_tunnel_connect_closes_the_session_on_error(j, monkeypatch):
    FakeWs.sessions = []
    monkeypatch.setattr(clients, "WsClient", FakeWs)

    def boom(self, timeout):
        raise TimeoutError("no reply")

    monkeypatch.setattr(FakeWs, "recv_json", boom)
    with pytest.raises(TimeoutError):
        j._tunnel_connect(FakeRelay(), "tok", IP, TARGETS)
    assert FakeWs.sessions[0].closed


PENTEST_OUT = """[PASS] [CRITICAL] No-Auth Bypass
[SKIP] session_hijack: skipped: requested with --skip

Total Tests: 12
Passed: 9
Failed: 0
Skipped: 3
"""


class FakeRun:
    """subprocess.run double: writes `output` to the stdout file and returns `code` (or times out)."""

    def __init__(self, output: str = PENTEST_OUT, code: int = 0, timeout: bool = False):
        self.output, self.code, self.timeout, self.calls = output, code, timeout, []

    def __call__(self, cmd, stdout, stderr, env, timeout):
        self.calls.append({"cmd": cmd, "stderr": stderr, "env": env, "timeout": timeout})
        stdout.write(self.output)
        stdout.flush()
        if self.timeout:
            raise journey.subprocess.TimeoutExpired(cmd, timeout)
        return journey.subprocess.CompletedProcess(cmd, self.code)


def test_pentest_runs_the_strict_suite_and_reports_the_summary(j, tmp_path, monkeypatch):
    run = FakeRun()
    monkeypatch.setattr(journey.subprocess, "run", run)
    ok, detail = j._pentest(FakeRelay(), FakeStub(), {"E": "1", "VIRTUAL_ENV": "e2e/.venv"}, tmp_path)
    assert ok, detail
    assert detail == "Passed: 9; Failed: 0; Skipped: 3"
    [call] = run.calls
    suite = journey.REPO / "security-tests"
    token = FakeStub().mint(upn="pentest@netbridge.test")
    assert call["cmd"] == ["uv", "run", "--project", str(suite), "python", str(suite / "pentest_suite.py"),
                           "ws://127.0.0.1:18080", "--token", token, "--strict",
                           "--skip", "rapid_connection_dos", "--skip", "session_hijack",
                           "--skip", "stream_id_enumeration"]
    assert call["timeout"] == 180 and call["env"] == {"E": "1"} and call["stderr"] is journey.subprocess.STDOUT
    assert (tmp_path / "pentest.log").read_text() == PENTEST_OUT


def test_pentest_fails_on_a_non_zero_exit_with_the_log_tail(j, tmp_path, monkeypatch):
    out = "x" * 1000 + "\nPrecheck failed: GET http://127.0.0.1:18080/status failed\n"
    monkeypatch.setattr(journey.subprocess, "run", FakeRun(out, code=2))
    ok, detail = j._pentest(FakeRelay(), FakeStub(), {}, tmp_path)
    assert not ok
    assert detail.startswith("exit 2 (log ") and str(tmp_path / "pentest.log") in detail
    assert detail.endswith(out[-600:]) and "x" * 601 not in detail


def test_pentest_fails_on_timeout_keeping_the_partial_log(j, tmp_path, monkeypatch):
    monkeypatch.setattr(journey.subprocess, "run", FakeRun("[PASS] [CRITICAL] No-Auth Bypass\n", timeout=True))
    ok, detail = j._pentest(FakeRelay(), FakeStub(), {}, tmp_path)
    assert not ok and detail.startswith("timed out after 180s") and "No-Auth Bypass" in detail
    assert "No-Auth Bypass" in (tmp_path / "pentest.log").read_text()


def test_pentest_step_runs_in_source_mode(j, tmp_path, monkeypatch):
    monkeypatch.setattr(journey.subprocess, "run", FakeRun(code=1))
    with pytest.raises(journey.StepFailed):
        j._pentest_step(FakeRelay(), FakeStub(), {}, tmp_path)
    assert j.results[-1]["step"] == "pentest_suite" and j.results[-1]["detail"].startswith("exit 1")


def test_pentest_step_is_a_recorded_skip_in_exe_mode(j, tmp_path, monkeypatch):
    run = FakeRun()
    monkeypatch.setattr(journey.subprocess, "run", run)
    j.args.mode = "exe"
    j._pentest_step(FakeRelay(), FakeStub(), {}, tmp_path)
    assert j.results[-1] == {"step": "pentest_suite", "ok": True, "detail": "skipped: exe mode has no checkout"}
    assert run.calls == []
