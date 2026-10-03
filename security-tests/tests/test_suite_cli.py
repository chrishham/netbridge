"""The pentest suite against a fake relay on loopback (aiohttp test server)."""
import json
import socket

import pytest
from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestServer

import pentest_suite as ps

GOOD = "good-token"
MiB = 1024 * 1024


class FakeRelay:
    """A relay double: /status, /ws (always 401) and /tunnel with a configurable message behaviour.

    mode "reject": tcp_connect -> success false, everything else ignored (the real relay's behaviour)
    mode "accept": tcp_connect -> success true
    mode "drop":   any message closes the connection
    mode "silent": nothing is ever answered
    mode "no_agent": tcp_connect -> success false for a reason other than validation
    """

    def __init__(self, *, mode="reject", status=200, status_json=True, leak=False, max_msg_size=MiB, limit=20, die=False):
        self.mode, self.status, self.status_json, self.leak = mode, status, status_json, leak
        self.max_msg_size, self.limit, self.die = max_msg_size, limit, die
        self.connections = 0
        self.received: list[str] = []
        self.app = web.Application()
        self.app.router.add_get("/status", self.handle_status)
        self.app.router.add_get("/ws", self.handle_agent)
        self.app.router.add_get("/tunnel", self.handle_tunnel)
        self.url = ""

    async def handle_status(self, request):
        if not self.status_json:
            return web.Response(status=self.status, text="<html>proxy error</html>")
        body = {"status": "ok", "auth_required": True}
        if self.leak:
            body["agents"] = 1
        return web.json_response(body, status=self.status)

    async def handle_agent(self, request):
        return web.Response(status=401, text="Missing Authorization header")

    async def handle_tunnel(self, request):
        if request.headers.get("Authorization") != f"Bearer {GOOD}":
            return web.Response(status=401, text="Token validation failed")
        if self.connections >= self.limit:
            return web.Response(status=429, text="Too many connection attempts")
        self.connections += 1
        ws = web.WebSocketResponse(max_msg_size=self.max_msg_size)
        await ws.prepare(request)
        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            self.received.append(msg.data)
            if self.mode == "drop":
                if self.die:  # the message "crashed" the relay: /status fails from now on
                    self.status = 500
                await ws.close()
                break
            if self.mode == "silent":
                continue
            try:
                data = json.loads(msg.data)
            except ValueError:
                continue
            if data.get("type") == "tcp_connect":
                await ws.send_str(json.dumps({"type": "tcp_connect_result", "stream_id": data.get("stream_id"),
                                              "success": self.mode == "accept",
                                              "error": "No bridge agent available" if self.mode == "no_agent"
                                              else "Invalid host format"}))
        return ws


@pytest.fixture(autouse=True)
def short_waits(monkeypatch):
    monkeypatch.setattr(ps.PenTestSuite, "REPLY_TIMEOUT", 0.2)


@pytest.fixture
async def relay():
    servers = []

    async def start(**kw) -> FakeRelay:
        fake = FakeRelay(**kw)
        server = TestServer(fake.app, host="127.0.0.1")
        await server.start_server()
        servers.append(server)
        fake.url = f"ws://127.0.0.1:{server.port}"
        return fake

    yield start
    for server in servers:
        await server.close()


def dead_url() -> str:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"ws://127.0.0.1:{port}"


# --- precheck ----------------------------------------------------------------

async def test_precheck_passes_with_status_json_and_a_working_token(relay):
    fake = await relay()
    assert await ps.PenTestSuite(fake.url, GOOD).precheck() is None
    assert fake.connections == 1  # the authenticated upgrade really happened


async def test_precheck_without_token_only_needs_status(relay):
    fake = await relay()
    assert await ps.PenTestSuite(fake.url).precheck() is None
    assert fake.connections == 0


async def test_precheck_fails_on_a_dead_relay():
    error = await ps.PenTestSuite(dead_url(), GOOD).precheck()
    assert error and "/status" in error


async def test_precheck_fails_on_status_500(relay):
    fake = await relay(status=500)
    error = await ps.PenTestSuite(fake.url, GOOD).precheck()
    assert error and "500" in error


async def test_precheck_fails_on_non_json_status(relay):
    fake = await relay(status_json=False)
    error = await ps.PenTestSuite(fake.url, GOOD).precheck()
    assert error and "JSON" in error


async def test_precheck_fails_on_a_bad_token(relay):
    fake = await relay()
    error = await ps.PenTestSuite(fake.url, "bad-token").precheck()
    assert error and "/tunnel" in error and "401" in error


async def test_main_exits_2_when_precheck_fails(capsys):
    assert await ps.main([dead_url(), "--token", GOOD]) == 2
    out = capsys.readouterr().out
    assert "Precheck failed" in out and "/status" in out
    assert "[PASS]" not in out  # no test ran


# --- authenticated tests fail when the handshake fails --------------------------

@pytest.mark.parametrize("test", ["session_hijack", "large_payload_dos", "rapid_connection_dos",
                                  "invalid_message_types", "host_port_injection"])
async def test_authenticated_test_fails_on_401(relay, test):
    fake = await relay()
    result = await getattr(ps.PenTestSuite(fake.url, "bad-token"), f"test_{test}")()
    assert result.passed is False
    assert result.severity == "HIGH"
    assert result.details.startswith("authenticated connection failed:") and "401" in result.details


# --- observable outcomes ----------------------------------------------------------

async def test_host_port_injection_passes_on_explicit_rejections(relay):
    fake = await relay(mode="reject")
    result = await ps.PenTestSuite(fake.url, GOOD).test_host_port_injection()
    assert result.passed, result.details
    assert len(fake.received) == 8


@pytest.mark.parametrize("mode, words", [("drop", "connection closed"), ("silent", "no reply"),
                                         ("accept", "accepted")])
async def test_host_port_injection_fails_without_a_rejection(relay, mode, words):
    fake = await relay(mode=mode)
    result = await ps.PenTestSuite(fake.url, GOOD).test_host_port_injection()
    assert result.passed is False and result.severity == "CRITICAL"
    assert words in result.details


async def test_invalid_message_types_passes_when_ignored_and_healthy(relay):
    fake = await relay(mode="reject")
    result = await ps.PenTestSuite(fake.url, GOOD).test_invalid_message_types()
    assert result.passed, result.details
    # every invalid message was followed by a health probe on the same connection
    assert len(fake.received) == 2 * len(ps.INVALID_MESSAGES)


@pytest.mark.parametrize("mode, words", [("drop", "connection closed"), ("silent", "no reply")])
async def test_invalid_message_types_fails_without_proven_health(relay, mode, words):
    fake = await relay(mode=mode)
    result = await ps.PenTestSuite(fake.url, GOOD).test_invalid_message_types()
    assert result.passed is False
    assert words in result.details


async def test_large_payload_passes_when_the_relay_closes(relay):
    fake = await relay(max_msg_size=MiB)
    result = await ps.PenTestSuite(fake.url, GOOD).test_large_payload_dos()
    assert result.passed, result.details
    assert "1009" in result.details


async def test_large_payload_passes_on_a_drop_when_the_relay_survives(relay):
    fake = await relay(mode="drop", max_msg_size=0)
    result = await ps.PenTestSuite(fake.url, GOOD).test_large_payload_dos()
    assert result.passed, result.details
    assert "relay still answers" in result.details


async def test_large_payload_fails_when_the_relay_dies(relay):
    fake = await relay(mode="drop", max_msg_size=0, die=True)
    result = await ps.PenTestSuite(fake.url, GOOD).test_large_payload_dos()
    assert result.passed is False and result.severity == "HIGH"
    assert "relay down afterwards" in result.details


async def test_large_payload_fails_on_silence(relay):
    fake = await relay(mode="silent", max_msg_size=0)  # 0 = no limit: the payload is swallowed
    result = await ps.PenTestSuite(fake.url, GOOD).test_large_payload_dos()
    assert result.passed is False
    assert "no close or error" in result.details


async def test_rate_limiting_passes_on_429(relay):
    fake = await relay(limit=3)
    result = await ps.PenTestSuite(fake.url, GOOD).test_rapid_connection_dos()
    assert result.passed, result.details


async def test_unauthenticated_test_still_passes_on_401(relay):
    fake = await relay()
    result = await ps.PenTestSuite(fake.url, GOOD).test_no_auth_bypass()
    assert result.passed, result.details


async def test_status_check_reads_the_http_url_of_a_ws_relay(relay):
    fake = await relay(leak=True)
    result = await ps.PenTestSuite(fake.url, GOOD).test_health_endpoint()
    assert result.passed is False and "agents" in result.details


# --- --skip, --strict, errors ---------------------------------------------------------

async def test_skip_marks_results_without_running_them(relay):
    fake = await relay()
    suite = ps.PenTestSuite(fake.url, GOOD, skip=["rapid_connection_dos", "session_hijack"])
    results = {r.name: r for r in await suite.run_all_tests()}
    for name in ("rapid_connection_dos", "session_hijack"):
        assert results[name].passed is True and results[name].severity == "SKIP"
        assert results[name].details.startswith("skipped: ")
    assert fake.connections < 5  # the 35-connection burst never ran
    assert all(r.passed for r in results.values()), [r for r in results.values() if not r.passed]


def test_unknown_skip_name_is_an_argparse_error(capsys):
    with pytest.raises(SystemExit) as exc:
        ps.parse_args(["ws://x", "--skip", "no_such_test"])
    assert exc.value.code == 2
    assert "no_such_test" in capsys.readouterr().err


def test_skip_is_repeatable():
    args = ps.parse_args(["ws://x", "--skip", "session_hijack", "--skip", "stream_id_enumeration", "--strict"])
    assert args.skip == ["session_hijack", "stream_id_enumeration"] and args.strict


async def test_strict_fails_on_a_non_critical_failure_default_does_not(relay, capsys):
    fake = await relay(leak=True)  # status leaks a count: a MEDIUM finding
    assert await ps.main([fake.url, "--token", GOOD]) == 0
    fake = await relay(leak=True)
    assert await ps.main([fake.url, "--token", GOOD, "--strict"]) == 1
    out = capsys.readouterr().out
    assert "Passed: 10" in out and "Failed: 1" in out


async def test_strict_passes_on_a_clean_relay(relay, capsys):
    fake = await relay()
    assert await ps.main([fake.url, "--token", GOOD, "--strict", "--skip", "stream_id_enumeration"]) == 0
    out = capsys.readouterr().out
    assert "Passed: 11" in out and "Failed: 0" in out and "Skipped: 1" in out


async def test_default_fails_on_a_critical_failure(relay):
    fake = await relay(mode="accept")  # injection payloads accepted: CRITICAL
    assert await ps.main([fake.url, "--token", GOOD]) == 1


async def test_exceptions_are_error_failures(relay, monkeypatch):
    async def boom(self):
        raise RuntimeError("kaputt")

    monkeypatch.setattr(ps.PenTestSuite, "test_stream_id_enumeration", boom)
    fake = await relay()
    results = await ps.PenTestSuite(fake.url, GOOD).run_all_tests()
    [err] = [r for r in results if not r.passed]
    assert err.severity == "ERROR" and "kaputt" in err.details
    assert ps.exit_code(results, strict=True) == 1
    assert ps.exit_code(results, strict=False) == 0


def test_exit_code_rules():
    ok = ps.TestResult("a", True, "CRITICAL", "")
    skipped = ps.TestResult("b", True, "SKIP", "skipped: x")
    low = ps.TestResult("c", False, "LOW", "")
    critical = ps.TestResult("d", False, "CRITICAL", "")
    assert ps.exit_code([ok, skipped], strict=True) == 0
    assert ps.exit_code([ok, low], strict=False) == 0
    assert ps.exit_code([ok, low], strict=True) == 1
    assert ps.exit_code([critical], strict=False) == 1


async def test_host_port_injection_fails_on_an_unrelated_refusal(relay):
    fake = await relay(mode="no_agent")
    result = await ps.PenTestSuite(fake.url, GOOD).test_host_port_injection()
    assert not result.passed and "validation unproven" in result.details


@pytest.mark.parametrize("test", ["no_auth_bypass", "invalid_token", "expired_token", "malformed_jwt",
                                  "websocket_without_auth"])
async def test_rejection_tests_fail_when_the_relay_does_not_answer(test):
    result = await getattr(ps.PenTestSuite(dead_url(), GOOD), f"test_{test}")()
    assert result.passed is False and result.severity == "HIGH"
    assert "no answer from the relay" in result.details


async def test_rate_limiting_without_token_is_a_skip(relay):
    fake = await relay()
    result = await ps.PenTestSuite(fake.url).test_rapid_connection_dos()
    assert result.severity == "SKIP"


def test_empty_token_is_an_argparse_error(capsys):
    with pytest.raises(SystemExit):
        ps.parse_args(["ws://127.0.0.1:1", "--token", ""])
    assert "--token is empty" in capsys.readouterr().err


async def test_status_check_fails_when_status_is_unreadable():
    result = await ps.PenTestSuite(dead_url()).test_health_endpoint()
    assert not result.passed and "nothing checked" in result.details


async def test_stream_id_enumeration_is_reported_as_a_skip():
    result = await ps.PenTestSuite(dead_url()).test_stream_id_enumeration()
    assert result.severity == "SKIP"


@pytest.mark.parametrize("text, ok", [
    ('{"type": "error", "error": "Message too large"}', True),
    ('{"accepted": true, "error": null}', False),
    ('{"success": true, "error": "x"}', False),
    ('"error"', False),
    ("not json error", False),
])
def test_is_error_reply(text, ok):
    assert ps._is_error_reply(text) is ok


async def test_status_check_fails_on_a_non_200_status(relay):
    fake = await relay(status=503)
    result = await ps.PenTestSuite(fake.url).test_health_endpoint()
    assert not result.passed and "503" in result.details
