"""Tests for relay.__main__ — input validation, parsing, WebSocket helpers, and handlers."""

import asyncio
import json
import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from relay.__main__ import (
    _get_int_env,
    _is_loopback,
    _JSONFormatter,
    _parse_blocked_ports,
    _parse_destination_list,
    authenticate_request,
    create_app,
    handle_status,
    safe_ws_send,
    validate_tcp_connect_params,
)


# ---------------------------------------------------------------------------
# _is_loopback
# ---------------------------------------------------------------------------
class TestIsLoopback:
    """Tests for _is_loopback()."""

    def test_ipv4_loopback(self):
        assert _is_loopback("127.0.0.1") is True

    def test_localhost(self):
        assert _is_loopback("localhost") is True

    def test_ipv6_loopback(self):
        assert _is_loopback("::1") is True

    def test_all_interfaces(self):
        """0.0.0.0 is NOT loopback."""
        assert _is_loopback("0.0.0.0") is False

    def test_external_ip(self):
        assert _is_loopback("192.168.1.1") is False


# ---------------------------------------------------------------------------
# _get_int_env
# ---------------------------------------------------------------------------
class TestGetIntEnv:
    """Tests for _get_int_env()."""

    def test_present_valid(self, monkeypatch):
        monkeypatch.setenv("TEST_RELAY_INT", "99")
        assert _get_int_env("TEST_RELAY_INT", 1) == 99

    def test_present_invalid(self, monkeypatch):
        monkeypatch.setenv("TEST_RELAY_INT", "xyz")
        assert _get_int_env("TEST_RELAY_INT", 5) == 5

    def test_missing(self, monkeypatch):
        monkeypatch.delenv("TEST_RELAY_INT", raising=False)
        assert _get_int_env("TEST_RELAY_INT", 7) == 7


# ---------------------------------------------------------------------------
# validate_tcp_connect_params
# ---------------------------------------------------------------------------
class TestValidateTcpConnectParams:
    """Tests for validate_tcp_connect_params()."""

    def test_valid(self):
        ok, err = validate_tcp_connect_params("example.com", 443)
        assert ok is True
        assert err == ""

    def test_valid_ip(self):
        ok, _ = validate_tcp_connect_params("10.0.0.1", 80)
        assert ok is True

    def test_non_string_host(self):
        ok, err = validate_tcp_connect_params(123, 80)
        assert ok is False
        assert "string" in err.lower()

    def test_empty_host(self):
        ok, err = validate_tcp_connect_params("", 80)
        assert ok is False
        assert "length" in err.lower()

    def test_too_long_host(self):
        ok, err = validate_tcp_connect_params("a" * 256, 80)
        assert ok is False
        assert "length" in err.lower()

    def test_invalid_host_format(self):
        ok, err = validate_tcp_connect_params("exam ple.com", 80)
        assert ok is False
        assert "invalid" in err.lower()

    def test_non_int_port(self):
        ok, err = validate_tcp_connect_params("example.com", "80")
        assert ok is False
        assert "integer" in err.lower()

    def test_port_zero(self):
        ok, err = validate_tcp_connect_params("example.com", 0)
        assert ok is False
        assert "range" in err.lower()

    def test_port_too_high(self):
        ok, err = validate_tcp_connect_params("example.com", 70000)
        assert ok is False
        assert "range" in err.lower()


# ---------------------------------------------------------------------------
# _parse_blocked_ports
# ---------------------------------------------------------------------------
class TestParseBlockedPorts:
    """Tests for _parse_blocked_ports()."""

    def test_empty(self):
        assert _parse_blocked_ports("") == set()

    def test_single(self):
        assert _parse_blocked_ports("3389") == {3389}

    def test_multiple(self):
        assert _parse_blocked_ports("22,3389,5900") == {22, 3389, 5900}

    def test_invalid_entries_skipped(self):
        assert _parse_blocked_ports("22,abc,80") == {22, 80}

    def test_out_of_range_skipped(self):
        assert _parse_blocked_ports("0,80,99999") == {80}


# ---------------------------------------------------------------------------
# _parse_destination_list
# ---------------------------------------------------------------------------
class TestParseDestinationList:
    """Tests for _parse_destination_list()."""

    def test_empty(self, monkeypatch):
        monkeypatch.delenv("TEST_DEST", raising=False)
        cidrs, patterns = _parse_destination_list("TEST_DEST")
        assert cidrs == []
        assert patterns == []

    def test_cidrs(self, monkeypatch):
        monkeypatch.setenv("TEST_DEST", "10.0.0.0/8,192.168.0.0/16")
        cidrs, patterns = _parse_destination_list("TEST_DEST")
        assert len(cidrs) == 2
        assert patterns == []

    def test_hostname_patterns(self, monkeypatch):
        monkeypatch.setenv("TEST_DEST", "*.evil.com,bad.org")
        cidrs, patterns = _parse_destination_list("TEST_DEST")
        assert cidrs == []
        assert len(patterns) == 2
        assert "*.evil.com" in patterns

    def test_mixed(self, monkeypatch):
        monkeypatch.setenv("TEST_DEST", "10.0.0.0/8,*.corp.com")
        cidrs, patterns = _parse_destination_list("TEST_DEST")
        assert len(cidrs) == 1
        assert len(patterns) == 1


# ---------------------------------------------------------------------------
# _JSONFormatter
# ---------------------------------------------------------------------------
class TestJSONFormatter:
    """Tests for _JSONFormatter."""

    def test_output_is_valid_json(self):
        formatter = _JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello world", args=(), exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["msg"] == "hello world"
        assert "ts" in data
        assert "logger" in data


# ---------------------------------------------------------------------------
# safe_ws_send
# ---------------------------------------------------------------------------
class TestSafeWsSend:
    """Tests for safe_ws_send()."""

    @pytest.mark.asyncio
    async def test_success(self):
        ws = AsyncMock()
        ws.closed = False
        result = await safe_ws_send(ws, '{"type":"test"}')
        assert result is True
        ws.send_str.assert_called_once()

    @pytest.mark.asyncio
    async def test_closed_ws(self):
        ws = AsyncMock()
        ws.closed = True
        result = await safe_ws_send(ws, '{"type":"test"}')
        assert result is False

    @pytest.mark.asyncio
    async def test_exception_during_send(self):
        ws = AsyncMock()
        ws.closed = False
        ws.send_str.side_effect = ConnectionResetError("reset")
        result = await safe_ws_send(ws, '{"type":"test"}')
        assert result is False

    @pytest.mark.asyncio
    async def test_silent_mode_suppresses_logging(self, caplog):
        ws = AsyncMock()
        ws.closed = False
        ws.send_str.side_effect = Exception("oops")
        with caplog.at_level(logging.WARNING):
            result = await safe_ws_send(ws, "msg", silent=True)
        assert result is False
        assert "oops" not in caplog.text


# ---------------------------------------------------------------------------
# authenticate_request
# ---------------------------------------------------------------------------
class TestAuthenticateRequest:
    """Tests for authenticate_request()."""

    @pytest.mark.asyncio
    async def test_no_auth_mode(self, monkeypatch):
        """When REQUIRE_AUTH is False, returns anonymous."""
        import relay.__main__ as mod
        original = mod.REQUIRE_AUTH
        mod.REQUIRE_AUTH = False
        try:
            request = MagicMock()
            ok, result = await authenticate_request(request)
            assert ok is True
            assert "anonymous" in result
        finally:
            mod.REQUIRE_AUTH = original

    @pytest.mark.asyncio
    async def test_missing_header(self):
        """Missing Authorization header returns failure."""
        import relay.__main__ as mod
        original = mod.REQUIRE_AUTH
        mod.REQUIRE_AUTH = True
        try:
            request = MagicMock()
            request.headers = {"Authorization": ""}
            with patch("relay.__main__.extract_bearer_token", return_value=None):
                ok, result = await authenticate_request(request)
            assert ok is False
            assert "missing" in result.lower()
        finally:
            mod.REQUIRE_AUTH = original

    @pytest.mark.asyncio
    async def test_valid_token(self):
        """Valid token returns success with user email."""
        import relay.__main__ as mod
        original = mod.REQUIRE_AUTH
        mod.REQUIRE_AUTH = True
        try:
            request = MagicMock()
            request.headers = {"Authorization": "Bearer tok123"}
            with patch("relay.__main__.extract_bearer_token", return_value="tok123"), \
                 patch("relay.__main__.validate_token", new_callable=AsyncMock, return_value="alice@example.com"):
                ok, result = await authenticate_request(request)
            assert ok is True
            assert result == "alice@example.com"
        finally:
            mod.REQUIRE_AUTH = original

    @pytest.mark.asyncio
    async def test_invalid_token(self):
        """Invalid token returns failure."""
        from relay.auth import TokenValidationError
        import relay.__main__ as mod
        original = mod.REQUIRE_AUTH
        mod.REQUIRE_AUTH = True
        try:
            request = MagicMock()
            request.headers = {"Authorization": "Bearer badtok"}
            with patch("relay.__main__.extract_bearer_token", return_value="badtok"), \
                 patch("relay.__main__.validate_token", new_callable=AsyncMock,
                       side_effect=TokenValidationError("invalid")):
                ok, result = await authenticate_request(request)
            assert ok is False
            assert "invalid" in result.lower()
        finally:
            mod.REQUIRE_AUTH = original


# ---------------------------------------------------------------------------
# handle_status
# ---------------------------------------------------------------------------
class TestHandleStatus:
    """Tests for handle_status()."""

    @pytest.mark.asyncio
    async def test_unauthenticated_minimal(self):
        """Unauthenticated request gets minimal response."""
        request = MagicMock()
        with patch("relay.__main__.authenticate_request", new_callable=AsyncMock,
                    return_value=(False, "nope")):
            resp = await handle_status(request)
        body = json.loads(resp.body)
        assert body["status"] == "ok"
        assert "agents" not in body

    @pytest.mark.asyncio
    async def test_authenticated_with_counts(self):
        """Authenticated request gets operational counts."""
        request = MagicMock()
        with patch("relay.__main__.authenticate_request", new_callable=AsyncMock,
                    return_value=(True, "user@example.com")):
            resp = await handle_status(request)
        body = json.loads(resp.body)
        assert body["status"] == "ok"
        assert "agents" in body
        assert "active_streams" in body


# ---------------------------------------------------------------------------
# create_app
# ---------------------------------------------------------------------------
class TestCreateApp:
    """Tests for create_app()."""

    def test_routes_registered(self):
        """App has the expected routes."""
        app = create_app()
        routes = {r.resource.canonical for r in app.router.routes()}
        assert "/ws" in routes
        assert "/tunnel" in routes
        assert "/status" in routes
        assert "/" in routes


# ---------------------------------------------------------------------------
# _handle_tcp_connect
# ---------------------------------------------------------------------------
class TestHandleTcpConnect:
    """Tests for _handle_tcp_connect()."""

    @pytest.mark.asyncio
    async def test_invalid_params(self):
        """Invalid host/port is rejected with error message."""
        from relay.__main__ import _handle_tcp_connect
        ws = AsyncMock()
        ws.closed = False
        limiter = MagicMock()
        limiter.has_capacity.return_value = True
        limiter.acquire = AsyncMock()

        data = {"stream_id": "s1", "host": "", "port": 80}
        await _handle_tcp_connect(ws, data, "key", "user@x.com", limiter, "{}")

        ws.send_str.assert_called_once()
        sent = json.loads(ws.send_str.call_args[0][0])
        assert sent["success"] is False

    @pytest.mark.asyncio
    async def test_rate_limit(self):
        """Rate-limited request gets error."""
        from relay.__main__ import _handle_tcp_connect
        ws = AsyncMock()
        ws.closed = False
        limiter = MagicMock()
        limiter.has_capacity.return_value = False

        data = {"stream_id": "s1", "host": "example.com", "port": 443}
        await _handle_tcp_connect(ws, data, "key", "user@x.com", limiter, "{}")

        ws.send_str.assert_called_once()
        sent = json.loads(ws.send_str.call_args[0][0])
        assert sent["success"] is False
        assert "rate limit" in sent["error"].lower()

    @pytest.mark.asyncio
    async def test_blocked_port(self):
        """Blocked port is rejected."""
        import relay.__main__ as mod
        from relay.__main__ import _handle_tcp_connect

        original_ports = mod.BLOCKED_PORTS
        mod.BLOCKED_PORTS = {3389}
        try:
            ws = AsyncMock()
            ws.closed = False
            limiter = MagicMock()
            limiter.has_capacity.return_value = True
            limiter.acquire = AsyncMock()

            data = {"stream_id": "s1", "host": "10.0.0.1", "port": 3389}
            await _handle_tcp_connect(ws, data, "key", "user@x.com", limiter, "{}")

            ws.send_str.assert_called_once()
            sent = json.loads(ws.send_str.call_args[0][0])
            assert sent["success"] is False
            assert "not allowed" in sent["error"].lower()
        finally:
            mod.BLOCKED_PORTS = original_ports

    @pytest.mark.asyncio
    async def test_denied_destination(self):
        """Denied destination is rejected."""
        from relay.__main__ import _handle_tcp_connect

        ws = AsyncMock()
        ws.closed = False
        limiter = MagicMock()
        limiter.has_capacity.return_value = True
        limiter.acquire = AsyncMock()

        data = {"stream_id": "s1", "host": "evil.com", "port": 443}
        with patch("relay.__main__._check_destination_allowed", new_callable=AsyncMock,
                    return_value=(False, "denied")):
            await _handle_tcp_connect(ws, data, "key", "user@x.com", limiter, "{}")

        ws.send_str.assert_called_once()
        sent = json.loads(ws.send_str.call_args[0][0])
        assert sent["success"] is False

    @pytest.mark.asyncio
    async def test_no_agent(self):
        """Missing agent returns error."""
        import relay.__main__ as mod
        from relay.__main__ import _handle_tcp_connect

        ws = AsyncMock()
        ws.closed = False
        limiter = MagicMock()
        limiter.has_capacity.return_value = True
        limiter.acquire = AsyncMock()

        data = {"stream_id": "s1", "host": "example.com", "port": 443}

        # Ensure no agent registered and destination allowed
        original_agents = mod.bridge_agents.copy()
        mod.bridge_agents.clear()
        try:
            with patch("relay.__main__._check_destination_allowed", new_callable=AsyncMock,
                        return_value=(True, "")), \
                 patch("relay.__main__.BLOCKED_PORTS", set()):
                await _handle_tcp_connect(ws, data, "key", "noagent@x.com", limiter, "{}")

            ws.send_str.assert_called()
            sent = json.loads(ws.send_str.call_args[0][0])
            assert sent["success"] is False
            assert "no bridge agent" in sent["error"].lower()
        finally:
            mod.bridge_agents.update(original_agents)

    @pytest.mark.asyncio
    async def test_max_streams(self):
        """Max active streams returns error."""
        import relay.__main__ as mod
        from relay.__main__ import _handle_tcp_connect

        ws = AsyncMock()
        ws.closed = False
        limiter = MagicMock()
        limiter.has_capacity.return_value = True
        limiter.acquire = AsyncMock()

        data = {"stream_id": "s1", "host": "example.com", "port": 443}

        original_streams = mod.tcp_streams.copy()
        original_max = mod.MAX_ACTIVE_STREAMS
        mod.MAX_ACTIVE_STREAMS = 0  # Force limit hit
        try:
            with patch("relay.__main__._check_destination_allowed", new_callable=AsyncMock,
                        return_value=(True, "")), \
                 patch("relay.__main__.BLOCKED_PORTS", set()):
                await _handle_tcp_connect(ws, data, "key", "user@x.com", limiter, "{}")

            ws.send_str.assert_called()
            sent = json.loads(ws.send_str.call_args[0][0])
            assert sent["success"] is False
            assert "limit" in sent["error"].lower()
        finally:
            mod.tcp_streams.clear()
            mod.tcp_streams.update(original_streams)
            mod.MAX_ACTIVE_STREAMS = original_max

    @pytest.mark.asyncio
    async def test_stream_id_collision(self):
        """Duplicate stream_id is rejected."""
        import relay.__main__ as mod
        from relay.__main__ import _handle_tcp_connect

        ws = AsyncMock()
        ws.closed = False
        agent_ws = AsyncMock()
        agent_ws.closed = False
        limiter = MagicMock()
        limiter.has_capacity.return_value = True
        limiter.acquire = AsyncMock()

        # Register an agent and a pre-existing stream
        mod.bridge_agents["user@x.com"] = agent_ws
        mod.tcp_streams["s1"] = {
            "user_email": "user@x.com",
            "tunnel_key": "key",
            "tunnel_ws": ws,
            "created_at": time.monotonic(),
            "last_activity": time.monotonic(),
        }

        data = {"stream_id": "s1", "host": "example.com", "port": 443}
        try:
            with patch("relay.__main__._check_destination_allowed", new_callable=AsyncMock,
                        return_value=(True, "")), \
                 patch("relay.__main__.BLOCKED_PORTS", set()):
                await _handle_tcp_connect(ws, data, "key", "user@x.com", limiter, "{}")

            # Should reject collision
            sent = json.loads(ws.send_str.call_args[0][0])
            assert sent["success"] is False
            assert "collision" in sent["error"].lower()
        finally:
            mod.bridge_agents.pop("user@x.com", None)
            mod.tcp_streams.pop("s1", None)

    @pytest.mark.asyncio
    async def test_valid_request_forwarded(self):
        """Valid request registers stream and forwards to agent."""
        import relay.__main__ as mod
        from relay.__main__ import _handle_tcp_connect

        ws = AsyncMock()
        ws.closed = False
        agent_ws = AsyncMock()
        agent_ws.closed = False
        limiter = MagicMock()
        limiter.has_capacity.return_value = True
        limiter.acquire = AsyncMock()

        mod.bridge_agents["user@x.com"] = agent_ws
        raw_msg = json.dumps({"type": "tcp_connect", "stream_id": "s2", "host": "example.com", "port": 443})
        data = json.loads(raw_msg)

        try:
            with patch("relay.__main__._check_destination_allowed", new_callable=AsyncMock,
                        return_value=(True, "")), \
                 patch("relay.__main__.BLOCKED_PORTS", set()):
                await _handle_tcp_connect(ws, data, "key", "user@x.com", limiter, raw_msg)

            # Should forward to agent
            agent_ws.send_str.assert_called_once_with(raw_msg)
            # Stream should be registered
            assert "s2" in mod.tcp_streams
        finally:
            mod.bridge_agents.pop("user@x.com", None)
            mod.tcp_streams.pop("s2", None)


# ---------------------------------------------------------------------------
# _handle_tcp_data
# ---------------------------------------------------------------------------
class TestHandleTcpData:
    """Tests for _handle_tcp_data()."""

    @pytest.mark.asyncio
    async def test_forward_to_agent(self):
        """Data is forwarded to the bridge agent."""
        import relay.__main__ as mod
        from relay.__main__ import _handle_tcp_data

        agent_ws = AsyncMock()
        agent_ws.closed = False
        mod.bridge_agents["user@x.com"] = agent_ws
        mod.tcp_streams["s1"] = {
            "user_email": "user@x.com",
            "tunnel_key": "tkey",
            "tunnel_ws": MagicMock(),
            "created_at": time.monotonic(),
            "last_activity": time.monotonic(),
        }

        try:
            raw = '{"type":"tcp_data","stream_id":"s1","data":"aGVsbG8="}'
            with patch("relay.__main__._global_bandwidth_limiter", None):
                await _handle_tcp_data({"stream_id": "s1"}, "tkey", raw)
            agent_ws.send_str.assert_called_once_with(raw)
        finally:
            mod.bridge_agents.pop("user@x.com", None)
            mod.tcp_streams.pop("s1", None)

    @pytest.mark.asyncio
    async def test_ownership_check(self):
        """Data from wrong tunnel_key is rejected."""
        import relay.__main__ as mod
        from relay.__main__ import _handle_tcp_data

        agent_ws = AsyncMock()
        agent_ws.closed = False
        mod.bridge_agents["user@x.com"] = agent_ws
        mod.tcp_streams["s1"] = {
            "user_email": "user@x.com",
            "tunnel_key": "correct_key",
            "tunnel_ws": MagicMock(),
            "created_at": time.monotonic(),
            "last_activity": time.monotonic(),
        }

        try:
            with patch("relay.__main__._global_bandwidth_limiter", None):
                await _handle_tcp_data({"stream_id": "s1"}, "wrong_key", "{}")
            agent_ws.send_str.assert_not_called()
        finally:
            mod.bridge_agents.pop("user@x.com", None)
            mod.tcp_streams.pop("s1", None)

    @pytest.mark.asyncio
    async def test_missing_stream(self):
        """Missing stream_id is silently ignored."""
        from relay.__main__ import _handle_tcp_data
        # Should not raise
        with patch("relay.__main__._global_bandwidth_limiter", None):
            await _handle_tcp_data({"stream_id": "nonexistent"}, "key", "{}")


# ---------------------------------------------------------------------------
# _handle_tcp_close
# ---------------------------------------------------------------------------
class TestHandleTcpClose:
    """Tests for _handle_tcp_close()."""

    @pytest.mark.asyncio
    async def test_close_and_forward(self):
        """Close removes stream and forwards to agent."""
        import relay.__main__ as mod
        from relay.__main__ import _handle_tcp_close

        agent_ws = AsyncMock()
        agent_ws.closed = False
        mod.bridge_agents["user@x.com"] = agent_ws
        mod.tcp_streams["s1"] = {
            "user_email": "user@x.com",
            "tunnel_key": "tkey",
            "tunnel_ws": MagicMock(),
            "created_at": time.monotonic(),
            "last_activity": time.monotonic(),
        }

        try:
            raw = '{"type":"tcp_close","stream_id":"s1","reason":"done"}'
            await _handle_tcp_close({"stream_id": "s1"}, "tkey", raw)
            assert "s1" not in mod.tcp_streams
            agent_ws.send_str.assert_called_once_with(raw)
        finally:
            mod.bridge_agents.pop("user@x.com", None)
            mod.tcp_streams.pop("s1", None)

    @pytest.mark.asyncio
    async def test_ownership_check(self):
        """Close from wrong tunnel_key is rejected."""
        import relay.__main__ as mod
        from relay.__main__ import _handle_tcp_close

        agent_ws = AsyncMock()
        agent_ws.closed = False
        mod.bridge_agents["user@x.com"] = agent_ws
        mod.tcp_streams["s1"] = {
            "user_email": "user@x.com",
            "tunnel_key": "correct_key",
            "tunnel_ws": MagicMock(),
            "created_at": time.monotonic(),
            "last_activity": time.monotonic(),
        }

        try:
            await _handle_tcp_close({"stream_id": "s1"}, "wrong_key", "{}")
            # Stream should NOT be removed
            assert "s1" in mod.tcp_streams
            agent_ws.send_str.assert_not_called()
        finally:
            mod.bridge_agents.pop("user@x.com", None)
            mod.tcp_streams.pop("s1", None)
