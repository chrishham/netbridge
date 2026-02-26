"""Tests for netbridge_agent.agent module.

Covers destination validation, stream management, proxy detection,
and message handling with mocked I/O.
"""

import asyncio
import base64
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netbridge_agent.agent import (
    AgentState,
    StreamInfo,
    get_proxy_auth,
    handle_message,
    handle_tcp_close,
    handle_tcp_data,
    send_to_relay,
    validate_destination,
)


# ---------------------------------------------------------------------------
# validate_destination
# ---------------------------------------------------------------------------


class TestValidateDestination:
    @pytest.mark.asyncio
    async def test_public_ip_allowed(self):
        allowed, reason = await validate_destination("8.8.8.8", 443)
        assert allowed is True

    @pytest.mark.asyncio
    async def test_loopback_ipv4_blocked(self):
        allowed, reason = await validate_destination("127.0.0.1", 80)
        assert allowed is False
        assert "blocked" in reason.lower()

    @pytest.mark.asyncio
    async def test_loopback_ipv6_blocked(self):
        allowed, reason = await validate_destination("::1", 80)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_link_local_blocked(self):
        allowed, reason = await validate_destination("169.254.1.1", 80)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_private_allowed_by_default(self):
        allowed, reason = await validate_destination("10.0.0.1", 80)
        assert allowed is True

    @pytest.mark.asyncio
    async def test_private_blocked_when_disabled(self):
        allowed, reason = await validate_destination("10.0.0.1", 80, allow_private=False)
        assert allowed is False
        assert "private" in reason.lower()

    @pytest.mark.asyncio
    async def test_172_16_blocked_when_disabled(self):
        allowed, reason = await validate_destination("172.16.0.1", 80, allow_private=False)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_192_168_blocked_when_disabled(self):
        allowed, reason = await validate_destination("192.168.1.1", 80, allow_private=False)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_denied_ip_cidr(self):
        allowed, reason = await validate_destination(
            "10.1.2.3", 80,
            denied_destinations=["10.1.0.0/16"],
        )
        assert allowed is False
        assert "denied" in reason.lower()

    @pytest.mark.asyncio
    async def test_denied_hostname(self):
        allowed, reason = await validate_destination(
            "evil.example.com", 443,
            denied_destinations=["evil.example.com"],
        )
        assert allowed is False

    @pytest.mark.asyncio
    async def test_denied_hostname_case_insensitive(self):
        allowed, reason = await validate_destination(
            "Evil.Example.COM", 443,
            denied_destinations=["evil.example.com"],
        )
        assert allowed is False

    @pytest.mark.asyncio
    async def test_allowed_list_permits_match(self):
        allowed, reason = await validate_destination(
            "8.8.8.8", 443,
            allowed_destinations=["8.8.8.0/24"],
        )
        assert allowed is True

    @pytest.mark.asyncio
    async def test_allowed_list_blocks_non_match(self):
        allowed, reason = await validate_destination(
            "1.2.3.4", 443,
            allowed_destinations=["8.8.8.0/24"],
        )
        assert allowed is False
        assert "not in the allowed" in reason.lower()

    @pytest.mark.asyncio
    async def test_allowed_list_hostname(self):
        allowed, reason = await validate_destination(
            "good.example.com", 443,
            allowed_destinations=["good.example.com"],
        )
        assert allowed is True

    @pytest.mark.asyncio
    async def test_ipv6_brackets_stripped(self):
        allowed, reason = await validate_destination("[::1]", 80)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_loopback_always_blocked_even_if_in_allowed(self):
        """Loopback is always blocked, even if explicitly in allowed list."""
        allowed, reason = await validate_destination(
            "127.0.0.1", 80,
            allowed_destinations=["127.0.0.0/8"],
        )
        assert allowed is False


# ---------------------------------------------------------------------------
# StreamInfo
# ---------------------------------------------------------------------------


class TestStreamInfo:
    def test_touch_updates_activity(self):
        stream = StreamInfo(
            reader=MagicMock(),
            writer=MagicMock(),
            forward_task=None,
            host="host",
            port=80,
        )
        old_activity = stream.last_activity
        time.sleep(0.01)
        stream.touch()
        assert stream.last_activity > old_activity

    def test_is_idle_false_when_recent(self):
        stream = StreamInfo(
            reader=MagicMock(),
            writer=MagicMock(),
            forward_task=None,
            host="host",
            port=80,
        )
        assert stream.is_idle(timeout=60) is False

    def test_is_idle_true_when_old(self):
        stream = StreamInfo(
            reader=MagicMock(),
            writer=MagicMock(),
            forward_task=None,
            host="host",
            port=80,
        )
        stream.last_activity = time.monotonic() - 120
        assert stream.is_idle(timeout=60) is True

    def test_age_increases(self):
        stream = StreamInfo(
            reader=MagicMock(),
            writer=MagicMock(),
            forward_task=None,
            host="host",
            port=80,
        )
        assert stream.age() >= 0


# ---------------------------------------------------------------------------
# AgentState
# ---------------------------------------------------------------------------


class TestAgentState:
    def test_initial_state(self):
        state = AgentState()
        assert state.active_streams == {}
        assert state.pending_connections == {}
        assert state.passthrough_proxy_auth is None
        assert state.allow_private_destinations is True
        assert state.allowed_destinations == []
        assert state.denied_destinations == []

    def test_get_lock_creates_lock(self):
        state = AgentState()
        lock = state.get_lock()
        assert isinstance(lock, asyncio.Lock)

    def test_get_lock_returns_same_instance(self):
        state = AgentState()
        lock1 = state.get_lock()
        lock2 = state.get_lock()
        assert lock1 is lock2


# ---------------------------------------------------------------------------
# get_proxy_auth
# ---------------------------------------------------------------------------


class TestGetProxyAuth:
    def test_cli_user_takes_precedence(self):
        auth = get_proxy_auth("http://other:pass@proxy:8080", "cli_user", "cli_pass")
        assert auth.login == "cli_user"
        assert auth.password == "cli_pass"

    def test_cli_user_empty_password(self):
        auth = get_proxy_auth(None, "user", None)
        assert auth.login == "user"
        assert auth.password == ""

    def test_proxy_url_credentials(self):
        auth = get_proxy_auth("http://user:pass@proxy:8080", None, None)
        assert auth.login == "user"
        assert auth.password == "pass"

    def test_proxy_url_user_no_password(self):
        auth = get_proxy_auth("http://user@proxy:8080", None, None)
        assert auth.login == "user"
        assert auth.password == ""

    def test_no_auth_returns_none(self):
        assert get_proxy_auth(None, None, None) is None

    def test_proxy_url_no_credentials_returns_none(self):
        assert get_proxy_auth("http://proxy:8080", None, None) is None


# ---------------------------------------------------------------------------
# send_to_relay
# ---------------------------------------------------------------------------


class TestSendToRelay:
    @pytest.mark.asyncio
    async def test_send_success(self):
        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock()
        result = await send_to_relay(ws, {"type": "heartbeat"})
        assert result is True
        ws.send_str.assert_called_once()
        sent = json.loads(ws.send_str.call_args[0][0])
        assert sent["type"] == "heartbeat"

    @pytest.mark.asyncio
    async def test_send_closed_ws(self):
        ws = MagicMock()
        ws.closed = True
        result = await send_to_relay(ws, {"type": "heartbeat"})
        assert result is False

    @pytest.mark.asyncio
    async def test_send_timeout(self):
        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock(side_effect=asyncio.TimeoutError())
        result = await send_to_relay(ws, {"type": "test"}, timeout=0.01)
        assert result is False

    @pytest.mark.asyncio
    async def test_send_exception(self):
        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock(side_effect=ConnectionError("broken"))
        result = await send_to_relay(ws, {"type": "test"})
        assert result is False


# ---------------------------------------------------------------------------
# handle_tcp_data
# ---------------------------------------------------------------------------


class TestHandleTcpData:
    @pytest.mark.asyncio
    async def test_writes_decoded_data(self):
        state = AgentState()
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()

        stream = StreamInfo(
            reader=MagicMock(),
            writer=writer,
            forward_task=None,
            host="host",
            port=80,
        )
        state.active_streams["s1"] = stream

        data = b"hello world"
        request = {
            "stream_id": "s1",
            "data": base64.b64encode(data).decode(),
        }
        await handle_tcp_data(state, request)

        writer.write.assert_called_once_with(data)
        writer.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_missing_stream_no_error(self):
        state = AgentState()
        request = {
            "stream_id": "nonexistent",
            "data": base64.b64encode(b"x").decode(),
        }
        await handle_tcp_data(state, request)  # should not raise

    @pytest.mark.asyncio
    async def test_oversized_payload_dropped(self):
        state = AgentState()
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()

        stream = StreamInfo(
            reader=MagicMock(),
            writer=writer,
            forward_task=None,
            host="host",
            port=80,
        )
        state.active_streams["s1"] = stream

        # Create a payload larger than the max
        request = {
            "stream_id": "s1",
            "data": "A" * (2 * 1024 * 1024),  # >1MB base64
        }
        await handle_tcp_data(state, request)

        writer.write.assert_not_called()


# ---------------------------------------------------------------------------
# handle_tcp_close
# ---------------------------------------------------------------------------


class TestHandleTcpClose:
    @pytest.mark.asyncio
    async def test_closes_stream(self):
        state = AgentState()
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        stream = StreamInfo(
            reader=MagicMock(),
            writer=writer,
            forward_task=None,
            host="host",
            port=80,
        )
        state.active_streams["s1"] = stream

        await handle_tcp_close(state, {"stream_id": "s1", "reason": "client_closed"})
        assert "s1" not in state.active_streams

    @pytest.mark.asyncio
    async def test_close_nonexistent_no_error(self):
        state = AgentState()
        await handle_tcp_close(state, {"stream_id": "nope", "reason": "test"})


# ---------------------------------------------------------------------------
# handle_message
# ---------------------------------------------------------------------------


class TestHandleMessage:
    @pytest.mark.asyncio
    async def test_dispatches_tcp_data(self):
        state = AgentState()
        ws = MagicMock()

        with patch("netbridge_agent.agent.handle_tcp_data", new_callable=AsyncMock) as mock_data:
            msg = json.dumps({"type": "tcp_data", "stream_id": "s1", "data": "AA=="})
            await handle_message(state, ws, msg)
            mock_data.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatches_tcp_close(self):
        state = AgentState()
        ws = MagicMock()

        with patch("netbridge_agent.agent.handle_tcp_close", new_callable=AsyncMock) as mock_close:
            msg = json.dumps({"type": "tcp_close", "stream_id": "s1", "reason": "done"})
            await handle_message(state, ws, msg)
            mock_close.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatches_tcp_connect(self):
        state = AgentState()
        ws = MagicMock()

        with patch("netbridge_agent.agent.handle_tcp_connect", new_callable=AsyncMock) as mock_conn:
            msg = json.dumps({"type": "tcp_connect", "stream_id": "s1", "host": "h", "port": 80})
            await handle_message(state, ws, msg)
            mock_conn.assert_called_once()

    @pytest.mark.asyncio
    async def test_invalid_json_no_crash(self):
        state = AgentState()
        ws = MagicMock()
        await handle_message(state, ws, "not json{{{")  # should not raise

    @pytest.mark.asyncio
    async def test_unknown_type_no_crash(self):
        state = AgentState()
        ws = MagicMock()
        msg = json.dumps({"type": "unknown_type"})
        await handle_message(state, ws, msg)  # should not raise
