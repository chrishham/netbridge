"""Tests for netbridge_agent.legacy — timestamp, proxy, stream info, and message handling."""

import asyncio
import base64
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from netbridge_agent.legacy import (
    StreamInfo,
    get_proxy_auth,
    get_system_proxy,
    handle_message,
    handle_tcp_close,
    handle_tcp_data,
    send_to_relay,
    ts,
)


# ---------------------------------------------------------------------------
# ts
# ---------------------------------------------------------------------------
class TestTs:
    """Tests for ts()."""

    def test_returns_formatted_timestamp(self):
        """Returns a non-empty timestamp string."""
        result = ts()
        assert isinstance(result, str)
        assert len(result) > 0
        # Should match HH:MM:SS pattern
        assert ":" in result


# ---------------------------------------------------------------------------
# get_system_proxy
# ---------------------------------------------------------------------------
class TestGetSystemProxy:
    """Tests for get_system_proxy()."""

    def test_with_https_proxy(self):
        """Returns HTTPS proxy when set."""
        with patch("netbridge_agent.legacy.urllib.request.getproxies",
                    return_value={"https": "http://proxy:8080"}):
            assert get_system_proxy() == "http://proxy:8080"

    def test_with_http_proxy_fallback(self):
        """Falls back to HTTP proxy when HTTPS is not set."""
        with patch("netbridge_agent.legacy.urllib.request.getproxies",
                    return_value={"http": "http://proxy:3128"}):
            assert get_system_proxy() == "http://proxy:3128"

    def test_no_proxy(self):
        """Returns None when no proxy is configured."""
        with patch("netbridge_agent.legacy.urllib.request.getproxies",
                    return_value={}):
            assert get_system_proxy() is None


# ---------------------------------------------------------------------------
# get_proxy_auth
# ---------------------------------------------------------------------------
class TestGetProxyAuth:
    """Tests for get_proxy_auth()."""

    def test_cli_credentials(self):
        """CLI user/pass takes precedence."""
        result = get_proxy_auth("http://proxy:8080", "user", "pass")
        assert isinstance(result, aiohttp.BasicAuth)
        assert result.login == "user"
        assert result.password == "pass"

    def test_cli_user_no_pass(self):
        """CLI user with no password uses empty string."""
        result = get_proxy_auth(None, "user", None)
        assert result.login == "user"
        assert result.password == ""

    def test_url_credentials(self):
        """Extracts credentials from proxy URL."""
        result = get_proxy_auth("http://user:secret@proxy:8080", None, None)
        assert result.login == "user"
        assert result.password == "secret"

    def test_no_credentials(self):
        """Returns None when no credentials available."""
        result = get_proxy_auth("http://proxy:8080", None, None)
        assert result is None

    def test_no_proxy_no_cli(self):
        """Returns None with no proxy URL and no CLI credentials."""
        result = get_proxy_auth(None, None, None)
        assert result is None


# ---------------------------------------------------------------------------
# StreamInfo
# ---------------------------------------------------------------------------
class TestStreamInfo:
    """Tests for StreamInfo dataclass."""

    def test_touch_updates_activity(self, mock_reader, mock_writer):
        """touch() updates last_activity timestamp."""
        stream = StreamInfo(
            reader=mock_reader,
            writer=mock_writer,
            forward_task=None,
            host="example.com",
            port=443,
        )
        old_activity = stream.last_activity
        time.sleep(0.01)
        stream.touch()
        assert stream.last_activity > old_activity

    def test_is_idle(self, mock_reader, mock_writer):
        """is_idle returns True when last_activity exceeds timeout."""
        stream = StreamInfo(
            reader=mock_reader,
            writer=mock_writer,
            forward_task=None,
            host="example.com",
            port=443,
        )
        with patch("netbridge_agent.legacy.time.monotonic",
                    return_value=stream.last_activity + 200):
            assert stream.is_idle(120.0) is True

    def test_not_idle(self, mock_reader, mock_writer):
        """is_idle returns False for a fresh stream."""
        stream = StreamInfo(
            reader=mock_reader,
            writer=mock_writer,
            forward_task=None,
            host="example.com",
            port=443,
        )
        assert stream.is_idle(120.0) is False

    def test_age(self, mock_reader, mock_writer):
        """age() returns seconds since creation."""
        stream = StreamInfo(
            reader=mock_reader,
            writer=mock_writer,
            forward_task=None,
            host="example.com",
            port=443,
        )
        with patch("netbridge_agent.legacy.time.monotonic",
                    return_value=stream.created_at + 60):
            assert stream.age() == pytest.approx(60, abs=1)


# ---------------------------------------------------------------------------
# send_to_relay
# ---------------------------------------------------------------------------
class TestSendToRelay:
    """Tests for send_to_relay()."""

    async def test_success(self):
        ws = AsyncMock()
        ws.closed = False
        result = await send_to_relay(ws, {"type": "test"})
        assert result is True
        ws.send_str.assert_called_once()

    async def test_closed_ws(self):
        ws = AsyncMock()
        ws.closed = True
        result = await send_to_relay(ws, {"type": "test"})
        assert result is False

    async def test_timeout(self):
        ws = AsyncMock()
        ws.closed = False
        ws.send_str.side_effect = asyncio.TimeoutError
        with patch("netbridge_agent.legacy.asyncio.wait_for", side_effect=asyncio.TimeoutError):
            result = await send_to_relay(ws, {"type": "test"})
        assert result is False

    async def test_exception(self):
        ws = AsyncMock()
        ws.closed = False
        ws.send_str.side_effect = Exception("boom")
        with patch("netbridge_agent.legacy.asyncio.wait_for", side_effect=Exception("boom")):
            result = await send_to_relay(ws, {"type": "test"})
        assert result is False


# ---------------------------------------------------------------------------
# handle_message
# ---------------------------------------------------------------------------
class TestHandleMessage:
    """Tests for handle_message()."""

    async def test_routes_tcp_connect(self):
        ws = AsyncMock()
        msg = json.dumps({"type": "tcp_connect", "stream_id": "s1", "host": "x.com", "port": 80})
        with patch("netbridge_agent.legacy.handle_tcp_connect", new_callable=AsyncMock) as mock_fn:
            await handle_message(ws, msg)
            mock_fn.assert_called_once()

    async def test_routes_tcp_data(self):
        ws = AsyncMock()
        msg = json.dumps({"type": "tcp_data", "stream_id": "s1", "data": "aGVsbG8="})
        with patch("netbridge_agent.legacy.handle_tcp_data", new_callable=AsyncMock) as mock_fn:
            await handle_message(ws, msg)
            mock_fn.assert_called_once()

    async def test_routes_tcp_close(self):
        ws = AsyncMock()
        msg = json.dumps({"type": "tcp_close", "stream_id": "s1"})
        with patch("netbridge_agent.legacy.handle_tcp_close", new_callable=AsyncMock) as mock_fn:
            await handle_message(ws, msg)
            mock_fn.assert_called_once()

    async def test_invalid_json(self, capsys):
        ws = AsyncMock()
        await handle_message(ws, "not json {{")
        captured = capsys.readouterr()
        assert "invalid json" in captured.out.lower()

    async def test_unknown_type(self, capsys):
        ws = AsyncMock()
        msg = json.dumps({"type": "unknown_xyz"})
        await handle_message(ws, msg)
        captured = capsys.readouterr()
        assert "unknown" in captured.out.lower()


# ---------------------------------------------------------------------------
# handle_tcp_data
# ---------------------------------------------------------------------------
class TestHandleTcpData:
    """Tests for handle_tcp_data()."""

    async def test_writes_data(self, mock_reader, mock_writer):
        import netbridge_agent.legacy as mod
        stream = StreamInfo(
            reader=mock_reader,
            writer=mock_writer,
            forward_task=None,
            host="x.com",
            port=80,
        )

        # Reset the module-level lock so it's created in this event loop
        mod._streams_lock = None

        mod.active_streams["s1"] = stream
        try:
            data_b64 = base64.b64encode(b"hello").decode()
            await handle_tcp_data({"stream_id": "s1", "data": data_b64})
            mock_writer.write.assert_called_once_with(b"hello")
            mock_writer.drain.assert_called_once()
        finally:
            mod.active_streams.pop("s1", None)

    async def test_missing_stream(self):
        import netbridge_agent.legacy as mod
        mod._streams_lock = None
        # Should not raise for missing stream
        await handle_tcp_data({"stream_id": "nonexistent", "data": "aGVsbG8="})


# ---------------------------------------------------------------------------
# handle_tcp_close
# ---------------------------------------------------------------------------
class TestHandleTcpClose:
    """Tests for handle_tcp_close()."""

    async def test_closes_stream(self, mock_reader, mock_writer):
        import netbridge_agent.legacy as mod
        stream = StreamInfo(
            reader=mock_reader,
            writer=mock_writer,
            forward_task=None,
            host="x.com",
            port=80,
        )

        mod._streams_lock = None
        mod.active_streams["s1"] = stream
        try:
            await handle_tcp_close({"stream_id": "s1", "reason": "done"})
            assert "s1" not in mod.active_streams
        finally:
            mod.active_streams.pop("s1", None)
