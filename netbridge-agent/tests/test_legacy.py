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
    get_proxy_auth_header,
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
# get_proxy_auth_header
# ---------------------------------------------------------------------------
class TestGetProxyAuthHeader:
    """Tests for get_proxy_auth_header()."""

    def test_cli_credentials(self):
        """CLI user/pass takes precedence."""
        result = get_proxy_auth_header("http://proxy:8080", "user", "pass")
        assert result == aiohttp.encode_basic_auth("user", "pass")

    def test_cli_user_no_pass(self):
        """CLI user with no password uses empty string."""
        result = get_proxy_auth_header(None, "user", None)
        assert result == aiohttp.encode_basic_auth("user", "")

    def test_url_credentials(self):
        """Extracts credentials from proxy URL."""
        result = get_proxy_auth_header("http://user:secret@proxy:8080", None, None)
        assert result == aiohttp.encode_basic_auth("user", "secret")

    def test_no_credentials(self):
        """Returns None when no credentials available."""
        result = get_proxy_auth_header("http://proxy:8080", None, None)
        assert result is None

    def test_no_proxy_no_cli(self):
        """Returns None with no proxy URL and no CLI credentials."""
        result = get_proxy_auth_header(None, None, None)
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


@pytest.mark.parametrize("raw", ["[1]", '"x"', "null", "42",
                                 '{"type":"tcp_connect","stream_id":[1],"host":null,"port":1}',
                                 '{"type":"tcp_connect","stream_id":"s1","host":"h","port":true}'])
async def test_legacy_handle_message_survives_hostile_frames(raw):
    from netbridge_agent import legacy
    ws = MagicMock(closed=False, send_str=AsyncMock())
    await legacy.handle_message(ws, raw)
    assert legacy.active_streams == {}


@pytest.mark.parametrize("data", [None, 5, [1], "!!not-base64!!"])
async def test_legacy_tcp_data_bad_payload_closes_the_stream_and_writes_nothing(data, mock_writer, mock_reader, monkeypatch):
    from netbridge_agent import legacy
    info = legacy.StreamInfo(mock_reader, mock_writer, None, "h", 80)
    monkeypatch.setitem(legacy.active_streams, "s1", info)
    await legacy.handle_tcp_data({"type": "tcp_data", "stream_id": "s1", "data": data})
    mock_writer.write.assert_not_called()
    assert "s1" not in legacy.active_streams
    mock_writer.close.assert_called()


async def test_legacy_tcp_data_valid_payload_is_written(mock_writer, mock_reader, monkeypatch):
    from netbridge_agent import legacy
    info = legacy.StreamInfo(mock_reader, mock_writer, None, "h", 80)
    monkeypatch.setitem(legacy.active_streams, "s1", info)
    await legacy.handle_tcp_data({"type": "tcp_data", "stream_id": "s1", "data": "AA=="})
    mock_writer.write.assert_called_once_with(b"\x00")


@pytest.fixture
def legacy_dial(monkeypatch):
    """Legacy connect path with an allowed destination and a dial that blocks until released."""
    from netbridge_agent import legacy
    release = asyncio.Event()
    dials = []

    async def slow_dial(host, port, timeout, proxy_auth=None):
        dials.append((host, port))
        await release.wait()
        raise OSError("refused")

    monkeypatch.setattr(legacy, "validate_destination", AsyncMock(return_value=(True, "")))
    monkeypatch.setattr(legacy, "open_tcp_connection", slow_dial)
    monkeypatch.setattr(legacy, "pending_connections", {})
    monkeypatch.setattr(legacy, "active_streams", {})
    yield legacy, release, dials
    release.set()


def _connect(sid="s1"):
    return {"type": "tcp_connect", "stream_id": sid, "host": "example.com", "port": 80}


async def test_legacy_duplicate_pending_id_is_ignored(legacy_dial):
    legacy, release, dials = legacy_dial
    ws = MagicMock(closed=False, send_str=AsyncMock())
    await legacy.handle_tcp_connect(ws, _connect())
    first = legacy.pending_connections["s1"]
    await legacy.handle_tcp_connect(ws, _connect())
    await asyncio.sleep(0)
    assert legacy.pending_connections["s1"] is first
    assert len(dials) == 1
    ws.send_str.assert_not_called()                 # no reply that would tear down s1
    release.set()
    await first
    assert "s1" not in legacy.pending_connections


async def test_legacy_duplicate_at_capacity_gets_no_rejection(legacy_dial, monkeypatch):
    legacy, release, dials = legacy_dial
    monkeypatch.setattr(legacy, "MAX_CONCURRENT_CONNECTIONS", 1)
    ws = MagicMock(closed=False, send_str=AsyncMock())
    await legacy.handle_tcp_connect(ws, _connect())
    await legacy.handle_tcp_connect(ws, _connect())
    ws.send_str.assert_not_called()


async def test_legacy_close_cancels_a_pending_dial(legacy_dial):
    legacy, release, dials = legacy_dial
    ws = MagicMock(closed=False, send_str=AsyncMock())
    await legacy.handle_tcp_connect(ws, _connect())
    task = legacy.pending_connections["s1"]
    await asyncio.sleep(0)
    await legacy.handle_tcp_close({"type": "tcp_close", "stream_id": "s1"})
    assert task.cancelled()
    assert legacy.pending_connections == {}
    assert legacy.active_streams == {}


async def test_legacy_finished_dial_keeps_an_entry_that_reused_the_id(legacy_dial):
    legacy, release, dials = legacy_dial
    ws = MagicMock(closed=False, send_str=AsyncMock())
    await legacy.handle_tcp_connect(ws, _connect())
    task = legacy.pending_connections["s1"]
    await asyncio.sleep(0)
    replacement = asyncio.get_running_loop().create_future()
    legacy.pending_connections["s1"] = replacement
    release.set()
    await task
    assert legacy.pending_connections["s1"] is replacement
