"""Tests for socks_proxy.tunnel — URL normalization, TunnelManager, and message handling."""

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from socks_proxy.tunnel import TunnelManager, normalize_relay_url


# ---------------------------------------------------------------------------
# normalize_relay_url
# ---------------------------------------------------------------------------
class TestNormalizeRelayUrl:
    """Tests for normalize_relay_url()."""

    def test_bare_hostname(self):
        """Bare hostname gets wss:// prefix and /tunnel path."""
        assert normalize_relay_url("relay.example.com") == "wss://relay.example.com/tunnel"

    def test_with_wss_scheme(self):
        """wss:// scheme without path gets /tunnel appended."""
        assert normalize_relay_url("wss://relay.example.com") == "wss://relay.example.com/tunnel"

    def test_full_url_with_path(self):
        """Full URL with scheme and path is returned as-is."""
        url = "wss://relay.example.com/custom"
        assert normalize_relay_url(url) == url

    def test_trailing_slash(self):
        """Trailing slash is stripped before processing."""
        assert normalize_relay_url("relay.example.com/") == "wss://relay.example.com/tunnel"

    def test_ws_scheme(self):
        """ws:// scheme without path gets /tunnel appended."""
        assert normalize_relay_url("ws://localhost:8080") == "ws://localhost:8080/tunnel"

    def test_custom_path(self):
        """Custom path parameter is used."""
        assert normalize_relay_url("relay.com", path="/ws") == "wss://relay.com/ws"


# ---------------------------------------------------------------------------
# TunnelManager.__init__
# ---------------------------------------------------------------------------
class TestTunnelManagerInit:
    """Tests for TunnelManager initialization."""

    @patch("socks_proxy.tunnel.get_session_id", return_value="abc123")
    def test_attributes(self, _mock_sid):
        """Init sets relay_url, auth_token, and session_id."""
        tm = TunnelManager("relay.example.com", auth_token="tok123")
        assert "wss://relay.example.com/tunnel" in tm.relay_url
        assert tm.auth_token == "tok123"
        assert tm.session_id == "abc123"
        assert tm.streams == {}
        assert tm.ws is None
        assert tm._stopping is False


# ---------------------------------------------------------------------------
# _release_semaphore_for_stream
# ---------------------------------------------------------------------------
class TestReleaseSemaphore:
    """Tests for TunnelManager._release_semaphore_for_stream()."""

    @patch("socks_proxy.tunnel.get_session_id", return_value="sid")
    def test_release_once(self, _mock):
        """Semaphore is released and handler marked."""
        tm = TunnelManager("relay.com")
        handler = MagicMock()
        handler.semaphore_released = False

        tm._release_semaphore_for_stream(handler)
        assert handler.semaphore_released is True

    @patch("socks_proxy.tunnel.get_session_id", return_value="sid")
    def test_prevent_double_release(self, _mock):
        """Second release is a no-op."""
        tm = TunnelManager("relay.com")
        handler = MagicMock()
        handler.semaphore_released = True

        # Should not call release again (semaphore starts at MAX_CONCURRENT_STREAMS)
        initial_value = tm._stream_semaphore._value
        tm._release_semaphore_for_stream(handler)
        assert tm._stream_semaphore._value == initial_value


# ---------------------------------------------------------------------------
# connect
# ---------------------------------------------------------------------------
class TestConnect:
    """Tests for TunnelManager.connect()."""

    @pytest.mark.asyncio
    async def test_not_connected(self):
        """Raises ConnectionError when not connected to relay."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        with pytest.raises(ConnectionError, match="Not connected"):
            await tm.connect("example.com", 443)

    @pytest.mark.asyncio
    async def test_semaphore_full(self):
        """Raises ConnectionError when semaphore is exhausted."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm._connected.set()
        tm._stream_semaphore = asyncio.Semaphore(0)  # No slots
        with pytest.raises(ConnectionError, match="Too many"):
            await tm.connect("example.com", 443)

    @pytest.mark.asyncio
    async def test_send_failure(self):
        """Send failure cleans up and raises ConnectionError."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm._connected.set()
        tm.ws = AsyncMock()
        tm.ws.send_str.side_effect = Exception("send failed")

        with pytest.raises(ConnectionError, match="send"):
            await tm.connect("example.com", 443)
        assert len(tm.streams) == 0

    @pytest.mark.asyncio
    async def test_success_flow(self):
        """Successful connect sends request and waits for result."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm._connected.set()
        tm.ws = AsyncMock()

        async def fake_send(msg):
            """Simulate relay responding with success."""
            import json
            data = json.loads(msg)
            stream_id = data["stream_id"]
            handler = tm.streams.get(stream_id)
            if handler and not handler.connect_future.done():
                handler.connect_future.set_result({"success": True})

        tm.ws.send_str.side_effect = fake_send

        stream_id = await tm.connect("example.com", 443)
        assert stream_id in tm.streams


# ---------------------------------------------------------------------------
# close_stream
# ---------------------------------------------------------------------------
class TestCloseStream:
    """Tests for TunnelManager.close_stream()."""

    @pytest.mark.asyncio
    async def test_close_and_notify_relay(self):
        """Close removes handler, releases semaphore, and notifies relay."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm.ws = AsyncMock()
        tm.ws.closed = False

        future = asyncio.get_running_loop().create_future()
        from socks_proxy.stream import StreamHandler
        handler = StreamHandler(stream_id="s1", connect_future=future)
        tm.streams["s1"] = handler

        await tm.close_stream("s1")
        assert "s1" not in tm.streams
        assert handler.closed is True
        tm.ws.send_str.assert_called_once()

    @pytest.mark.asyncio
    async def test_missing_stream(self):
        """Closing a nonexistent stream does not raise."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm.ws = AsyncMock()
        tm.ws.closed = False
        await tm.close_stream("nonexistent")  # Should not raise

    @pytest.mark.asyncio
    async def test_ws_closed(self):
        """Closing with a closed WebSocket skips relay notification."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm.ws = AsyncMock()
        tm.ws.closed = True

        future = asyncio.get_running_loop().create_future()
        from socks_proxy.stream import StreamHandler
        handler = StreamHandler(stream_id="s1", connect_future=future)
        tm.streams["s1"] = handler

        await tm.close_stream("s1")
        tm.ws.send_str.assert_not_called()


# ---------------------------------------------------------------------------
# send_data
# ---------------------------------------------------------------------------
class TestSendData:
    """Tests for TunnelManager.send_data()."""

    @pytest.mark.asyncio
    async def test_success(self):
        """Data is base64-encoded and sent via WebSocket."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm.ws = AsyncMock()
        tm.ws.closed = False
        await tm.send_data("s1", b"hello")
        tm.ws.send_str.assert_called_once()
        import json
        sent = json.loads(tm.ws.send_str.call_args[0][0])
        assert sent["type"] == "tcp_data"
        assert sent["stream_id"] == "s1"
        assert base64.b64decode(sent["data"]) == b"hello"

    @pytest.mark.asyncio
    async def test_closed_ws(self):
        """Raises ConnectionError when WebSocket is closed."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm.ws = AsyncMock()
        tm.ws.closed = True
        with pytest.raises(ConnectionError, match="closed"):
            await tm.send_data("s1", b"data")


# ---------------------------------------------------------------------------
# _handle_message
# ---------------------------------------------------------------------------
class TestHandleMessage:
    """Tests for TunnelManager._handle_message()."""

    @pytest.mark.asyncio
    async def test_tcp_connect_result_sets_future(self):
        """tcp_connect_result sets the stream's connect future."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        future = asyncio.get_running_loop().create_future()
        from socks_proxy.stream import StreamHandler
        handler = StreamHandler(stream_id="s1", connect_future=future)
        tm.streams["s1"] = handler

        await tm._handle_message({
            "type": "tcp_connect_result",
            "stream_id": "s1",
            "success": True,
        })
        assert future.done()
        assert future.result()["success"] is True

    @pytest.mark.asyncio
    async def test_tcp_data_queues_data(self):
        """tcp_data decodes and queues data on the handler."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        future = asyncio.get_running_loop().create_future()
        from socks_proxy.stream import StreamHandler
        handler = StreamHandler(stream_id="s1", connect_future=future)
        tm.streams["s1"] = handler

        encoded = base64.b64encode(b"test data").decode()
        await tm._handle_message({
            "type": "tcp_data",
            "stream_id": "s1",
            "data": encoded,
        })
        assert handler.data_queue.qsize() == 1
        queued = handler.data_queue.get_nowait()
        assert queued == b"test data"

    @pytest.mark.asyncio
    async def test_tcp_close_closes_handler(self):
        """tcp_close closes the handler and removes it from streams."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        future = asyncio.get_running_loop().create_future()
        from socks_proxy.stream import StreamHandler
        handler = StreamHandler(stream_id="s1", connect_future=future)
        tm.streams["s1"] = handler

        await tm._handle_message({
            "type": "tcp_close",
            "stream_id": "s1",
        })
        assert handler.closed is True
        assert "s1" not in tm.streams

    @pytest.mark.asyncio
    async def test_missing_stream_id(self):
        """Message without stream_id is silently ignored."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        await tm._handle_message({"type": "tcp_data"})  # no stream_id

    @pytest.mark.asyncio
    async def test_unknown_stream(self):
        """Message for unknown stream is silently ignored."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        await tm._handle_message({
            "type": "tcp_data",
            "stream_id": "nonexistent",
            "data": base64.b64encode(b"x").decode(),
        })


# ---------------------------------------------------------------------------
# End-to-end (agent reachability) status
# ---------------------------------------------------------------------------
class TestClassifyConnectError:
    """Tests for classify_connect_error()."""

    def test_no_agent_is_conclusive_down(self):
        from socks_proxy.tunnel import classify_connect_error
        assert classify_connect_error("No bridge agent available") is False

    def test_case_insensitive(self):
        from socks_proxy.tunnel import classify_connect_error
        assert classify_connect_error("no BRIDGE AGENT available") is False

    def test_relay_side_rejection_is_inconclusive(self):
        from socks_proxy.tunnel import classify_connect_error
        assert classify_connect_error("Destination foo is not allowed") is None
        assert classify_connect_error("Port 22 is not allowed") is None
        assert classify_connect_error("Rate limit exceeded for stream creation") is None
        assert classify_connect_error("Maximum stream limit reached") is None

    def test_agent_error_means_agent_is_alive(self):
        from socks_proxy.tunnel import classify_connect_error
        assert classify_connect_error("Connection refused") is True
        assert classify_connect_error("Name or service not known") is True


def _tunnel_with_reply(reply):
    """Build a connected TunnelManager whose relay answers with *reply*."""
    import json

    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")
    tm._connected.set()
    tm.ws = AsyncMock()

    async def fake_send(msg):
        data = json.loads(msg)
        handler = tm.streams.get(data["stream_id"])
        if handler and not handler.connect_future.done():
            handler.connect_future.set_result(reply)

    tm.ws.send_str.side_effect = fake_send
    return tm


class TestAgentAvailability:
    """The tray needs to know the tunnel works end to end, not just to the relay."""

    @pytest.mark.asyncio
    async def test_starts_unknown(self):
        tm = _tunnel_with_reply({"success": True})
        assert tm.agent_available is None

    @pytest.mark.asyncio
    async def test_successful_connect_marks_agent_available(self):
        tm = _tunnel_with_reply({"success": True})
        await tm.connect("example.com", 443)
        assert tm.agent_available is True

    @pytest.mark.asyncio
    async def test_no_agent_error_marks_unavailable(self):
        tm = _tunnel_with_reply({"success": False, "error": "No bridge agent available"})
        with pytest.raises(ConnectionError):
            await tm.connect("netbridge-gauth", 80)
        assert tm.agent_available is False

    @pytest.mark.asyncio
    async def test_no_agent_error_records_probe_target(self):
        tm = _tunnel_with_reply({"success": False, "error": "No bridge agent available"})
        with pytest.raises(ConnectionError):
            await tm.connect("netbridge-gauth", 80)
        assert tm._probe_target == ("netbridge-gauth", 80)

    @pytest.mark.asyncio
    async def test_relay_rejection_leaves_status_unknown(self):
        tm = _tunnel_with_reply({"success": False, "error": "Destination x is not allowed"})
        with pytest.raises(ConnectionError):
            await tm.connect("x", 80)
        assert tm.agent_available is None

    @pytest.mark.asyncio
    async def test_status_callback_receives_agent_state(self):
        calls = []
        tm = _tunnel_with_reply({"success": False, "error": "No bridge agent available"})
        tm._on_status_change = lambda **kw: calls.append(kw)

        with pytest.raises(ConnectionError):
            await tm.connect("host", 80)

        assert calls and calls[-1]["agent_available"] is False
        assert calls[-1]["connected"] is True

    @pytest.mark.asyncio
    async def test_legacy_status_callback_still_called(self):
        """Callbacks without the newer keyword args must not be dropped."""
        calls = []

        def legacy_callback(connected, auth_required=False):
            calls.append((connected, auth_required))

        tm = _tunnel_with_reply({"success": False, "error": "No bridge agent available"})
        tm._on_status_change = legacy_callback

        with pytest.raises(ConnectionError):
            await tm.connect("host", 80)

        assert calls == [(True, False)]

    @pytest.mark.asyncio
    async def test_no_duplicate_notifications(self):
        calls = []
        tm = _tunnel_with_reply({"success": True})
        tm._on_status_change = lambda **kw: calls.append(kw)

        await tm.connect("example.com", 443)
        await tm.connect("example.com", 443)

        assert len(calls) == 1


class TestProbeAgent:
    """probe_agent() checks the VDI end without waiting for user traffic."""

    @pytest.mark.asyncio
    async def test_probe_detects_missing_agent(self):
        tm = _tunnel_with_reply({"success": False, "error": "No bridge agent available"})
        result = await tm.probe_agent()
        assert result is False
        assert tm.agent_available is False

    @pytest.mark.asyncio
    async def test_probe_uses_default_target(self):
        import json
        from socks_proxy.tunnel import DEFAULT_PROBE_TARGET

        tm = _tunnel_with_reply({"success": False, "error": "No bridge agent available"})
        await tm.probe_agent()

        sent = json.loads(tm.ws.send_str.call_args_list[0][0][0])
        assert (sent["host"], sent["port"]) == DEFAULT_PROBE_TARGET

    @pytest.mark.asyncio
    async def test_probe_prefers_configured_target(self):
        import json

        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com", probe_target=("probe.internal", 8443))
        tm._connected.set()
        tm.ws = AsyncMock()

        async def fake_send(msg):
            data = json.loads(msg)
            handler = tm.streams.get(data["stream_id"])
            if handler and not handler.connect_future.done():
                handler.connect_future.set_result(
                    {"success": False, "error": "No bridge agent available"}
                )

        tm.ws.send_str.side_effect = fake_send
        await tm.probe_agent()

        sent = json.loads(tm.ws.send_str.call_args_list[0][0][0])
        assert (sent["host"], sent["port"]) == ("probe.internal", 8443)

    @pytest.mark.asyncio
    async def test_probe_success_closes_the_stream(self):
        """A probe must not leave a live stream behind."""
        tm = _tunnel_with_reply({"success": True})
        await tm.probe_agent()
        assert tm.streams == {}
        assert tm.agent_available is True

    @pytest.mark.asyncio
    async def test_probe_falls_through_to_next_candidate(self):
        """An inconclusive answer moves on to the next probe destination."""
        import json

        tm = _tunnel_with_reply({"success": True})
        tm._probe_target = ("known-good.internal", 443)
        replies = [
            {"success": False, "error": "Destination is not allowed"},
            {"success": False, "error": "No bridge agent available"},
        ]

        async def fake_send(msg):
            data = json.loads(msg)
            handler = tm.streams.get(data["stream_id"])
            if handler and not handler.connect_future.done():
                handler.connect_future.set_result(replies.pop(0))

        tm.ws.send_str.side_effect = fake_send

        assert await tm.probe_agent() is False
        assert tm.ws.send_str.call_count == 2

    @pytest.mark.asyncio
    async def test_probe_skipped_when_not_connected(self):
        tm = _tunnel_with_reply({"success": True})
        tm._connected.clear()
        assert await tm.probe_agent() is None
        tm.ws.send_str.assert_not_called()


class TestProbeIgnoresLocalErrors:
    """A local failure must never be read as 'the VDI is fine'."""

    @pytest.mark.asyncio
    async def test_disconnected_mid_probe_is_inconclusive(self):
        from socks_proxy.tunnel import TunnelConnectError

        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm._connected.set()
        tm.ws = AsyncMock()
        tm.ws.send_str.side_effect = Exception("socket gone")

        assert await tm._attempt_probe("host", 80) is None
        assert tm.agent_available is None

    @pytest.mark.asyncio
    async def test_relay_errors_are_still_classified(self):
        tm = _tunnel_with_reply({"success": False, "error": "Connection refused"})
        assert await tm._attempt_probe("host", 80) is True


class TestProbeLoop:
    """The loop checks immediately, then only when there is something to learn."""

    @pytest.mark.asyncio
    async def test_probes_immediately_without_waiting(self):
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm._connected.set()

        probed = asyncio.Event()

        async def fake_probe():
            probed.set()
            return True

        tm.probe_agent = fake_probe
        task = asyncio.create_task(tm._agent_probe_loop())
        try:
            await asyncio.wait_for(probed.wait(), timeout=1.0)
        finally:
            task.cancel()

    @pytest.mark.asyncio
    async def test_idles_while_healthy_and_wakes_on_request(self):
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm._connected.set()

        calls = []

        async def fake_probe():
            calls.append(1)
            tm._agent_available = True
            return True

        tm.probe_agent = fake_probe
        task = asyncio.create_task(tm._agent_probe_loop())
        try:
            await asyncio.sleep(0.05)
            assert len(calls) == 1  # idle, not polling

            tm._probe_now.set()  # e.g. a reconnect happened
            await asyncio.sleep(0.05)
            assert len(calls) == 2
        finally:
            task.cancel()

    @pytest.mark.asyncio
    async def test_keeps_polling_while_agent_is_down(self):
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm._connected.set()

        calls = []

        async def fake_probe():
            calls.append(1)
            tm._agent_available = False
            return False

        tm.probe_agent = fake_probe
        with patch("socks_proxy.tunnel.AGENT_PROBE_INTERVAL", 0.01), \
             patch("socks_proxy.tunnel.AGENT_PROBE_INTERVAL_MAX", 0.01):
            task = asyncio.create_task(tm._agent_probe_loop())
            try:
                await asyncio.sleep(0.1)
                assert len(calls) > 2
            finally:
                task.cancel()
