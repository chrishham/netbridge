"""Tests for netbridge_agent.agent module.

Covers destination validation, stream management, proxy detection,
and message handling with mocked I/O.
"""

import asyncio
import base64
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from netbridge_agent.agent import (
    AgentState,
    StreamInfo,
    get_proxy_auth_header,
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
    async def test_loopback_blocked_even_if_in_allowed(self):
        """Loopback is blocked by default, even if explicitly in allowed list."""
        allowed, reason = await validate_destination(
            "127.0.0.1", 80,
            allowed_destinations=["127.0.0.0/8"],
        )
        assert allowed is False

    @pytest.mark.asyncio
    async def test_loopback_allowed_when_enabled(self):
        allowed, reason = await validate_destination(
            "127.0.0.1", 80, allow_loopback=True,
        )
        assert allowed is True

    @pytest.mark.asyncio
    async def test_loopback_ipv6_allowed_when_enabled(self):
        allowed, reason = await validate_destination(
            "::1", 80, allow_loopback=True,
        )
        assert allowed is True

    @pytest.mark.asyncio
    async def test_link_local_still_blocked_with_allow_loopback(self):
        allowed, reason = await validate_destination(
            "169.254.1.1", 80, allow_loopback=True,
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
# get_proxy_auth_header
# ---------------------------------------------------------------------------


class TestGetProxyAuthHeader:
    def test_cli_user_takes_precedence(self):
        header = get_proxy_auth_header("http://other:pass@proxy:8080", "cli_user", "cli_pass")
        assert header == aiohttp.encode_basic_auth("cli_user", "cli_pass")

    def test_cli_user_empty_password(self):
        header = get_proxy_auth_header(None, "user", None)
        assert header == aiohttp.encode_basic_auth("user", "")

    def test_proxy_url_credentials(self):
        header = get_proxy_auth_header("http://user:pass@proxy:8080", None, None)
        assert header == aiohttp.encode_basic_auth("user", "pass")

    def test_proxy_url_user_no_password(self):
        header = get_proxy_auth_header("http://user@proxy:8080", None, None)
        assert header == aiohttp.encode_basic_auth("user", "")

    def test_no_auth_returns_none(self):
        assert get_proxy_auth_header(None, None, None) is None

    def test_proxy_url_no_credentials_returns_none(self):
        assert get_proxy_auth_header("http://proxy:8080", None, None) is None


# ---------------------------------------------------------------------------
# send_to_relay
# ---------------------------------------------------------------------------


class TestSendToRelay:
    @pytest.mark.asyncio
    async def test_send_success(self):
        ws = MagicMock()
        ws.closed = False
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


# ---------------------------------------------------------------------------
# Reconnect delay reset
# ---------------------------------------------------------------------------


class TestReconnectDelayReset:
    """Agent should reset backoff delay after a healthy connection."""

    @pytest.mark.asyncio
    async def test_delay_resets_after_long_connection(self):
        """When a connection lasts > HEALTHY_THRESHOLD, delay resets to initial."""
        from netbridge_agent.agent import run_agent, RECONNECT_DELAY

        delays = []
        call_count = 0
        stop = asyncio.Event()

        async def fake_connect_and_run(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First connection: simulate a healthy 120-second connection
                # that was closed by the server (not intentional stop)
                return False, 120.0
            elif call_count == 2:
                # Second connection: another healthy connection
                return False, 90.0
            else:
                # Third connection: stop
                stop.set()
                return True, 5.0

        async def capture_wait(coro, timeout):
            delays.append(timeout)
            if stop.is_set():
                return
            raise asyncio.TimeoutError

        with patch("netbridge_agent.agent.connect_and_run", side_effect=fake_connect_and_run), \
             patch("netbridge_agent.agent.check_az_login", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_arm_token", return_value="tok"), \
             patch("netbridge_agent.agent.check_token_expiration", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_user_identity", return_value="user@test"), \
             patch("netbridge_agent.agent.cleanup_idle_streams", new_callable=AsyncMock), \
             patch("netbridge_agent.agent.token_refresh_loop", new_callable=AsyncMock), \
             patch("asyncio.wait_for", side_effect=capture_wait):
            await run_agent("relay.com", stop)

        # After healthy long connections, delay should reset to RECONNECT_DELAY
        # We should see initial delay (RECONNECT_DELAY) after first healthy disconnect
        assert len(delays) >= 2
        # First delay after 120s connection should be RECONNECT_DELAY (not escalated)
        assert delays[0] == RECONNECT_DELAY
        # Second delay after 90s connection should also be RECONNECT_DELAY
        assert delays[1] == RECONNECT_DELAY


# ---------------------------------------------------------------------------
# Initial auth retry
# ---------------------------------------------------------------------------


class TestInitialAuthRetry:
    """A failed initial auth must be retried, not leave the agent dead."""

    @pytest.mark.asyncio
    async def test_retries_after_transient_auth_failure(self):
        """az CLI timeout on first attempt -> agent retries and then connects."""
        from netbridge_agent.agent import run_agent, RECONNECT_DELAY

        stop = asyncio.Event()
        statuses = []
        delays = []
        login_results = iter([
            (False, "Azure CLI timed out after 30s."),
            (True, "ok"),
        ])

        async def fake_connect_and_run(*args, **kwargs):
            stop.set()
            return True, 5.0

        async def capture_wait(coro, timeout):
            coro.close()
            delays.append(timeout)
            raise asyncio.TimeoutError

        with patch("netbridge_agent.agent.connect_and_run", side_effect=fake_connect_and_run) as mock_connect, \
             patch("netbridge_agent.agent.check_az_login", side_effect=lambda: next(login_results)), \
             patch("netbridge_agent.agent.get_arm_token", return_value="tok"), \
             patch("netbridge_agent.agent.check_token_expiration", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_user_identity", return_value="user@test"), \
             patch("netbridge_agent.agent.cleanup_idle_streams", new_callable=AsyncMock), \
             patch("netbridge_agent.agent.token_refresh_loop", new_callable=AsyncMock), \
             patch("asyncio.wait_for", side_effect=capture_wait):
            await run_agent("relay.com", stop, on_status_change=lambda c, a: statuses.append((c, a)))

        assert statuses[0] == (False, True)  # auth_required reported while retrying
        assert delays[0] == RECONNECT_DELAY
        mock_connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_during_auth_retry_returns(self):
        """Stopping while waiting to retry auth exits cleanly without connecting."""
        from netbridge_agent.agent import run_agent

        stop = asyncio.Event()

        async def stop_on_wait(coro, timeout):
            coro.close()
            stop.set()

        with patch("netbridge_agent.agent.connect_and_run", new_callable=AsyncMock) as mock_connect, \
             patch("netbridge_agent.agent.check_az_login", return_value=(False, "Not logged in")), \
             patch("asyncio.wait_for", side_effect=stop_on_wait):
            await run_agent("relay.com", stop)

        mock_connect.assert_not_called()


class TestIPv4MappedPolicy:
    @pytest.mark.parametrize("host", ["::ffff:127.0.0.1", "[::ffff:127.0.0.1]"])
    async def test_mapped_loopback_blocked(self, host):
        assert (await validate_destination(host, 80))[0] is False
        assert (await validate_destination(host, 80, allow_loopback=True))[0] is True

    @pytest.mark.parametrize("host", ["::ffff:169.254.169.254", "[::ffff:169.254.169.254]"])
    async def test_mapped_link_local_always_blocked(self, host):
        assert (await validate_destination(host, 80, allow_loopback=True))[0] is False

    async def test_mapped_private_follows_allow_private(self):
        assert (await validate_destination("::ffff:10.0.0.1", 80, allow_private=False))[0] is False
        assert (await validate_destination("::ffff:10.0.0.1", 80))[0] is True

    async def test_mapped_address_matches_ipv4_cidr_rules(self):
        assert (await validate_destination("::ffff:10.1.2.3", 80, allowed_destinations=["10.0.0.0/8"]))[0] is True
        assert (await validate_destination("::ffff:11.1.2.3", 80, allowed_destinations=["10.0.0.0/8"]))[0] is False
        assert (await validate_destination("::ffff:10.1.2.3", 80, denied_destinations=["10.0.0.0/8"]))[0] is False

    async def test_plain_ipv6_unaffected(self):
        assert (await validate_destination("2001:4860:4860::8888", 443))[0] is True

    async def test_resolved_mapped_address_is_normalised(self):
        loop = asyncio.get_running_loop()
        infos = [(10, 1, 6, "", ("::ffff:127.0.0.1", 0, 0, 0))]
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=infos)):
            assert (await validate_destination("evil.example", 80))[0] is False


class TestMappedFormCidrEntries:
    @pytest.mark.parametrize("host", ["10.1.2.3", "::ffff:10.1.2.3"])
    async def test_mapped_form_deny_entry_blocks_v4_and_mapped(self, host):
        r = await validate_destination(host, 80, denied_destinations=["::ffff:10.0.0.0/104"])
        assert r[0] is False

    @pytest.mark.parametrize("host", ["10.1.2.3", "::ffff:10.1.2.3"])
    async def test_mapped_form_allow_entry_allows(self, host):
        assert (await validate_destination(host, 80, allowed_destinations=["::ffff:10.0.0.0/104"]))[0] is True
        assert (await validate_destination("11.1.2.3", 80, allowed_destinations=["::ffff:10.0.0.0/104"]))[0] is False


# ---------------------------------------------------------------------------
# magic-host (intercept) failures
# ---------------------------------------------------------------------------


class TestMagicHostUnavailable:
    @staticmethod
    async def _connect(state):
        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock()
        msg = json.dumps({"type": "tcp_connect", "stream_id": "s1", "host": "netbridge-exec", "port": 80})
        await handle_message(state, ws, msg)
        return json.loads(ws.send_str.call_args.args[0])

    async def test_service_not_available(self):
        state = AgentState()
        state.get_intercept_server = lambda: MagicMock(port_for=lambda h: None)
        sent = await self._connect(state)
        assert sent["success"] is False
        assert sent["error"] == "Service netbridge-exec is not available"
        assert sent["error_code"] == "unavailable"

    async def test_intercept_not_configured(self):
        state = AgentState()
        state.get_intercept_server = None
        sent = await self._connect(state)
        assert sent["success"] is False
        assert sent["error"] == "Intercept server is not configured"
        assert sent["error_code"] == "unavailable"

    async def test_intercept_not_running(self):
        state = AgentState()
        state.get_intercept_server = lambda: None
        sent = await self._connect(state)
        assert sent["success"] is False
        assert sent["error"] == "Intercept server is not running"
        assert sent["error_code"] == "unavailable"


# ---------------------------------------------------------------------------
# error_code on failed tcp_connect_result
# ---------------------------------------------------------------------------


class TestConnectErrorCodes:
    @staticmethod
    async def _connect(state, host="example.com", port=80):
        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock()
        msg = json.dumps({"type": "tcp_connect", "stream_id": "s1", "host": host, "port": port})
        await handle_message(state, ws, msg)
        task = state.pending_connections.get("s1")
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)
        return json.loads(ws.send_str.call_args.args[0])

    async def test_pending_cap_is_capacity(self, monkeypatch):
        from netbridge_agent import agent
        monkeypatch.setattr(agent, "MAX_CONCURRENT_CONNECTIONS", 0)
        sent = await self._connect(AgentState())
        assert sent["error"] == "Too many pending connections"
        assert sent["error_code"] == "capacity"

    async def test_active_cap_is_capacity(self, monkeypatch):
        from netbridge_agent import agent
        monkeypatch.setattr(agent, "MAX_ACTIVE_STREAMS", 0)
        sent = await self._connect(AgentState())
        assert sent["error"] == "Too many active streams"
        assert sent["error_code"] == "capacity"

    async def test_denied_destination_is_not_allowed_and_logged(self, caplog):
        state = AgentState()
        with caplog.at_level("WARNING"):
            sent = await self._connect(state, host="127.0.0.1")
        assert sent["success"] is False
        assert sent["error_code"] == "not_allowed"
        assert any(r.getMessage().startswith("Destination denied: s1 -> 127.0.0.1:80: ")
                   and r.getMessage().endswith(" [not_allowed]") for r in caplog.records)

    async def test_empty_resolution_is_dns_failed(self, monkeypatch, caplog):
        from netbridge_agent import agent
        monkeypatch.setattr(agent, "resolve_destination", AsyncMock(return_value=[]))
        with caplog.at_level("WARNING"):
            sent = await self._connect(AgentState())
        assert sent["error_code"] == "dns_failed"
        msgs = [r.getMessage() for r in caplog.records]
        assert any(m.startswith("DNS returned no usable addresses: s1 -> example.com:80")
                   and m.endswith(" [dns_failed]") for m in msgs)
        assert not any(m.startswith("Destination denied") for m in msgs)

    async def test_empty_resolution_with_cidr_allowlist_is_still_dns_failed(self, monkeypatch):
        from netbridge_agent import agent
        monkeypatch.setattr(agent, "resolve_destination", AsyncMock(return_value=[]))
        state = AgentState()
        state.allowed_destinations = ["203.0.113.0/24"]
        sent = await self._connect(state)
        assert sent["error_code"] == "dns_failed"

    async def test_refused(self, monkeypatch, caplog):
        from netbridge_agent import agent
        import ipaddress
        monkeypatch.setattr(agent, "resolve_destination",
                            AsyncMock(return_value=[ipaddress.ip_address("93.184.216.34")]))
        monkeypatch.setattr(agent, "open_tcp_connection",
                            AsyncMock(side_effect=ConnectionRefusedError("refused")))
        with caplog.at_level("WARNING"):
            sent = await self._connect(AgentState())
        assert sent["error_code"] == "refused"
        assert any(r.getMessage().startswith("Failed: s1 -> example.com:80: ConnectionRefusedError: ")
                   and r.getMessage().endswith(" [refused]") for r in caplog.records)

    async def test_dns_error_from_resolution(self, monkeypatch, caplog):
        from netbridge_agent import agent
        monkeypatch.setattr(agent, "resolve_destination",
                            AsyncMock(side_effect=agent.DnsError("no such host")))
        with caplog.at_level("WARNING"):
            sent = await self._connect(AgentState())
        assert sent["error_code"] == "dns_failed"
        assert any(r.getMessage().startswith("Failed: s1 -> example.com:80: DnsError: no such host")
                   and r.getMessage().endswith(" [dns_failed]") for r in caplog.records)

    async def test_proxy_auth_rejected_is_upstream_proxy(self, monkeypatch):
        from netbridge_agent import agent
        from netbridge_agent.tunnel import ProxyAuthRejected
        import ipaddress
        monkeypatch.setattr(agent, "resolve_destination",
                            AsyncMock(return_value=[ipaddress.ip_address("93.184.216.34")]))
        monkeypatch.setattr(agent, "open_tcp_connection",
                            AsyncMock(side_effect=ProxyAuthRejected("rejected", 407)))
        sent = await self._connect(AgentState())
        assert sent["error_code"] == "upstream_proxy"
