"""Tests for netbridge_agent.intercept module.

Covers magic hostname detection, InterceptServer lifecycle,
and agent-level intercept routing for magic hostnames.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from netbridge_agent.intercept import InterceptServer, is_magic_hostname


# ---------------------------------------------------------------------------
# is_magic_hostname
# ---------------------------------------------------------------------------


class TestMagicHostname:
    def test_netbridge_exec_is_magic(self):
        assert is_magic_hostname("netbridge-exec") is True

    def test_regular_hostname_is_not_magic(self):
        assert is_magic_hostname("example.com") is False

    def test_ip_address_is_not_magic(self):
        assert is_magic_hostname("10.0.0.1") is False
        assert is_magic_hostname("127.0.0.1") is False

    def test_case_insensitive(self):
        assert is_magic_hostname("NETBRIDGE-EXEC") is True
        assert is_magic_hostname("Netbridge-Exec") is True
        assert is_magic_hostname("NetBridge-Exec") is True


# ---------------------------------------------------------------------------
# InterceptServer
# ---------------------------------------------------------------------------


class TestInterceptServer:
    async def test_start_and_stop(self):
        server = InterceptServer()
        assert server.port is None

        await server.start()
        assert server.port is not None
        assert server.port > 0

        await server.stop()
        assert server.port is None

    async def test_health_through_intercept(self):
        server = InterceptServer()
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{server.port}/health"
                async with session.get(url) as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["status"] == "ok"
        finally:
            await server.stop()


# ---------------------------------------------------------------------------
# Agent intercept routing
# ---------------------------------------------------------------------------


class TestAgentIntercept:
    async def test_magic_host_rejected_when_disabled(self):
        """When get_remote_exec_state returns (False, None), magic host is rejected."""
        from netbridge_agent.agent import AgentState, handle_tcp_connect

        state = AgentState()
        state.get_remote_exec_state = lambda: (False, None)

        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock()

        request = {
            "stream_id": "abcd1234-test-stream",
            "host": "netbridge-exec",
            "port": 80,
        }

        await handle_tcp_connect(state, ws, request)

        # Wait for the pending connection task to finish
        for task in list(state.pending_connections.values()):
            await task

        # Should have sent a failure response
        assert ws.send_str.call_count >= 1
        sent = json.loads(ws.send_str.call_args_list[0][0][0])
        assert sent["type"] == "tcp_connect_result"
        assert sent["success"] is False
        assert "disabled" in sent["error"].lower()

    async def test_magic_host_rejected_when_not_configured(self):
        """When get_remote_exec_state is None, magic host is rejected."""
        from netbridge_agent.agent import AgentState, handle_tcp_connect

        state = AgentState()
        # get_remote_exec_state is None by default

        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock()

        request = {
            "stream_id": "abcd1234-test-stream",
            "host": "netbridge-exec",
            "port": 80,
        }

        await handle_tcp_connect(state, ws, request)

        for task in list(state.pending_connections.values()):
            await task

        assert ws.send_str.call_count >= 1
        sent = json.loads(ws.send_str.call_args_list[0][0][0])
        assert sent["type"] == "tcp_connect_result"
        assert sent["success"] is False
        assert "not configured" in sent["error"].lower()

    async def test_magic_host_uses_intercept_when_enabled(self):
        """When remote exec is enabled, magic host connects to intercept server."""
        from netbridge_agent.agent import AgentState, handle_tcp_connect

        server = InterceptServer()
        await server.start()
        try:
            state = AgentState()
            state.allow_loopback = True  # We need loopback for 127.0.0.1
            state.get_remote_exec_state = lambda: (True, server)

            ws = MagicMock()
            ws.closed = False
            ws.send_str = AsyncMock()

            request = {
                "stream_id": "abcd1234-test-stream",
                "host": "netbridge-exec",
                "port": 80,
            }

            await handle_tcp_connect(state, ws, request)

            # Wait for the pending connection task to finish
            for task in list(state.pending_connections.values()):
                await task

            # Should have sent a success response
            assert ws.send_str.call_count >= 1
            sent = json.loads(ws.send_str.call_args_list[0][0][0])
            assert sent["type"] == "tcp_connect_result"
            assert sent["success"] is True

            # Stream should be active and connected to the intercept port
            assert "abcd1234-test-stream" in state.active_streams
            stream = state.active_streams["abcd1234-test-stream"]
            assert stream.host == "127.0.0.1"
            assert stream.port == server.port
        finally:
            # Clean up the stream
            from netbridge_agent.agent import close_all_streams
            await close_all_streams(state, timeout=2.0)
            await server.stop()


# ---------------------------------------------------------------------------
# End-to-end integration tests
# ---------------------------------------------------------------------------


class TestEndToEndIntercept:
    """Test the full flow: InterceptServer serving remote_exec handlers."""

    @pytest.mark.asyncio
    async def test_e2e_health(self):
        """Health endpoint works through the intercept server."""
        import aiohttp
        from netbridge_agent.intercept import InterceptServer

        server = InterceptServer()
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://127.0.0.1:{server.port}/health") as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["status"] == "ok"
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_e2e_exec(self):
        """Exec endpoint works through the intercept server."""
        import aiohttp
        from netbridge_agent.intercept import InterceptServer

        server = InterceptServer()
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{server.port}/exec",
                    json={"cmd": "echo integration-test"}
                ) as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["exit_code"] == 0
                    assert "integration-test" in data["stdout"]
        finally:
            await server.stop()
