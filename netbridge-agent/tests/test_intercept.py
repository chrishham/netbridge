"""Tests for netbridge_agent.intercept module.

Covers magic hostname detection, InterceptServer dispatcher routing,
hot-plug register/unregister, error isolation, and streaming.
"""

import asyncio
import json

import aiohttp
import pytest
from aiohttp import web

from netbridge_agent.intercept import InterceptServer, is_magic_hostname, MAGIC_HOSTS


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


# ---------------------------------------------------------------------------
# InterceptServer — dispatcher routing
# ---------------------------------------------------------------------------


def _make_app(routes: dict[str, str]) -> web.Application:
    """Build a trivial aiohttp app from {path: response_text} pairs."""
    app = web.Application()
    for path, text in routes.items():

        async def handler(request, _text=text):
            return web.json_response({"msg": _text})

        app.router.add_get(path, handler)
    return app


class TestInterceptServerRouting:
    @pytest.mark.asyncio
    async def test_register_and_route_by_host_header(self):
        server = InterceptServer()
        server.register_app("netbridge-alpha", _make_app({"/hello": "alpha"}))
        server.register_app("netbridge-beta", _make_app({"/hello": "beta"}))
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/hello",
                    headers={"Host": "netbridge-alpha"},
                ) as r:
                    assert r.status == 200
                    assert (await r.json())["msg"] == "alpha"

                async with s.get(
                    f"http://127.0.0.1:{server.port}/hello",
                    headers={"Host": "netbridge-beta"},
                ) as r:
                    assert r.status == 200
                    assert (await r.json())["msg"] == "beta"
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_unknown_hostname_returns_404(self):
        server = InterceptServer()
        server.register_app("netbridge-known", _make_app({"/x": "ok"}))
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/x",
                    headers={"Host": "netbridge-unknown"},
                ) as r:
                    assert r.status == 404
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_unmatched_route_in_registered_app_returns_404(self):
        server = InterceptServer()
        server.register_app("netbridge-app", _make_app({"/exists": "yes"}))
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/nope",
                    headers={"Host": "netbridge-app"},
                ) as r:
                    assert r.status == 404
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_registered_hostnames_property(self):
        server = InterceptServer()
        server.register_app("netbridge-a", _make_app({}))
        server.register_app("netbridge-b", _make_app({}))
        assert server.registered_hostnames == {"netbridge-a", "netbridge-b"}


# ---------------------------------------------------------------------------
# InterceptServer — error isolation
# ---------------------------------------------------------------------------


class TestInterceptServerIsolation:
    @pytest.mark.asyncio
    async def test_crashing_plugin_returns_500_others_survive(self):
        crash_app = web.Application()

        async def crash(request):
            raise RuntimeError("plugin exploded")

        crash_app.router.add_get("/boom", crash)

        ok_app = _make_app({"/check": "alive"})

        server = InterceptServer()
        server.register_app("netbridge-crash", crash_app)
        server.register_app("netbridge-ok", ok_app)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/boom",
                    headers={"Host": "netbridge-crash"},
                ) as r:
                    assert r.status == 500

                async with s.get(
                    f"http://127.0.0.1:{server.port}/check",
                    headers={"Host": "netbridge-ok"},
                ) as r:
                    assert r.status == 200
                    assert (await r.json())["msg"] == "alive"
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_streaming_response_through_dispatcher(self):
        stream_app = web.Application()

        async def stream_handler(request):
            resp = web.StreamResponse(
                status=200, headers={"Content-Type": "text/plain"}
            )
            await resp.prepare(request)
            for i in range(3):
                await resp.write(f"line {i}\n".encode())
            await resp.write_eof()
            return resp

        stream_app.router.add_get("/stream", stream_handler)

        server = InterceptServer()
        server.register_app("netbridge-stream", stream_app)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/stream",
                    headers={"Host": "netbridge-stream"},
                ) as r:
                    assert r.status == 200
                    body = await r.text()
                    assert body.count("\n") == 3
        finally:
            await server.stop()


# ---------------------------------------------------------------------------
# InterceptServer — hot-plug
# ---------------------------------------------------------------------------


class TestInterceptServerHotPlug:
    @pytest.mark.asyncio
    async def test_hot_add_after_start(self):
        server = InterceptServer()
        await server.start()
        try:
            server.register_app("netbridge-late", _make_app({"/ping": "pong"}))
            assert "netbridge-late" in MAGIC_HOSTS

            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/ping",
                    headers={"Host": "netbridge-late"},
                ) as r:
                    assert r.status == 200
                    assert (await r.json())["msg"] == "pong"
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_hot_remove_after_start(self):
        server = InterceptServer()
        server.register_app("netbridge-temp", _make_app({"/hi": "there"}))
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/hi",
                    headers={"Host": "netbridge-temp"},
                ) as r:
                    assert r.status == 200

            server.unregister_app("netbridge-temp")
            assert "netbridge-temp" not in MAGIC_HOSTS

            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/hi",
                    headers={"Host": "netbridge-temp"},
                ) as r:
                    assert r.status == 404
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_unregister_nonexistent_is_noop(self):
        server = InterceptServer()
        server.unregister_app("netbridge-nope")  # should not raise


# ---------------------------------------------------------------------------
# InterceptServer — lifecycle
# ---------------------------------------------------------------------------


class TestInterceptServerLifecycle:
    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        server = InterceptServer()
        assert server.port is None
        await server.start()
        assert server.port is not None
        assert server.port > 0
        await server.stop()
        assert server.port is None

    @pytest.mark.asyncio
    async def test_start_with_no_apps_serves_404(self):
        server = InterceptServer()
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/anything",
                    headers={"Host": "netbridge-whatever"},
                ) as r:
                    assert r.status == 404
        finally:
            await server.stop()


# ---------------------------------------------------------------------------
# Agent intercept routing (simplified)
# ---------------------------------------------------------------------------


class TestAgentInterceptRouting:
    @pytest.mark.asyncio
    async def test_magic_host_routes_to_intercept_server(self):
        from netbridge_agent.agent import AgentState, handle_tcp_connect
        from netbridge_agent.remote_exec import create_app
        from unittest.mock import MagicMock, AsyncMock

        server = InterceptServer()
        server.register_app("netbridge-exec", create_app())
        await server.start()
        try:
            state = AgentState()
            state.allow_loopback = True
            state.get_intercept_server = lambda: server

            ws = MagicMock()
            ws.closed = False
            ws.send_str = AsyncMock()

            request = {
                "stream_id": "test-stream-1234",
                "host": "netbridge-exec",
                "port": 80,
            }

            await handle_tcp_connect(state, ws, request)
            for task in list(state.pending_connections.values()):
                await task

            sent = json.loads(ws.send_str.call_args_list[0][0][0])
            assert sent["type"] == "tcp_connect_result"
            assert sent["success"] is True
        finally:
            from netbridge_agent.agent import close_all_streams
            await close_all_streams(state, timeout=2.0)
            await server.stop()

    @pytest.mark.asyncio
    async def test_magic_host_rejected_when_no_server(self):
        from netbridge_agent.agent import AgentState, handle_tcp_connect
        from unittest.mock import MagicMock, AsyncMock

        state = AgentState()
        state.get_intercept_server = lambda: None

        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock()

        request = {
            "stream_id": "test-stream-5678",
            "host": "netbridge-exec",
            "port": 80,
        }

        await handle_tcp_connect(state, ws, request)
        for task in list(state.pending_connections.values()):
            await task

        sent = json.loads(ws.send_str.call_args_list[0][0][0])
        assert sent["type"] == "tcp_connect_result"
        assert sent["success"] is False
        assert "not running" in sent["error"].lower()

    @pytest.mark.asyncio
    async def test_magic_host_rejected_when_no_callback(self):
        from netbridge_agent.agent import AgentState, handle_tcp_connect
        from unittest.mock import MagicMock, AsyncMock

        state = AgentState()
        # get_intercept_server is None by default

        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock()

        request = {
            "stream_id": "test-stream-9999",
            "host": "netbridge-exec",
            "port": 80,
        }

        await handle_tcp_connect(state, ws, request)
        for task in list(state.pending_connections.values()):
            await task

        sent = json.loads(ws.send_str.call_args_list[0][0][0])
        assert sent["type"] == "tcp_connect_result"
        assert sent["success"] is False

    @pytest.mark.asyncio
    async def test_magic_host_rejected_when_hostname_not_registered(self):
        """TCP connect rejected at agent level when hostname isn't registered."""
        from netbridge_agent.agent import AgentState, handle_tcp_connect
        from unittest.mock import MagicMock, AsyncMock

        server = InterceptServer()
        await server.start()
        try:
            state = AgentState()
            state.allow_loopback = True
            state.get_intercept_server = lambda: server

            ws = MagicMock()
            ws.closed = False
            ws.send_str = AsyncMock()

            request = {
                "stream_id": "test-stream-unreg",
                "host": "netbridge-exec",
                "port": 80,
            }

            await handle_tcp_connect(state, ws, request)
            for task in list(state.pending_connections.values()):
                await task

            sent = json.loads(ws.send_str.call_args_list[0][0][0])
            assert sent["type"] == "tcp_connect_result"
            assert sent["success"] is False
            assert "remote exec is disabled" in sent["error"].lower()
        finally:
            await server.stop()
