"""Rate limit tests for relay server.

Tests per-IP and per-user connection limits.
"""

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from unittest.mock import AsyncMock, patch

import relay.__main__ as mod


USER = "testuser@example.com"


class RelayServer(TestServer):
    """TestServer that, like the relay's own AppRunner, does not cancel handlers on disconnect."""

    async def _make_runner(self, **kwargs):
        kwargs["handler_cancellation"] = False
        return web.AppRunner(self.app, **kwargs)


@pytest.fixture(autouse=True)
def relay_state(monkeypatch):
    """Auth mode and fresh module state for every test."""
    import asyncio
    monkeypatch.setattr(mod, "REQUIRE_AUTH", True)
    monkeypatch.setattr(mod, "_state_lock", asyncio.Lock())
    for name in ("bridge_agents", "tunnel_clients", "tcp_streams",
                 "_ip_limiters", "_user_connection_limiters",
                 "_user_message_limiters", "_user_stream_limiters"):
        monkeypatch.setattr(mod, name, {})


@pytest_asyncio.fixture
async def client():
    async with TestClient(RelayServer(mod.create_app())) as c:
        yield c


async def _auth_by_header(request):
    """Valid iff the bearer token is 'good'."""
    if request.headers.get("Authorization") == "Bearer good":
        return True, USER
    return False, "Invalid JWT format"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/ws", "/tunnel"])
async def test_failed_auth_exhausts_ip_bucket_but_valid_token_passes(client, monkeypatch, path):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 2)
    bad = {"Authorization": "Bearer bad"}
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        for _ in range(2):
            resp = await client.get(path, headers=bad)
            assert resp.status == 401
            assert "Invalid JWT format" in await resp.text()
        resp = await client.get(path, headers=bad)
        assert resp.status == 429
        assert "Too many failed attempts from this IP" in await resp.text()

        ws = await client.ws_connect(path, headers={"Authorization": "Bearer good"})
        try:
            if path == "/ws":
                assert (await ws.receive_json())["type"] == "registered"
            else:
                assert not ws.closed
        finally:
            await ws.close()


@pytest.mark.asyncio
async def test_valid_tokens_never_consume_ip_bucket(client, monkeypatch):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 2)
    monkeypatch.setattr(mod, "RATE_LIMIT_CONNECTIONS_PER_MIN", 100)
    good = {"Authorization": "Bearer good"}
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        sockets = [await client.ws_connect("/tunnel", headers=good) for _ in range(3)]
        try:
            assert all(not ws.closed for ws in sockets)
            resp = await client.get("/tunnel", headers={"Authorization": "Bearer bad"})
            assert resp.status == 401  # bucket untouched by the three valid upgrades
        finally:
            for ws in sockets:
                await ws.close()


@pytest.mark.asyncio
async def test_per_user_limit_still_applies_when_ip_bucket_empty(client, monkeypatch):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 1)
    monkeypatch.setattr(mod, "RATE_LIMIT_CONNECTIONS_PER_MIN", 1)
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        assert (await client.get("/tunnel", headers={"Authorization": "Bearer bad"})).status == 401
        assert (await client.get("/tunnel", headers={"Authorization": "Bearer bad"})).status == 429
        ws = await client.ws_connect("/tunnel", headers={"Authorization": "Bearer good"})
        try:
            resp = await client.get("/tunnel", headers={"Authorization": "Bearer good"})
            assert resp.status == 429
            assert "Too many connection attempts" in await resp.text()
        finally:
            await ws.close()


@pytest.mark.asyncio
async def test_rapid_valid_connections_hit_per_user_limit_with_defaults(client):
    """Mirrors pentest rapid_connection_dos: 35 valid /tunnel upgrades from one IP, default limits."""
    good = {"Authorization": "Bearer good"}
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        for i in range(35):
            resp = await client.get("/tunnel", headers=good)  # plain GET: auth and limits run before the upgrade
            if resp.status == 429:
                assert "Too many connection attempts" in await resp.text()
                assert i <= mod.RATE_LIMIT_CONNECTIONS_PER_MIN
                break
        else:
            pytest.fail("no 429 within 35 valid connections")


@pytest.mark.asyncio
async def test_failed_auth_logs_keep_their_text(client, monkeypatch, caplog):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 1)
    bad = {"Authorization": "Bearer bad"}
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        await client.get("/ws", headers=bad)
        await client.get("/ws", headers=bad)
    text = caplog.text
    assert "Agent auth rejected for 127.0.0.1: Invalid JWT format" in text
    assert "Per-IP auth-failure limit exceeded for 127.0.0.1 (0 more since last report)" in text


@pytest.mark.asyncio
async def test_throttle_warning_is_logged_once_per_window(client, monkeypatch, caplog):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 1)
    clock = [1000.0]
    monkeypatch.setattr(mod, "_now", lambda: clock[0])  # report clock only; aiolimiter keeps the real one
    bad = {"Authorization": "Bearer bad"}
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        for _ in range(6):  # 1 x 401, then 5 x 429
            await client.get("/ws", headers=bad)
        assert caplog.text.count("Per-IP auth-failure limit exceeded") == 1
        clock[0] += mod.IP_THROTTLE_REPORT_INTERVAL + 1
        await client.get("/ws", headers=bad)
    assert "(4 more since last report)" in caplog.text


@pytest.mark.asyncio
async def test_per_user_limit_rejects_after_auth(client, monkeypatch):
    """Per-user limit (patched to 2) should reject third connection after auth."""
    # Patch the per-user connection limit to 2
    monkeypatch.setattr(mod, "RATE_LIMIT_CONNECTIONS_PER_MIN", 2)

    # Mock authenticate to always succeed
    call_count = [0]

    async def mock_auth(request):
        call_count[0] += 1
        return True, USER

    with patch("relay.__main__.authenticate_request", side_effect=mock_auth):
        # First two connections should succeed
        resp1 = await client.ws_connect("/ws")
        msg1 = await resp1.receive_json()
        assert msg1["type"] == "registered"

        resp2 = await client.ws_connect("/ws")
        msg2 = await resp2.receive_json()
        assert msg2["type"] == "registered"

        # Third connection should be rejected after auth with 429
        resp3 = await client.get("/ws")
        assert resp3.status == 429
        text = await resp3.text()
        assert "Too many connection attempts" in text

        # Verify auth was called for all three attempts
        assert call_count[0] == 3

        # Clean up
        await resp1.close()
        await resp2.close()


@pytest.mark.asyncio
async def test_rejected_token_does_not_consume_user_budget(client, monkeypatch):
    """Failed auth should not consume per-user connection budget."""
    # Patch the per-user connection limit to 2
    monkeypatch.setattr(mod, "RATE_LIMIT_CONNECTIONS_PER_MIN", 2)

    # First two attempts: auth fails
    # Third attempt: auth succeeds, should not be rate-limited
    call_count = [0]

    async def mock_auth(request):
        call_count[0] += 1
        if call_count[0] <= 2:
            return False, "Invalid token"
        return True, USER

    with patch("relay.__main__.authenticate_request", side_effect=mock_auth):
        # First two: should fail auth (401)
        resp1 = await client.get("/ws")
        assert resp1.status == 401

        resp2 = await client.get("/ws")
        assert resp2.status == 401

        # Third: should succeed (auth passes, not rate-limited)
        resp3 = await client.ws_connect("/ws")
        msg3 = await resp3.receive_json()
        assert msg3["type"] == "registered"

        # Verify auth was called three times
        assert call_count[0] == 3

        # Clean up
        await resp3.close()
