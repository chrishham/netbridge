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


@pytest.mark.asyncio
async def test_per_ip_limit_rejects_third_request(client, monkeypatch):
    """Per-IP limit (patched to 2) should reject third upgrade with 429."""
    # Patch the per-IP limit to 2
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 2)

    # Mock authenticate to always succeed
    async def mock_auth(request):
        return True, USER

    with patch("relay.__main__.authenticate_request", side_effect=mock_auth):
        # First two connections should succeed (and get registered)
        resp1 = await client.ws_connect("/ws")
        msg1 = await resp1.receive_json()
        assert msg1["type"] == "registered"

        resp2 = await client.ws_connect("/ws")
        msg2 = await resp2.receive_json()
        assert msg2["type"] == "registered"

        # Third connection should be rejected with 429 before auth
        resp3 = await client.get("/ws")
        assert resp3.status == 429
        text = await resp3.text()
        assert "Too many requests from this IP" in text

        # Clean up
        await resp1.close()
        await resp2.close()


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
