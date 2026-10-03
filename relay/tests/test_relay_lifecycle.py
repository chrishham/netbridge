"""Connection lifecycle tests: drive the real relay app over loopback websockets."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import relay.__main__ as mod

USER = "anonymous@local"  # identity the relay assigns in no-auth mode
WAIT = 1.0  # upper bound for any single expected message


@pytest.fixture(autouse=True)
def relay_state(monkeypatch):
    """No-auth mode and fresh module state for every test."""
    monkeypatch.setattr(mod, "REQUIRE_AUTH", False)
    monkeypatch.setattr(mod, "_state_lock", asyncio.Lock())
    for name in ("bridge_agents", "tunnel_clients", "tcp_streams", "_ip_limiters",
                 "_user_connection_limiters", "_user_message_limiters", "_user_stream_limiters"):
        monkeypatch.setattr(mod, name, {})


class RelayServer(TestServer):
    """TestServer that, like the relay's own AppRunner, does not cancel handlers on disconnect."""

    async def _make_runner(self, **kwargs):
        kwargs["handler_cancellation"] = False
        return web.AppRunner(self.app, **kwargs)


@pytest_asyncio.fixture
async def client():
    async with TestClient(RelayServer(mod.create_app())) as c:
        yield c


@pytest.fixture
def fast_sweep(monkeypatch):
    """Sweep every 10 ms (set before the app starts its sweep task)."""
    monkeypatch.setattr(mod, "STREAM_TIMEOUT", 5)
    monkeypatch.setattr(mod, "STREAM_CLEANUP_INTERVAL", 0.01)


class Peer:
    """Client websocket whose messages are read in the background (so close handshakes complete)."""

    def __init__(self, ws):
        self.ws = ws
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.seen: list[dict] = []
        self._reader = asyncio.create_task(self._read())

    async def _read(self):
        async for msg in self.ws:
            data = json.loads(msg.data)
            self.seen.append(data)
            await self.inbox.put(data)

    async def send(self, **msg):
        await self.ws.send_str(json.dumps(msg))

    async def expect(self, type_, **fields):
        """Return the next message of `type_` matching `fields`, skipping others."""
        async def _next():
            while True:
                m = await self.inbox.get()
                if m.get("type") == type_ and all(m.get(k) == v for k, v in fields.items()):
                    return m
        return await asyncio.wait_for(_next(), WAIT)

    async def close(self):
        await self.ws.close()
        await asyncio.wait_for(self._reader, WAIT)


async def connect_agent(client) -> tuple[Peer, object]:
    """Connect an agent; return its peer and the relay-side websocket."""
    agent = Peer(await client.ws_connect("/ws"))
    await agent.expect("registered")
    return agent, mod.bridge_agents[USER]


async def connect_tunnel(client) -> Peer:
    tunnel = Peer(await client.ws_connect("/tunnel"))
    await wait_until(lambda: len(mod.tunnel_clients) == 1)
    return tunnel


async def open_stream(tunnel: Peer, agent: Peer, sid: str):
    await tunnel.send(type="tcp_connect", stream_id=sid, host="10.0.0.1", port=80)
    await agent.expect("tcp_connect", stream_id=sid)


async def wait_until(cond, timeout=WAIT):
    deadline = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < deadline, "condition not met in time"
        await asyncio.sleep(0.005)


@pytest_asyncio.fixture
async def hold_cleanup(client, monkeypatch):
    """Factory: make the relay's agent cleanup for one websocket wait until released.

    Depends on `client` so every hold is released before the server shuts down.
    """
    real, releases = mod._cleanup_agent, []

    def hold(held_ws):
        entered, release, done = asyncio.Event(), asyncio.Event(), asyncio.Event()
        releases.append(release)

        async def wrapper(ws, user_email):
            if ws is held_ws:
                entered.set()
                await release.wait()
            await real(ws, user_email)
            if ws is held_ws:
                done.set()

        monkeypatch.setattr(mod, "_cleanup_agent", wrapper)
        return entered, release, done

    yield hold
    for release in releases:
        release.set()


@pytest.mark.asyncio
async def test_agent_disconnect_closes_its_streams(client):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")

    await agent.close()

    msg = await tunnel.expect("tcp_close", stream_id="s1")
    assert msg["reason"] == "agent_disconnected"
    assert "s1" not in mod.tcp_streams
    status = await (await client.get("/status")).json()
    assert status["agents"] == 0
    await tunnel.close()


@pytest.mark.asyncio
async def test_tunnel_disconnect_notifies_agent(client):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")

    await tunnel.close()

    msg = await agent.expect("tcp_close", stream_id="s1")
    assert msg["reason"] == "tunnel_client_disconnected"
    assert mod.tcp_streams == {}
    await agent.close()


@pytest.mark.asyncio
async def test_replacement_keeps_new_agent_and_its_streams(client, hold_cleanup):
    agent_a, ws_a = await connect_agent(client)
    entered, release, done = hold_cleanup(ws_a)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent_a, "s1")

    agent_b, ws_b = await connect_agent(client)  # relay closes A
    await asyncio.wait_for(entered.wait(), WAIT)
    await open_stream(tunnel, agent_b, "s2")
    # A's cleanup has not run yet: S2 exists alongside the held cleanup
    assert mod.bridge_agents[USER] is ws_b
    assert "s2" in mod.tcp_streams

    release.set()
    await asyncio.wait_for(done.wait(), WAIT)

    assert mod.bridge_agents[USER] is ws_b
    assert "s2" in mod.tcp_streams
    assert "s1" not in mod.tcp_streams
    await tunnel.expect("tcp_close", stream_id="s1", reason="agent_disconnected")
    closes = [m["stream_id"] for m in tunnel.seen if m["type"] == "tcp_close"]
    assert closes == ["s1"]
    await tunnel.close()
    await agent_b.close()


@pytest.mark.asyncio
async def test_old_stream_data_not_forwarded_to_replacement(client, hold_cleanup):
    agent_a, ws_a = await connect_agent(client)
    entered, release, done = hold_cleanup(ws_a)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent_a, "s1")

    agent_b, _ = await connect_agent(client)
    await asyncio.wait_for(entered.wait(), WAIT)
    await tunnel.send(type="tcp_data", stream_id="s1", data="aGVsbG8=")
    # The relay handles a tunnel's messages in order: once B sees S3, S1's data was handled
    await open_stream(tunnel, agent_b, "s3")
    assert [m for m in agent_b.seen if m.get("stream_id") == "s1"] == []
    await tunnel.expect("tcp_close", stream_id="s1", reason="agent_disconnected")

    release.set()
    await asyncio.wait_for(done.wait(), WAIT)
    assert all(m.get("stream_id") != "s1" for m in agent_b.seen)
    await tunnel.close()
    await agent_b.close()


@pytest.mark.asyncio
async def test_stale_sweep_closes_idle_streams_only(fast_sweep, client):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "idle")
    await open_stream(tunnel, agent, "fresh")
    mod.tcp_streams["idle"]["last_activity"] = time.monotonic() - 100

    for peer in (tunnel, agent):
        await peer.expect("tcp_close", stream_id="idle", reason="idle_timeout")
    assert "idle" not in mod.tcp_streams
    assert "fresh" in mod.tcp_streams
    assert all(m.get("stream_id") != "fresh" for m in tunnel.seen + agent.seen
               if m["type"] == "tcp_close")
    await tunnel.close()
    await agent.close()


@pytest.mark.asyncio
async def test_stale_sweep_rechecks_before_closing(fast_sweep, monkeypatch):
    tunnel_ws, agent_ws = AsyncMock(closed=False), AsyncMock(closed=False)
    stale = time.monotonic() - 100
    mod.bridge_agents[USER] = agent_ws
    mod.tcp_streams["s1"] = {
        "user_email": USER, "tunnel_key": "k", "tunnel_ws": tunnel_ws, "agent_ws": agent_ws,
        "created_at": stale, "last_activity": stale,
    }

    class RefreshingLock:
        """Refreshes s1 between the sweep's scan (1st acquire) and its removal (2nd acquire)."""

        def __init__(self):
            self.lock, self.acquired = asyncio.Lock(), 0

        async def __aenter__(self):
            self.acquired += 1
            if self.acquired == 2:
                mod.tcp_streams["s1"]["last_activity"] = time.monotonic()
            await self.lock.acquire()

        async def __aexit__(self, *exc):
            self.lock.release()

    lock = RefreshingLock()
    monkeypatch.setattr(mod, "_state_lock", lock)
    sweep = asyncio.create_task(mod.cleanup_stale_streams(MagicMock()))
    try:
        await wait_until(lambda: lock.acquired >= 3)  # removal step done, next scan started
    finally:
        sweep.cancel()
        await asyncio.gather(sweep, return_exceptions=True)

    assert "s1" in mod.tcp_streams
    tunnel_ws.send_str.assert_not_called()
    agent_ws.send_str.assert_not_called()
