from unittest.mock import AsyncMock

import pytest

from .test_relay_lifecycle import (  # noqa: F401  (fixtures are used by name)
    USER, Peer, client, connect_agent, connect_tunnel, open_stream, relay_state, wait_until,
)
import relay.__main__ as mod

pytestmark = pytest.mark.asyncio


async def test_failed_connect_result_releases_the_stream(client):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    assert "s1" in mod.tcp_streams
    await agent.send(type="tcp_connect_result", stream_id="s1", success=False, error="refused")
    res = await tunnel.expect("tcp_connect_result", stream_id="s1", success=False)
    assert res["error"] == "refused"                 # still forwarded
    await wait_until(lambda: "s1" not in mod.tcp_streams)


async def test_successful_connect_result_keeps_the_stream(client):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    await agent.send(type="tcp_connect_result", stream_id="s1", success=True)
    await tunnel.expect("tcp_connect_result", stream_id="s1", success=True)
    assert "s1" in mod.tcp_streams


async def test_failed_result_from_a_foreign_agent_does_not_release(client):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    mod.tcp_streams["s1"]["user_email"] = "someone@else"   # stream owned by another user
    await agent.send(type="tcp_connect_result", stream_id="s1", success=False, error="x")
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "s1" in mod.tcp_streams


async def test_tcp_close_is_forwarded_and_removes_the_stream(client):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    await agent.send(type="tcp_close", stream_id="s1")
    await tunnel.expect("tcp_close", stream_id="s1")
    await wait_until(lambda: "s1" not in mod.tcp_streams)


async def test_ownership_denied_from_other_agent_socket_is_dropped(client, caplog):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    mod.tcp_streams["s1"]["agent_ws"] = object()     # stream bound to a different agent socket
    await agent.send(type="tcp_data", stream_id="s1", data="AA==")
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "ownership denied" in caplog.text
    assert not [m for m in tunnel.seen if m.get("type") == "tcp_data"]


async def test_oversized_message_is_dropped(client, monkeypatch, caplog):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    # patched after connect: the socket's own max_msg_size was fixed at connect time
    monkeypatch.setattr(mod, "MAX_MESSAGE_SIZE", 100)
    await agent.send(type="tcp_data", stream_id="s1", data="A" * 200)
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "Oversized message" in caplog.text
    assert not [m for m in tunnel.seen if m.get("type") == "tcp_data"]


async def test_unknown_type_warns(client, caplog):
    agent, _ = await connect_agent(client)
    await agent.send(type="bogus")
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "Unknown message type 'bogus'" in caplog.text


async def test_invalid_json_warns_and_loop_continues(client, caplog):
    agent, _ = await connect_agent(client)
    await agent.ws.send_str("{not json")
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "Invalid JSON from agent" in caplog.text


async def test_bandwidth_limiter_only_acquired_for_tcp_data(client, monkeypatch):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    limiter = AsyncMock()
    monkeypatch.setattr(mod, "_global_bandwidth_limiter", limiter)
    monkeypatch.setattr(mod, "_bytes_per_sec", 1000)
    await agent.send(type="tcp_connect_result", stream_id="s1", success=True)
    await tunnel.expect("tcp_connect_result", stream_id="s1")
    limiter.acquire.assert_not_called()
    await agent.send(type="tcp_data", stream_id="s1", data="AA==")
    await tunnel.expect("tcp_data", stream_id="s1")
    limiter.acquire.assert_awaited_once()


async def test_deeply_nested_json_warns_and_loop_continues(client, caplog):
    agent, _ = await connect_agent(client)
    await agent.ws.send_str("[" * 100000 + "]" * 100000)
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "Invalid JSON from agent" in caplog.text


async def test_failed_result_does_not_drop_a_stream_that_reused_the_id(client, monkeypatch):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    replacement = dict(mod.tcp_streams["s1"])
    real_send = mod.safe_ws_send

    async def send_then_reuse(ws, data):
        await real_send(ws, data)
        if '"tcp_connect_result"' in data:   # the id is reopened while the send yields
            mod.tcp_streams["s1"] = replacement

    monkeypatch.setattr(mod, "safe_ws_send", send_then_reuse)
    await agent.send(type="tcp_connect_result", stream_id="s1", success=False, error="refused")
    await tunnel.expect("tcp_connect_result", stream_id="s1", success=False)
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert mod.tcp_streams.get("s1") is replacement
