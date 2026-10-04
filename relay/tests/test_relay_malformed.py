import json  # noqa: F401

import pytest

from .test_relay_lifecycle import (  # noqa: F401  (fixtures are used by name)
    USER, Peer, client, connect_agent, connect_tunnel, open_stream, relay_state, wait_until,
)
import relay.__main__ as mod

pytestmark = pytest.mark.asyncio

NON_OBJECTS = ["[1]", '"x"', "null", "42", "true"]


def _no_traceback(caplog):
    assert not [r for r in caplog.records if r.levelname == "ERROR"], caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.parametrize("raw", NON_OBJECTS)
async def test_tunnel_survives_non_object(client, raw, caplog):
    tunnel = await connect_tunnel(client)
    await tunnel.ws.send_str(raw)
    await tunnel.send(type="tcp_connect", stream_id="s1", host="10.0.0.1", port=80)
    res = await tunnel.expect("tcp_connect_result", stream_id="s1", success=False)
    assert "agent" in res["error"].lower()          # relay still answers: not torn down
    assert not tunnel.ws.closed
    assert "non-object" in caplog.text
    _no_traceback(caplog)


@pytest.mark.parametrize("raw", NON_OBJECTS)
async def test_agent_ws_survives_non_object(client, raw, caplog):
    agent, _ = await connect_agent(client)
    await agent.ws.send_str(raw)
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "non-object" in caplog.text
    _no_traceback(caplog)


BAD_STREAM_IDS = [None, [1], {}, "", "x" * 129, 7]


@pytest.mark.parametrize("sid", BAD_STREAM_IDS)
async def test_tunnel_bad_stream_id_never_becomes_a_key(client, sid, caplog):
    tunnel = await connect_tunnel(client)
    await tunnel.send(type="tcp_connect", stream_id=sid, host="10.0.0.1", port=80)
    res = await tunnel.expect("tcp_connect_result", success=False)
    assert res["stream_id"] is None and res["error"] == "Invalid stream_id"
    assert res["error_code"] == "invalid_request"
    for t in ("tcp_data", "tcp_close"):
        await tunnel.send(type=t, stream_id=sid, data="AA==")
    await tunnel.send(type="tcp_connect", stream_id="ok", host="10.0.0.1", port=80)
    await tunnel.expect("tcp_connect_result", stream_id="ok")
    assert mod.tcp_streams == {}
    _no_traceback(caplog)


@pytest.mark.parametrize("data", [None, 5, [1], {"a": 1}])
async def test_agent_tcp_data_with_non_str_data_is_not_forwarded(client, data):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    await agent.send(type="tcp_connect_result", stream_id="s1", success=True)
    await tunnel.expect("tcp_connect_result", stream_id="s1")
    await agent.send(type="tcp_data", stream_id="s1", data=data)
    await agent.send(type="tcp_data", stream_id="s1", data="AA==")
    got = await tunnel.expect("tcp_data", stream_id="s1")
    assert got["data"] == "AA=="                     # only the valid frame arrived


@pytest.mark.parametrize("fields", [
    {"success": "yes"},                              # non-bool success
    {"success": False},                              # failed result without error
    {"success": False, "error": None},
    {"success": False, "error": 5},
    {"success": True, "error": "boom"},              # error only allowed when absent/null on success
    {"success": False, "error": "x", "error_code": 5},            # non-str code
    {"success": False, "error": "x", "error_code": "REFUSED"},    # uppercase
    {"success": False, "error": "x", "error_code": "a" * 33},     # too long
    {"success": False, "error": "x", "error_code": ""},           # empty
    {"success": True, "error_code": "refused"},                   # code on success
])
async def test_invalid_connect_results_are_dropped(client, fields):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    await agent.send(type="tcp_connect_result", stream_id="s1", **fields)
    await agent.send(type="tcp_connect_result", stream_id="s1", success=True)
    good = await tunnel.expect("tcp_connect_result", stream_id="s1")
    assert good["success"] is True                   # the invalid ones were never forwarded


@pytest.mark.parametrize("data", [None, 1, [1]])
async def test_tunnel_tcp_data_with_non_str_data_is_not_forwarded(client, data, caplog):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    await tunnel.send(type="tcp_data", stream_id="s1", data=data)
    await tunnel.send(type="tcp_data", stream_id="s1", data="AA==")
    got = await agent.expect("tcp_data", stream_id="s1")
    assert got["data"] == "AA=="                     # only the valid frame arrived
    assert [m["data"] for m in agent.seen if m.get("type") == "tcp_data"] == ["AA=="]
    assert "Invalid tcp_data payload from tunnel client" in caplog.text
    assert not tunnel.ws.closed
    _no_traceback(caplog)


@pytest.mark.parametrize("sid", [None, [1], "x" * 129])
@pytest.mark.parametrize("type_", ["tcp_connect_result", "tcp_data", "tcp_close"])
async def test_agent_bad_stream_id_is_dropped_and_loop_continues(client, sid, type_, caplog):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    await agent.send(type=type_, stream_id=sid, success=True, data="AA==")
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "Invalid stream_id from agent" in caplog.text
    assert not [m for m in tunnel.seen if m.get("type") in ("tcp_connect_result", "tcp_data", "tcp_close")]
    assert "s1" in mod.tcp_streams
    _no_traceback(caplog)
