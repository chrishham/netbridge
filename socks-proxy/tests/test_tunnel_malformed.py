import asyncio
import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import WSMsgType

from socks_proxy.stream import StreamHandler
from socks_proxy.tunnel import TunnelManager, TunnelConnectError


def _tm():
    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")
    tm._connected.set()
    tm.ws = MagicMock(closed=False)
    tm.ws.send_str = AsyncMock()
    return tm


def _msgs(frames):
    class WS:
        closed = False
        send_str = AsyncMock()

        def __aiter__(self):
            async def gen():
                for f in frames:
                    yield MagicMock(type=WSMsgType.TEXT, data=f)
            return gen()

    return WS()


def _register(tm, sid="s1"):
    fut = asyncio.get_running_loop().create_future()
    h = StreamHandler(stream_id=sid, connect_future=fut)
    tm.streams[sid] = h
    return h, fut


@pytest.mark.asyncio
async def test_receive_loop_survives_bad_syntax_then_processes_valid():
    tm = _tm()
    h, fut = _register(tm)
    good = json.dumps({"type": "tcp_connect_result", "stream_id": "s1", "success": True})
    tm.ws = _msgs(["{not json", "[1]", "null", good])
    await tm._receive_loop()
    assert fut.done() and fut.result()["success"] is True


@pytest.mark.parametrize("sid", [None, [1], "", "x" * 129, 5])
@pytest.mark.asyncio
async def test_bad_stream_id_is_dropped(sid):
    tm = _tm()
    await tm._handle_message({"type": "tcp_data", "stream_id": sid, "data": "AA=="})   # no raise
    assert tm.streams == {}


@pytest.mark.parametrize("data", [None, 5, [1], "!!not-base64!!"])
@pytest.mark.asyncio
async def test_bad_tcp_data_closes_the_stream_and_notifies_the_relay(data):
    tm = _tm()
    _register(tm)
    await tm._handle_message({"type": "tcp_data", "stream_id": "s1", "data": data})
    assert "s1" not in tm.streams                                                # removed
    sent = [json.loads(c.args[0]) for c in tm.ws.send_str.await_args_list]
    assert {"type": "tcp_close", "stream_id": "s1", "reason": "client_closed"} in sent


@pytest.mark.parametrize("result", [
    {"success": False}, {"success": False, "error": None}, {"success": False, "error": 5}])
@pytest.mark.asyncio
async def test_failed_result_without_str_error_is_normalised_to_pinned_failure(result):
    tm = _tm()
    task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=2))
    for _ in range(100):
        if tm.streams:
            break
        await asyncio.sleep(0.01)
    (sid,) = tm.streams
    await tm._handle_message({"type": "tcp_connect_result", "stream_id": sid, **result})
    with pytest.raises(TunnelConnectError, match="Unknown error"):
        await task


@pytest.mark.asyncio
async def test_non_bool_success_fails_the_connect():
    tm = _tm()
    task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=2))
    for _ in range(100):
        if tm.streams:
            break
        await asyncio.sleep(0.01)
    (sid,) = tm.streams
    await tm._handle_message({"type": "tcp_connect_result", "stream_id": sid, "success": "yes"})
    with pytest.raises(ConnectionError, match="Invalid connect result"):
        await task
