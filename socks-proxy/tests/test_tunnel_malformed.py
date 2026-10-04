import asyncio
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
    tm.ws = _msgs(["{not json", "[1]", "null", "[" * 100000, good])
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
    h, _ = _register(tm, "s1")
    await tm._handle_message({"type": "tcp_data", "stream_id": "s1", "data": data})
    assert h.closed
    assert h.semaphore_released
    assert "s1" not in tm.streams                                                # removed
    sent = [json.loads(c.args[0]) for c in tm.ws.send_str.await_args_list]
    assert {"type": "tcp_close", "stream_id": "s1", "reason": "client_closed"} in sent


@pytest.mark.parametrize("result", [
    {"success": False}, {"success": False, "error": None}, {"success": False, "error": 5},
    {"success": False, "error": ""}])
@pytest.mark.asyncio
async def test_failed_result_without_str_error_is_normalised_to_pinned_failure(result):
    tm = _tm()
    task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=2))
    for _ in range(100):
        if tm.streams:
            break
        await asyncio.sleep(0)
    assert tm.streams, "connect() never registered a stream"
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
        await asyncio.sleep(0)
    assert tm.streams, "connect() never registered a stream"
    (sid,) = tm.streams
    handler = tm.streams[sid]
    await tm._handle_message({"type": "tcp_connect_result", "stream_id": sid, "success": "yes"})
    assert isinstance(handler.connect_future.exception(), ConnectionError)
    with pytest.raises(ConnectionError, match="Invalid connect result"):
        await task
    assert sid not in tm.streams
    sent = [json.loads(c.args[0]) for c in tm.ws.send_str.call_args_list]
    assert {"type": "tcp_close", "stream_id": sid, "reason": "client_closed"} in sent


@pytest.mark.asyncio
async def test_connect_timeout_tells_the_relay_to_close():
    tm = _tm()
    with pytest.raises(asyncio.TimeoutError):
        await tm.connect("10.0.0.1", 80, timeout=0.01)
    sent = [json.loads(c.args[0]) for c in tm.ws.send_str.call_args_list]
    assert sent[0]["type"] == "tcp_connect"
    assert sent[-1] == {"type": "tcp_close", "stream_id": sent[0]["stream_id"], "reason": "client_closed"}
    assert tm.streams == {}


@pytest.mark.asyncio
async def test_cancelled_connect_frees_the_stream_and_tells_the_relay():
    tm = _tm()
    free_before = tm._stream_semaphore._value
    task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=5))
    for _ in range(100):
        if tm.streams:
            break
        await asyncio.sleep(0)
    (sid,) = tm.streams
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert tm.streams == {}
    assert tm._stream_semaphore._value == free_before
    sent = [json.loads(c.args[0]) for c in tm.ws.send_str.call_args_list]
    assert sent[-1] == {"type": "tcp_close", "stream_id": sid, "reason": "client_closed"}


@pytest.mark.asyncio
async def test_cancel_while_sending_the_connect_request_frees_the_slot():
    tm = _tm()
    free_before = tm._stream_semaphore._value
    sending = asyncio.Event()
    sent = []

    async def send_str(data):
        msg = json.loads(data)
        sent.append(msg)
        if msg["type"] == "tcp_connect":
            sending.set()
            await asyncio.Event().wait()     # the write never completes

    tm.ws.send_str = send_str
    task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=5))
    await sending.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert tm.streams == {}
    assert tm._stream_semaphore._value == free_before
    assert sent[-1] == {"type": "tcp_close", "stream_id": sent[0]["stream_id"], "reason": "client_closed"}


@pytest.mark.parametrize("sent, expected", [
    ({"error_code": "refused"}, "refused"),
    ({"error_code": "future_code"}, "future_code"),
    ({"error_code": 5}, None),
    ({"error_code": "BAD"}, None),
    ({}, None),
])
@pytest.mark.asyncio
async def test_connect_error_code_attached_only_when_well_formed(sent, expected):
    tm = _tm()
    task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=2))
    for _ in range(100):
        if tm.streams:
            break
        await asyncio.sleep(0)
    assert tm.streams, "connect() never registered a stream"
    (sid,) = tm.streams
    await tm._handle_message({
        "type": "tcp_connect_result", "stream_id": sid,
        "success": False, "error": "nope", **sent,
    })
    with pytest.raises(TunnelConnectError) as exc_info:
        await task
    assert exc_info.value.error_code == expected
    assert isinstance(exc_info.value, ConnectionError)
