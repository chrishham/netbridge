import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from netbridge_agent.agent import AgentState, handle_message


def _ws():
    ws = MagicMock(closed=False)
    ws.send_str = AsyncMock()
    return ws


def _sent(ws):
    return [json.loads(c.args[0]) for c in ws.send_str.await_args_list]


@pytest.mark.parametrize("raw", ["[1]", '"x"', "null", "42", "true"])
async def test_handle_message_ignores_non_objects(raw):
    await handle_message(AgentState(), _ws(), raw)       # must not raise


@pytest.mark.parametrize("host,port", [([], 80), (None, 80), ("", 80), ("h", True), ("h", "80"),
                                       ("h", 0), ("h", 65536), ("h", None)])
async def test_tcp_connect_with_bad_host_or_port_is_answered_not_crashed(host, port):
    ws = _ws()
    await handle_message(AgentState(), ws, json.dumps(
        {"type": "tcp_connect", "stream_id": "s1", "host": host, "port": port}))
    (res,) = _sent(ws)
    assert res == {"type": "tcp_connect_result", "stream_id": "s1", "success": False,
                   "error": "Invalid host or port"}


@pytest.mark.parametrize("sid", [None, [1], "", "x" * 129, 5])
@pytest.mark.parametrize("kind", ["tcp_connect", "tcp_data", "tcp_close"])
async def test_bad_stream_id_is_dropped(kind, sid):
    ws, state = _ws(), AgentState()
    await handle_message(state, ws, json.dumps(
        {"type": kind, "stream_id": sid, "host": "8.8.8.8", "port": 80, "data": "AA=="}))
    assert state.active_streams == {} and state.pending_connections == {}


@pytest.mark.parametrize("data", [None, 5, [1], "!!not-base64!!"])
async def test_tcp_data_with_bad_data_closes_the_stream(data, mock_writer, mock_reader):
    from netbridge_agent.agent import StreamInfo
    state = AgentState()
    state.active_streams["s1"] = StreamInfo(mock_reader, mock_writer, None, "h", 80)
    await handle_message(state, _ws(), json.dumps({"type": "tcp_data", "stream_id": "s1", "data": data}))
    assert "s1" not in state.active_streams
    mock_writer.close.assert_called()
