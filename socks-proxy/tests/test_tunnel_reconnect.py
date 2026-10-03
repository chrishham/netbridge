"""Tests for tunnel reconnection, stream teardown, and pending connect handling."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from socks_proxy.stream import StreamHandler
from socks_proxy.tunnel import TunnelManager


@pytest.mark.asyncio
async def test_close_fails_pending_connect():
    """StreamHandler.close() fails a pending connect_future with ConnectionError."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    handler = StreamHandler(stream_id="s1", connect_future=future)

    await handler.close()

    assert handler.connect_future.done()
    assert isinstance(handler.connect_future.exception(), ConnectionError)
    assert "stream closed before connect completed" in str(handler.connect_future.exception())

    # Closing again with future already done should not raise
    await handler.close()


@pytest.mark.asyncio
async def test_ws_loss_fails_pending_connect_fast():
    """WebSocket loss fails pending connect within 1s and releases semaphore."""
    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")

    # Set up connected state with a fake websocket
    tm._connected.set()

    # Create a fake websocket that accepts send_str but never yields messages
    fake_ws = AsyncMock()
    fake_ws.closed = False
    fake_ws.__aiter__ = lambda self: self
    fake_ws.__anext__ = AsyncMock(side_effect=StopAsyncIteration())
    tm.ws = fake_ws

    # Start a connect task
    connect_task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=30))

    # Wait until the stream is registered
    for _ in range(50):  # Poll for up to 500ms
        if tm.streams:
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("Stream was not registered")

    # End the websocket's message iteration (simulate receive_loop ending)
    await tm._receive_loop()

    # The connect task must raise ConnectionError within 1s
    with pytest.raises(ConnectionError):
        await asyncio.wait_for(connect_task, timeout=1.0)

    # Streams must be empty and semaphore slot released
    assert len(tm.streams) == 0

    # Next connect can acquire immediately (semaphore slot was released)
    tm._connected.set()
    tm.ws = fake_ws
    try:
        await asyncio.wait_for(
            tm._stream_semaphore.acquire(),
            timeout=0.1
        )
        # If we get here, semaphore was acquired successfully
        tm._stream_semaphore.release()  # Clean up
    except asyncio.TimeoutError:
        raise AssertionError("Semaphore slot was not released")


@pytest.mark.asyncio
async def test_relay_tcp_close_fails_pending_connect():
    """tcp_close message fails pending connect within 1s."""
    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")

    tm._connected.set()

    # Create a fake websocket
    fake_ws = AsyncMock()
    fake_ws.closed = False
    tm.ws = fake_ws

    # Start a connect task
    connect_task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=30))

    # Wait until the stream is registered
    for _ in range(50):
        if tm.streams:
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("Stream was not registered")

    stream_id = list(tm.streams.keys())[0]

    # Deliver tcp_close message
    await tm._handle_message({
        "type": "tcp_close",
        "stream_id": stream_id,
        "reason": "agent_disconnected"
    })

    # Connect must raise ConnectionError within 1s
    with pytest.raises(ConnectionError):
        await asyncio.wait_for(connect_task, timeout=1.0)


@pytest.mark.asyncio
async def test_socks_reply_is_host_unreachable_on_pending_close():
    """SOCKS5 handler returns 0x04 when connect raises ConnectionError."""
    from socks_proxy.socks5 import handle_socks5_client, REPLY_HOST_UNREACHABLE

    # Create fake reader/writer
    reader = AsyncMock()
    writer = AsyncMock()
    writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 12345))

    # Fake tunnel that raises ConnectionError on connect
    tunnel = AsyncMock()
    tunnel.connect = AsyncMock(side_effect=ConnectionError("stream closed"))

    # Mock the greeting and request handlers
    async def fake_greeting(r, w, creds):
        pass

    async def fake_request(r, w):
        return "example.com", 80

    # Track what reply was sent
    sent_reply = None
    async def fake_send_reply(w, code):
        nonlocal sent_reply
        sent_reply = code

    with patch("socks_proxy.socks5._handle_greeting", fake_greeting):
        with patch("socks_proxy.socks5._handle_request", fake_request):
            with patch("socks_proxy.socks5._send_reply", fake_send_reply):
                await handle_socks5_client(reader, writer, tunnel)

    assert sent_reply == REPLY_HOST_UNREACHABLE
