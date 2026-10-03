"""Tests for tunnel reconnection, stream teardown, and pending connect handling."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
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

    # Size semaphore to 1 to make the test meaningful
    tm._stream_semaphore = asyncio.Semaphore(1)

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
async def test_send_failure_retrieves_future_exception():
    """When send_str fails after handler closed, future exception is retrieved."""
    import gc
    import warnings

    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")

    tm._connected.set()

    # Create a fake websocket whose send_str closes handlers then raises
    async def fake_send_str(msg):
        # Close all handlers while send is in progress
        handlers = list(tm.streams.values())
        for h in handlers:
            await h.close()
        # Then raise to simulate send failure
        raise ConnectionResetError("connection reset")

    fake_ws = AsyncMock()
    fake_ws.closed = False
    fake_ws.send_str = fake_send_str
    tm.ws = fake_ws

    # Catch warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        # Try to connect - should fail with ConnectionError
        with pytest.raises(ConnectionError, match="Failed to send connect request"):
            await tm.connect("10.0.0.1", 80, timeout=30)

        # Force garbage collection to trigger any pending warnings
        gc.collect()

        # Check no "Future exception was never retrieved" warning
        future_warnings = [
            warning for warning in w
            if "Future exception was never retrieved" in str(warning.message)
        ]
        assert len(future_warnings) == 0, \
            f"Unexpected future exception warning: {future_warnings}"


@pytest.mark.asyncio
async def test_socks_reply_is_host_unreachable_on_pending_close():
    """SOCKS5 handler returns 0x04 when connect raises ConnectionError."""
    from socks_proxy.socks5 import handle_socks5_client, REPLY_HOST_UNREACHABLE

    # Create fake reader/writer
    reader = AsyncMock()
    writer = MagicMock()
    writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 12345))
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    writer.close = MagicMock()

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


@pytest.mark.asyncio
async def test_receive_loop_end_closes_established_streams():
    """When receive_loop ends, all established streams are closed."""
    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")

    # Create two established streams
    loop = asyncio.get_running_loop()
    future1 = loop.create_future()
    future1.set_result({"success": True})
    handler1 = StreamHandler(stream_id="s1", connect_future=future1)

    future2 = loop.create_future()
    future2.set_result({"success": True})
    handler2 = StreamHandler(stream_id="s2", connect_future=future2)

    tm.streams = {"s1": handler1, "s2": handler2}

    # Create fake websocket that ends immediately
    fake_ws = AsyncMock()
    fake_ws.__aiter__ = lambda self: self
    fake_ws.__anext__ = AsyncMock(side_effect=StopAsyncIteration())
    tm.ws = fake_ws

    # Run receive_loop
    await tm._receive_loop()

    # Both handlers must be closed
    assert handler1.closed is True
    assert handler2.closed is True

    # Both must return None when read
    assert await handler1.read() is None
    assert await handler2.read() is None


@pytest.mark.asyncio
async def test_reconnect_after_failed_handshakes():
    """Reconnect retries with exponential backoff after handshake failures."""
    import socks_proxy.tunnel as tunnel_module
    from shared_auth.session import (
        RECONNECT_DELAY,
        RECONNECT_BACKOFF_FACTOR,
        RECONNECT_DELAY_MAX,
    )

    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")

    # Track delays and connection attempts
    recorded_delays = []
    attempt_count = [0]
    orig_sleep = tunnel_module.asyncio.sleep

    async def fake_sleep(duration):
        recorded_delays.append(duration)
        # Yield control but don't actually sleep the full duration
        await orig_sleep(0.001)

    # Initial websocket that ends immediately (triggers reconnection)
    initial_ws = AsyncMock()
    initial_ws.closed = False
    initial_ws.__aiter__ = lambda self: self
    initial_ws.__anext__ = AsyncMock(side_effect=StopAsyncIteration())

    # Patch ws_connect to fail 3 times then succeed
    async def fake_ws_connect(*args, **kwargs):
        attempt_count[0] += 1
        if attempt_count[0] <= 3:
            raise aiohttp.ClientError("handshake failed")
        # Succeed on 4th attempt
        ws = AsyncMock()
        ws.closed = False
        ws.__aiter__ = lambda self: self
        ws.__anext__ = AsyncMock(side_effect=StopAsyncIteration())
        return ws

    # Set up initial connected state with ws that will end
    tm._connected.set()
    tm.ws = initial_ws
    tm.session = AsyncMock()
    tm.session.ws_connect = fake_ws_connect

    # Patch sleep at module level
    with patch.object(tunnel_module.asyncio, "sleep", fake_sleep):
        # Run connection_loop
        loop_task = asyncio.create_task(tm._connection_loop())

        # Wait for 4 connection attempts
        for _ in range(100):
            if attempt_count[0] >= 4:
                # Give it a moment to settle
                await orig_sleep(0.01)
                break
            await orig_sleep(0.01)

        # Stop the loop
        tm._stopping = True
        loop_task.cancel()
        try:
            await loop_task
        except asyncio.CancelledError:
            pass

    # Filter for reconnect delays - shortest is RECONNECT_DELAY with jitter
    min_reconnect = RECONNECT_DELAY * 0.7  # Allow for some margin
    reconnect_delays = [d for d in recorded_delays if d >= min_reconnect]

    # Should have at least 3 reconnect delays (attempts 1, 2, 3 failed, 4th succeeded)
    assert attempt_count[0] >= 4, f"Expected at least 4 connection attempts, got {attempt_count[0]}"
    assert len(reconnect_delays) >= 3, \
        f"Expected at least 3 reconnect delays, got {len(reconnect_delays)}: {reconnect_delays}"

    # Take first 3 delays for verification
    reconnect_delays = reconnect_delays[:3]

    # Derive expected delays from constants
    # Attempt 1 fails: delay = RECONNECT_DELAY + jitter (0 to 30%)
    # Attempt 2 fails: delay = RECONNECT_DELAY * RECONNECT_BACKOFF_FACTOR + jitter
    # Attempt 3 fails: delay = min(prev * RECONNECT_BACKOFF_FACTOR, RECONNECT_DELAY_MAX) + jitter
    base_delays = [RECONNECT_DELAY]
    for i in range(1, 3):
        next_delay = base_delays[-1] * RECONNECT_BACKOFF_FACTOR
        base_delays.append(min(next_delay, RECONNECT_DELAY_MAX))

    # Check delays are within expected range (jitter up to 30%)
    for i, delay in enumerate(reconnect_delays):
        base = base_delays[i]
        max_delay = base * 1.3
        assert base <= delay <= max_delay, \
            f"Delay {i}: {delay} not in range [{base}, {max_delay}]"
