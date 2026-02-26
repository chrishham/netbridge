"""Tests for socks_proxy.stream — StreamHandler dataclass and queue management."""

import asyncio
import time
from unittest.mock import patch

import pytest

from socks_proxy.stream import QUEUE_PUT_TIMEOUT, StreamHandler


def _make_handler(**kwargs) -> StreamHandler:
    """Create a StreamHandler with a dummy future."""
    loop = asyncio.get_event_loop()
    future = loop.create_future()
    return StreamHandler(stream_id="test-stream", connect_future=future, **kwargs)


# ---------------------------------------------------------------------------
# receive_data
# ---------------------------------------------------------------------------
class TestReceiveData:
    """Tests for StreamHandler.receive_data()."""

    @pytest.mark.asyncio
    async def test_queue_data(self):
        """Data is queued and activity timestamp updated."""
        handler = _make_handler()
        before = handler.last_activity
        result = await handler.receive_data(b"hello")
        assert result is True
        assert handler.data_queue.qsize() == 1
        assert handler.last_activity >= before

    @pytest.mark.asyncio
    async def test_closed_returns_false(self):
        """Returns False when stream is already closed."""
        handler = _make_handler()
        handler.closed = True
        result = await handler.receive_data(b"data")
        assert result is False

    @pytest.mark.asyncio
    async def test_queue_full_with_timeout_recovery(self):
        """When queue is full but space opens within timeout, data is accepted."""
        handler = _make_handler()
        # Fill the queue
        for i in range(handler.data_queue.maxsize):
            handler.data_queue.put_nowait(f"item{i}".encode())

        # Schedule a consumer to make space
        async def consume():
            await asyncio.sleep(0.05)
            handler.data_queue.get_nowait()

        task = asyncio.create_task(consume())
        result = await handler.receive_data(b"new_data")
        assert result is True
        assert handler.stalled is False
        await task

    @pytest.mark.asyncio
    async def test_queue_full_stalled(self):
        """When queue is full and stays full, stream becomes stalled."""
        handler = _make_handler()
        # Fill the queue
        for i in range(handler.data_queue.maxsize):
            handler.data_queue.put_nowait(f"item{i}".encode())

        # Patch QUEUE_PUT_TIMEOUT to speed up the test
        with patch("socks_proxy.stream.QUEUE_PUT_TIMEOUT", 0.05):
            result = await handler.receive_data(b"overflow")

        assert result is False
        assert handler.stalled is True


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------
class TestRead:
    """Tests for StreamHandler.read()."""

    @pytest.mark.asyncio
    async def test_read_queued_data(self):
        """Reads data that was previously queued."""
        handler = _make_handler()
        handler.data_queue.put_nowait(b"chunk1")
        data = await handler.read()
        assert data == b"chunk1"

    @pytest.mark.asyncio
    async def test_eof_on_closed_empty(self):
        """Returns None when stream is closed and queue is empty."""
        handler = _make_handler()
        handler.closed = True
        handler._close_event.set()
        data = await handler.read()
        assert data is None

    @pytest.mark.asyncio
    async def test_blocking_wait_for_data(self):
        """Blocks until data is available."""
        handler = _make_handler()

        async def produce():
            await asyncio.sleep(0.05)
            handler.data_queue.put_nowait(b"delayed")

        task = asyncio.create_task(produce())
        data = await handler.read()
        assert data == b"delayed"
        await task

    @pytest.mark.asyncio
    async def test_close_event_wakes_reader(self):
        """Close event wakes a blocked reader, returning None (EOF)."""
        handler = _make_handler()

        async def close_later():
            await asyncio.sleep(0.05)
            await handler.close()

        task = asyncio.create_task(close_later())
        data = await handler.read()
        assert data is None
        await task


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------
class TestClose:
    """Tests for StreamHandler.close()."""

    @pytest.mark.asyncio
    async def test_sets_closed_flag(self):
        """close() sets the closed flag."""
        handler = _make_handler()
        await handler.close()
        assert handler.closed is True

    @pytest.mark.asyncio
    async def test_sets_close_event(self):
        """close() sets the close event."""
        handler = _make_handler()
        await handler.close()
        assert handler._close_event.is_set()

    @pytest.mark.asyncio
    async def test_queues_none_sentinel(self):
        """close() queues a None sentinel."""
        handler = _make_handler()
        await handler.close()
        item = handler.data_queue.get_nowait()
        assert item is None

    @pytest.mark.asyncio
    async def test_idempotent(self):
        """Calling close() multiple times is safe."""
        handler = _make_handler()
        await handler.close()
        await handler.close()
        assert handler.closed is True
        # Should only have one None sentinel (second close is no-op)
        assert handler.data_queue.qsize() == 1


# ---------------------------------------------------------------------------
# is_idle
# ---------------------------------------------------------------------------
class TestIsIdle:
    """Tests for StreamHandler.is_idle()."""

    def test_not_idle(self):
        """Freshly created stream is not idle."""
        loop = asyncio.new_event_loop()
        future = loop.create_future()
        handler = StreamHandler(stream_id="s1", connect_future=future)
        assert handler.is_idle(60.0) is False
        loop.close()

    def test_idle_after_timeout(self):
        """Stream is idle when last_activity is older than timeout."""
        loop = asyncio.new_event_loop()
        future = loop.create_future()
        handler = StreamHandler(stream_id="s1", connect_future=future)
        with patch("socks_proxy.stream.time.monotonic", return_value=handler.last_activity + 120):
            assert handler.is_idle(60.0) is True
        loop.close()
