"""
Stream Handler

Manages individual TCP streams multiplexed over the WebSocket connection.
Each stream corresponds to one SOCKS5 CONNECT session.
"""

import asyncio
import time
from dataclasses import dataclass, field


# Maximum items in queue before applying backpressure
MAX_QUEUE_SIZE = 100
# Timeout for queue put operations (seconds) - kept short for responsiveness
QUEUE_PUT_TIMEOUT = 2.0


@dataclass
class StreamHandler:
    """Handles a single multiplexed TCP stream."""

    stream_id: str
    connect_future: asyncio.Future
    # Queue for data coming from the remote end (via WebSocket)
    # Bounded to prevent memory exhaustion with slow consumers
    data_queue: asyncio.Queue[bytes | None] = field(
        default_factory=lambda: asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
    )
    closed: bool = False
    # Event signaled when stream is closed - used to wake up readers
    _close_event: asyncio.Event = field(default_factory=asyncio.Event)
    # Track last activity for stall detection
    last_activity: float = field(default_factory=time.monotonic)
    # Track if stream is stalled (queue full, can't accept more data)
    stalled: bool = False
    # Track if semaphore slot has been released for this stream (prevents double-release)
    semaphore_released: bool = False

    async def receive_data(self, data: bytes) -> bool:
        """
        Queue data received from the remote end.

        Returns:
            True if data was queued, False if stream is stalled/closed
        """
        if self.closed:
            return False

        try:
            # Use put_nowait first to avoid blocking the receive loop
            self.data_queue.put_nowait(data)
            self.last_activity = time.monotonic()
            self.stalled = False
            return True
        except asyncio.QueueFull:
            # Queue is full - try with timeout
            try:
                await asyncio.wait_for(
                    self.data_queue.put(data),
                    timeout=QUEUE_PUT_TIMEOUT
                )
                self.last_activity = time.monotonic()
                self.stalled = False
                return True
            except asyncio.TimeoutError:
                # Consumer is too slow, mark as stalled
                self.stalled = True
                return False

    async def close(self) -> None:
        """Mark stream as closed and signal EOF to reader."""
        if not self.closed:
            self.closed = True
            # Signal close event to wake up any waiting readers
            self._close_event.set()
            # Try to queue EOF sentinel, but don't block
            try:
                self.data_queue.put_nowait(None)
            except asyncio.QueueFull:
                # Queue is full - reader will see closed flag via _close_event
                pass

    async def read(self) -> bytes | None:
        """Read next chunk of data from the stream. Returns None on EOF."""
        while True:
            # Check if closed AND queue is empty - EOF condition
            if self.closed and self.data_queue.empty():
                return None

            # Fast path: try non-blocking get first (avoids task creation overhead)
            try:
                data = self.data_queue.get_nowait()
                self.last_activity = time.monotonic()
                return data
            except asyncio.QueueEmpty:
                pass

            # Slow path: wait on both queue and close event
            get_task = asyncio.create_task(self.data_queue.get())
            close_task = asyncio.create_task(self._close_event.wait())

            try:
                done, pending = await asyncio.wait(
                    [get_task, close_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )

                # Cancel pending tasks
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

                # Check if we got data from the queue
                if get_task in done:
                    try:
                        data = get_task.result()
                        self.last_activity = time.monotonic()
                        return data
                    except asyncio.CancelledError:
                        pass

                # Close event was triggered - check if we should exit
                if self.closed and self.data_queue.empty():
                    return None
                # Otherwise loop to drain any remaining queue items

            except asyncio.CancelledError:
                # Clean up tasks on cancellation
                get_task.cancel()
                close_task.cancel()
                raise

    def is_idle(self, idle_timeout: float) -> bool:
        """Check if stream has been idle for too long."""
        return time.monotonic() - self.last_activity > idle_timeout
