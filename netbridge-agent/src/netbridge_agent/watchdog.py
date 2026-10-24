"""Event-loop watchdog: logs a stack dump when the asyncio loop stops answering."""

import asyncio
import logging
import sys
import threading
import time
import traceback

logger = logging.getLogger(__name__)

_POLL = 0.1  # granularity for noticing stop() / a closed loop while waiting


class LoopWatchdog:
    """Daemon thread that pings the event loop and reports when it does not answer in time."""

    def __init__(self, loop: asyncio.AbstractEventLoop, loop_thread_id: int,
                 interval: float = 30.0, stall_threshold: float = 60.0) -> None:
        self._loop = loop
        self._loop_thread_id = loop_thread_id
        self._interval = interval
        self._stall_threshold = stall_threshold
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="netbridge-loop-watchdog", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive() and self._thread is not threading.current_thread():
            self._thread.join(timeout=self._interval)

    def _wait(self, event: threading.Event, timeout: float) -> bool | None:
        """Wait for `event`; True if set, False on timeout, None if stopped or the loop closed."""
        deadline = time.monotonic() + timeout
        while True:
            if event.is_set():
                return True
            if self._stop_event.is_set() or self._loop.is_closed():
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            event.wait(min(_POLL, remaining))

    def _stack(self) -> str:
        frame = sys._current_frames().get(self._loop_thread_id)
        return "".join(traceback.format_stack(frame)) if frame is not None else "(no stack available)"

    def _run(self) -> None:
        while not self._stop_event.wait(self._interval):
            event = threading.Event()
            started = time.monotonic()
            try:
                self._loop.call_soon_threadsafe(event.set)
            except RuntimeError:
                return  # loop closed
            result = self._wait(event, self._stall_threshold)
            if result is None:
                return
            if result:
                continue
            while result is False:
                stalled = int(time.monotonic() - started)
                logger.warning(f"Event loop unresponsive for {stalled}s\n{self._stack()}")
                result = self._wait(event, self._interval)
            if result is None:
                return
            logger.info(f"Event loop responsive again after {int(time.monotonic() - started)}s")
