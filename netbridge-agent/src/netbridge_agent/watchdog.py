"""Event-loop watchdog: logs a stack dump when the asyncio loop stops answering."""

import asyncio
import logging
import os
import sys
import threading
import time
import traceback
from pathlib import Path

logger = logging.getLogger(__name__)

_MAX_REPORT_BYTES = 5 * 1024 * 1024
_POLL = 0.1  # granularity for noticing stop() / a closed loop while waiting


class LoopWatchdog:
    """Daemon thread that pings the event loop and reports when it does not answer in time.

    Reports are mirrored to logging from at most one helper thread at a time, so a wedged
    handler can block at most one helper; reports arriving meanwhile are counted and noted
    in the next mirrored report (the file write is never skipped).
    """

    def __init__(self, loop: asyncio.AbstractEventLoop, loop_thread_id: int,
                 interval: float = 30.0, stall_threshold: float = 60.0,
                 *, report_path: Path | None = None) -> None:
        self._loop = loop
        self._loop_thread_id = loop_thread_id
        self._interval = interval
        self._stall_threshold = stall_threshold
        self._report_path = report_path
        self._stop_event = threading.Event()
        self._mirror_thread: threading.Thread | None = None
        self._mirror_skipped = 0
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

    def _report(self, text: str, level: int = logging.WARNING) -> None:
        """Write the report with plain OS calls, then mirror it to logging from a helper thread.

        The watchdog must not depend on a logging handler lock: if the loop thread is wedged
        inside a log write, the watchdog would block on the same lock and report nothing.
        """
        if self._report_path is not None:
            try:
                path = str(self._report_path)
                try:
                    if os.path.getsize(path) > _MAX_REPORT_BYTES:
                        os.replace(path, path + ".1")
                except OSError:
                    pass
                data = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {text}\n".encode("utf-8", "replace")
                fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
                try:
                    os.write(fd, data)
                finally:
                    os.close(fd)
            except OSError:
                pass
        if self._mirror_thread is not None and self._mirror_thread.is_alive():
            self._mirror_skipped += 1
            return
        if self._mirror_skipped:
            text = (f"[{self._mirror_skipped} earlier watchdog reports were not mirrored "
                    f"to this log; see watchdog.log] {text}")
        try:
            thread = threading.Thread(
                target=logger.log, args=(level, text), daemon=True,
                name="netbridge-loop-watchdog-log",
            )
            thread.start()
        except RuntimeError:
            return
        self._mirror_thread = thread
        self._mirror_skipped = 0

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
                self._report(f"Event loop unresponsive for {stalled}s\n{self._stack()}")
                result = self._wait(event, self._interval)
            if result is None:
                return
            self._report(f"Event loop responsive again after {int(time.monotonic() - started)}s", logging.INFO)
