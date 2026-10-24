import asyncio
import logging
import threading
import time

from netbridge_agent.watchdog import LoopWatchdog


def _loop_in_thread():
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    ident = []

    def run():
        asyncio.set_event_loop(loop)
        ident.append(threading.get_ident())
        ready.set()
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    ready.wait(1)
    return loop, t, ident[0]


def _stop(loop, t):
    loop.call_soon_threadsafe(loop.stop)
    t.join(2)
    loop.close()


def test_healthy_loop_logs_nothing(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent.watchdog")
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident, interval=0.05, stall_threshold=0.2)
    wd.start()
    time.sleep(0.4)
    wd.stop()
    _stop(loop, t)
    assert caplog.records == []


def test_stalled_loop_logs_warning_with_stack_and_recovery(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent.watchdog")
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident, interval=0.05, stall_threshold=0.1)
    wd.start()
    loop.call_soon_threadsafe(time.sleep, 0.6)  # block the loop thread
    time.sleep(1.0)
    wd.stop()
    _stop(loop, t)
    assert _wait_for(lambda: any(r.levelno == logging.WARNING for r in caplog.records))
    assert _wait_for(lambda: any(
        r.getMessage().startswith("Event loop responsive again after ") for r in caplog.records))
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings and warnings[0].getMessage().startswith("Event loop unresponsive for ")
    assert 'File "' in warnings[0].getMessage()  # stack dump attached
    assert any(r.getMessage().startswith("Event loop responsive again after ") for r in caplog.records)


def test_watchdog_exits_quietly_when_loop_closed(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent.watchdog")
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident, interval=0.05, stall_threshold=0.1)
    wd.start()
    _stop(loop, t)  # loop closed while watchdog runs
    time.sleep(0.3)
    assert not wd._thread.is_alive()
    assert caplog.records == []


def test_thread_is_daemon():
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident)
    wd.start()
    assert wd._thread.daemon and wd._thread.name == "netbridge-loop-watchdog"
    wd.stop()
    _stop(loop, t)


def _wait_for(pred, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def test_stall_report_is_written_to_report_file(tmp_path):
    report = tmp_path / "watchdog.log"
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident, interval=0.05, stall_threshold=0.1, report_path=report)
    wd.start()
    loop.call_soon_threadsafe(time.sleep, 0.6)
    time.sleep(1.0)
    wd.stop()
    _stop(loop, t)
    text = report.read_text()
    assert "Event loop unresponsive for " in text
    assert 'File "' in text
    assert "Event loop responsive again after " in text


def test_watchdog_reports_even_when_logging_handler_is_wedged(tmp_path):
    release = threading.Event()

    class WedgedHandler(logging.Handler):
        def emit(self, record):
            release.wait()  # blocks until the test's finally unblocks it

    wlogger = logging.getLogger("netbridge_agent.watchdog")
    handler = WedgedHandler()
    wlogger.addHandler(handler)
    old_level = wlogger.level
    wlogger.setLevel(logging.INFO)
    report = tmp_path / "watchdog.log"
    loop, t, ident = _loop_in_thread()
    try:
        wd = LoopWatchdog(loop, ident, interval=0.05, stall_threshold=0.1, report_path=report)
        wd.start()
        loop.call_soon_threadsafe(time.sleep, 0.6)
        time.sleep(1.0)
        started = time.monotonic()
        wd.stop()
        assert time.monotonic() - started < 1.0
        assert not wd._thread.is_alive()
        assert "Event loop unresponsive" in report.read_text()
    finally:
        release.set()  # unblock helper log threads so logging.shutdown() cannot hang on the lock
        wlogger.removeHandler(handler)
        wlogger.setLevel(old_level)
        _stop(loop, t)
        for th in threading.enumerate():
            if th.name == "netbridge-loop-watchdog-log":
                th.join(timeout=2.0)
        handler.close()


def test_report_file_errors_are_swallowed(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent.watchdog")
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident, interval=0.05, stall_threshold=0.1,
                      report_path=tmp_path / "missing" / "watchdog.log")
    wd.start()
    loop.call_soon_threadsafe(time.sleep, 0.6)
    time.sleep(1.0)
    wd.stop()
    _stop(loop, t)
    assert _wait_for(lambda: any(
        r.getMessage().startswith("Event loop unresponsive for ") for r in caplog.records))
