import os
import sys
import threading
import time

import pytest

from netbridge_e2e.procs import IS_WINDOWS, LogWatch, Proc


def test_logwatch_finds_line_appended_later(tmp_path):
    log = tmp_path / "logs" / "app.log"
    log.parent.mkdir()
    log.write_text("Status changed: disconnected -> connecting\n")
    watch = LogWatch(tmp_path / "logs" / "*.log")

    def later():
        time.sleep(0.7)
        with log.open("a") as f:
            f.write("Status changed: connecting -> connected\n")

    threading.Thread(target=later).start()
    m = watch.wait_for(r"Status changed: \S+ -> connected", timeout=5)
    assert m and m.group(0).endswith("-> connected")


def test_logwatch_since_mark_ignores_older_lines(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("Status changed: connecting -> connected\n")
    watch = LogWatch(log)
    mark = watch.mark()
    assert watch.wait_for(r"-> connected", timeout=0.6, since=mark) is None
    with log.open("a") as f:
        f.write("Status changed: connecting -> connected\n")
    assert watch.wait_for(r"-> connected", timeout=2, since=mark)


def test_logwatch_stops_early_when_process_died(tmp_path):
    watch = LogWatch(tmp_path / "missing.log")
    start = time.monotonic()
    assert watch.wait_for("never", timeout=30, alive=lambda: False) is None
    assert time.monotonic() - start < 2


def test_proc_captures_output_and_stops(tmp_path):
    log = tmp_path / "p.log"
    p = Proc("sleeper", [sys.executable, "-c", "print('hi', flush=True); import time; time.sleep(60)"], log).start()
    assert LogWatch(log).wait_for("hi", timeout=10)
    assert p.alive()
    p.stop()
    assert not p.alive()


@pytest.mark.skipif(IS_WINDOWS, reason="process-group check is POSIX specific")
def test_proc_stop_kills_grandchildren(tmp_path):
    pidfile = tmp_path / "child.pid"
    code = (
        "import subprocess, sys, time;"
        "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']);"
        f"open(r'{pidfile}', 'w').write(str(c.pid)); time.sleep(60)"
    )
    p = Proc("parent", [sys.executable, "-c", code], tmp_path / "p.log").start()
    deadline = time.monotonic() + 10
    while not pidfile.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    child = int(pidfile.read_text())
    p.stop()
    deadline = time.monotonic() + 5
    while not _gone(child) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert _gone(child)


def _gone(pid):
    """Dead or a zombie waiting for its (re)parent to reap it."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    try:
        return open(f"/proc/{pid}/stat").read().split(")")[-1].split()[0] == "Z"
    except OSError:
        return True
