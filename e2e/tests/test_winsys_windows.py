"""Windows-only tests for winsys module."""
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only tests")


def test_parent_pid_returns_parent():
    """Verify parent_pid() returns the parent process ID."""
    from netbridge_e2e import winsys

    ppid = winsys.parent_pid(os.getpid())
    assert ppid == os.getppid(), f"parent_pid({os.getpid()}) returned {ppid}, expected {os.getppid()}"


def test_click_messagebox_yes_returns_false_for_nonexistent_window():
    """Verify click_messagebox_yes() returns False when no matching window exists."""
    from netbridge_e2e import winsys

    result = winsys.click_messagebox_yes("no-such-title-e2e-test-xyz", timeout=0.5, accept_pid=lambda pid: True)
    assert result is False, "Expected False when no matching window exists"
