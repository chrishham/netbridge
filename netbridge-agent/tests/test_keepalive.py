import asyncio
from unittest.mock import MagicMock

import pytest

from netbridge_agent import keepalive


def test_noops_off_windows(monkeypatch):
    monkeypatch.setattr(keepalive.sys, "platform", "linux")
    keepalive._set_execution_state(True)
    assert keepalive._jiggle_mouse() is False


def _fake_windll(monkeypatch, sent=2):
    windll = MagicMock()
    windll.user32.SendInput.return_value = sent
    monkeypatch.setattr(keepalive.sys, "platform", "win32")
    monkeypatch.setattr(keepalive.ctypes, "windll", windll, raising=False)
    return windll


def test_execution_state_flags_and_send_input(monkeypatch):
    windll = _fake_windll(monkeypatch)
    keepalive._set_execution_state(True)
    windll.kernel32.SetThreadExecutionState.assert_called_with(
        keepalive.ES_CONTINUOUS | keepalive.ES_SYSTEM_REQUIRED | keepalive.ES_DISPLAY_REQUIRED)
    keepalive._set_execution_state(False)
    windll.kernel32.SetThreadExecutionState.assert_called_with(keepalive.ES_CONTINUOUS)
    assert keepalive._jiggle_mouse() is True
    assert windll.user32.SendInput.call_args.args[0] == 2
    windll.user32.SendInput.return_value = 1
    assert keepalive._jiggle_mouse() is False


async def test_loop_jiggles_warns_and_clears_state(monkeypatch, caplog):
    windll = _fake_windll(monkeypatch)
    monkeypatch.setattr(keepalive, "KEEPALIVE_INTERVAL", 0.01)
    stop = asyncio.Event()
    task = asyncio.create_task(keepalive.session_keepalive_loop(stop))
    await asyncio.sleep(0.05)
    windll.user32.SendInput.return_value = 0
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, 1)
    assert windll.user32.SendInput.called and "SendInput failed" in caplog.text
    assert windll.kernel32.SetThreadExecutionState.call_args.args[0] == keepalive.ES_CONTINUOUS


async def test_loop_clears_state_when_cancelled(monkeypatch):
    windll = _fake_windll(monkeypatch)
    task = asyncio.create_task(keepalive.session_keepalive_loop(asyncio.Event()))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert windll.kernel32.SetThreadExecutionState.call_args.args[0] == keepalive.ES_CONTINUOUS
