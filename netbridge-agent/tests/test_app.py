import asyncio
import logging
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from netbridge_agent import app as app_mod
from netbridge_agent.app import NetBridgeApp
from netbridge_agent.tray import Status


@pytest.fixture
def nb(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    before = list(logging.getLogger().handlers)
    a = NetBridgeApp(console=True)
    yield a
    for h in list(logging.getLogger().handlers):
        if h not in before:
            logging.getLogger().removeHandler(h)
            h.close()


@pytest.fixture
def fake_agent(monkeypatch):
    """run_agent that records its stop event and blocks until it is set."""
    seen = {}

    async def run_agent(relay_url, stop_event, **kw):
        seen["stop"] = stop_event
        seen["started"].set()
        await stop_event.wait()

    seen["started"] = asyncio.Event()
    monkeypatch.setattr("netbridge_agent.agent.run_agent", run_agent)
    return seen


async def _boot(nb, fake_agent, monkeypatch):
    monkeypatch.setattr(nb, "_check_for_update", AsyncMock())
    nb.config.auto_connect = True
    main = asyncio.create_task(nb._async_main())
    await asyncio.wait_for(fake_agent["started"].wait(), 2)
    assert nb._stop_event is fake_agent["stop"]  # the replaced, per-connection event
    return main


# --- shutdown ---

async def test_exit_after_agent_start_ends_async_main(nb, fake_agent, monkeypatch):
    main = await _boot(nb, fake_agent, monkeypatch)
    nb.request_exit()
    await asyncio.wait_for(main, 2)
    assert fake_agent["stop"].is_set()


async def test_restart_ends_async_main(nb, fake_agent, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("netbridge_agent.installer.get_exe_path", lambda: "C:/x/netbridge.exe", raising=False)
    popen = MagicMock()
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(subprocess, "DETACHED_PROCESS", 8, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    main = await _boot(nb, fake_agent, monkeypatch)
    nb.request_restart()
    await asyncio.wait_for(main, 2)
    assert popen.call_args.kwargs["creationflags"] == 8 | 0x08000000


async def test_restart_launch_failure_keeps_running(nb, fake_agent, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("netbridge_agent.installer.get_exe_path", lambda: "C:/x/netbridge.exe", raising=False)
    monkeypatch.setattr(subprocess, "Popen", MagicMock(side_effect=OSError("nope")))
    main = await _boot(nb, fake_agent, monkeypatch)
    nb.request_restart()
    await asyncio.sleep(0.05)
    assert not main.done()
    assert not nb._pending_exit.is_set()
    nb.request_exit()
    await asyncio.wait_for(main, 2)


def test_request_restart_is_noop_off_windows(nb, monkeypatch):
    popen = MagicMock()
    monkeypatch.setattr(subprocess, "Popen", popen)
    nb.request_restart()
    popen.assert_not_called()
    assert not nb._pending_exit.is_set()


def test_detached_creationflags_safe_without_windows_constants(monkeypatch):
    monkeypatch.delattr(subprocess, "DETACHED_PROCESS", raising=False)
    monkeypatch.delattr(subprocess, "CREATE_NO_WINDOW", raising=False)
    assert app_mod._detached_creationflags() == 0


async def test_install_ends_async_main(nb, fake_agent, monkeypatch):
    monkeypatch.setattr("netbridge_agent.installer.Installer.install_fresh", MagicMock(return_value=False))
    main = await _boot(nb, fake_agent, monkeypatch)
    nb.request_install()  # non-win32: no prompt, install_fresh patched
    await asyncio.wait_for(main, 2)


async def test_install_success_stops_tray_and_exits_process(nb, monkeypatch):
    monkeypatch.setattr("netbridge_agent.installer.Installer.install_fresh", MagicMock(return_value=True))
    exit_ = MagicMock()
    monkeypatch.setattr(app_mod.os, "_exit", exit_)
    nb.tray = MagicMock()
    nb.request_install()
    nb.tray.stop.assert_called_once()
    exit_.assert_called_once_with(0)


async def test_exit_before_the_event_exists_is_not_lost(nb, fake_agent, monkeypatch):
    nb.request_exit()  # _async_loop is None: only _pending_exit is set
    monkeypatch.setattr(nb, "_check_for_update", AsyncMock())
    await asyncio.wait_for(nb._async_main(), 2)  # returns instead of waiting forever


async def test_exit_requested_from_another_thread_mid_startup(nb, fake_agent, monkeypatch):
    from netbridge_agent.intercept import InterceptServer
    real_start = InterceptServer.start

    async def start_then_exit(self):
        await real_start(self)
        threading.Thread(target=nb.request_exit).start()  # exit arrives during start-up
        await asyncio.sleep(0.05)

    monkeypatch.setattr(InterceptServer, "start", start_then_exit)
    monkeypatch.setattr(nb, "_check_for_update", AsyncMock())
    await asyncio.wait_for(nb._async_main(), 2)


async def test_disconnect_does_not_stop_the_app(nb, fake_agent, monkeypatch):
    main = await _boot(nb, fake_agent, monkeypatch)
    nb.request_disconnect()
    await asyncio.wait_for(fake_agent["stop"].wait(), 2)
    await asyncio.sleep(0.05)
    assert not main.done()
    nb.request_exit()
    await asyncio.wait_for(main, 2)


async def test_signal_exit_on_closed_loop_does_not_raise(nb):
    nb._async_loop = MagicMock()
    nb._async_loop.call_soon_threadsafe.side_effect = RuntimeError("closed")
    nb._shutdown_event = asyncio.Event()
    nb._signal_exit()
    assert nb._pending_exit.is_set()


async def test_async_main_order_and_shutdown(nb, fake_agent, monkeypatch):
    from netbridge_agent.intercept import InterceptServer
    order = []
    real_start, real_stop, real_reg = InterceptServer.start, InterceptServer.stop, InterceptServer.register_app

    async def start(self):
        order.append("start")
        await real_start(self)

    async def stop(self):
        order.append("stop")
        await real_stop(self)

    async def register(self, host, app):
        order.append(f"register:{host}")
        await real_reg(self, host, app)

    monkeypatch.setattr(InterceptServer, "start", start)
    monkeypatch.setattr(InterceptServer, "stop", stop)
    monkeypatch.setattr(InterceptServer, "register_app", register)
    main = await _boot(nb, fake_agent, monkeypatch)
    assert order[:2] == ["start", "register:netbridge-exec"]
    agent_task = nb._agent_task
    nb.request_exit()
    await asyncio.wait_for(main, 2)
    assert agent_task.done()
    assert order[-1] == "stop"


# --- status and callbacks ---

def test_set_status_notifications(nb):
    nb.tray = MagicMock()
    nb.set_status(Status.CONNECTED)
    assert nb.tray.show_notification.call_args.args[0] == "Connected"
    nb.set_status(Status.DISCONNECTED)
    assert nb.tray.show_notification.call_args.args[0] == "Disconnected"
    nb.set_status(Status.AUTH_REQUIRED)
    assert nb.tray.show_notification.call_args.args[0] == "Login Required"
    assert nb.tray.show_notification.call_count == 3


def test_set_status_quiet_cases(nb):
    nb.tray = MagicMock()
    nb.set_status(Status.CONNECTED, notify=False)
    nb.set_status(Status.CONNECTED)  # unchanged
    nb.set_status(Status.CONNECTING)  # not a notifying transition
    nb.tray.show_notification.assert_not_called()
    assert nb.status is Status.CONNECTING


def test_set_status_from_connecting_to_disconnected_is_silent(nb):
    nb.tray = MagicMock()
    nb.set_status(Status.CONNECTING)
    nb.set_status(Status.DISCONNECTED)
    nb.tray.show_notification.assert_not_called()


def test_set_session_info_forwards_to_tray(nb):
    nb.set_session_info("x")  # no tray: no-op
    nb.tray = MagicMock()
    nb.set_session_info("sess")
    nb.tray.set_session_info.assert_called_once_with("sess")


@pytest.mark.parametrize("connected,auth,task,expected", [
    (False, True, None, Status.AUTH_REQUIRED),
    (True, False, None, Status.CONNECTED),
    (True, True, None, Status.AUTH_REQUIRED),
    (False, False, None, Status.DISCONNECTED),
    (False, False, object(), Status.CONNECTING),
])
def test_on_agent_status_mapping(nb, connected, auth, task, expected):
    nb._agent_task = task
    nb._on_agent_status(connected, auth_required=auth)
    assert nb.status is expected


def test_on_proxy_auth_rejected_notifies(nb):
    nb._on_proxy_auth_rejected()  # no tray: no-op
    nb.tray = MagicMock()
    nb._on_proxy_auth_rejected()
    title, body = nb.tray.show_notification.call_args.args
    assert title == "Proxy Authentication Failed"
    assert "Set Proxy Credentials" in body


# --- pending requests and agent task ---

async def test_connect_creates_one_task_only(nb, fake_agent):
    nb._pending_connect.set()
    nb._check_pending_requests()
    first = nb._agent_task
    await asyncio.wait_for(fake_agent["started"].wait(), 2)
    nb._pending_connect.set()
    nb._check_pending_requests()
    assert nb._agent_task is first
    assert not nb._pending_connect.is_set()
    nb._stop_event.set()
    await asyncio.wait_for(first, 2)


async def test_disconnect_sets_only_the_per_connection_event(nb, fake_agent):
    nb._shutdown_event = asyncio.Event()
    nb._pending_connect.set()
    nb._check_pending_requests()
    await asyncio.wait_for(fake_agent["started"].wait(), 2)
    nb._pending_disconnect.set()
    nb._check_pending_requests()
    assert fake_agent["stop"].is_set()
    assert not nb._shutdown_event.is_set()
    await asyncio.wait_for(nb._agent_task, 2)


async def test_disconnect_without_agent_is_noop(nb):
    nb._stop_event = asyncio.Event()
    nb._pending_disconnect.set()
    nb._check_pending_requests()
    assert not nb._stop_event.is_set()
    assert not nb._pending_disconnect.is_set()


async def test_run_agent_exception_is_logged_and_ends_disconnected(nb, monkeypatch, caplog):
    async def boom(**kw):
        raise RuntimeError("kaput")

    monkeypatch.setattr("netbridge_agent.agent.run_agent", boom)
    seen = []
    real = nb.set_status
    monkeypatch.setattr(nb, "set_status", lambda s, notify=True: (seen.append(s), real(s, notify))[1])
    with caplog.at_level(logging.ERROR):
        await nb._run_agent()
    assert seen == [Status.CONNECTING, Status.DISCONNECTED]
    assert "Agent error: kaput" in caplog.text


@pytest.mark.asyncio
async def test_request_connect_and_disconnect_schedule_check(nb):
    nb._async_loop = asyncio.get_running_loop()
    nb._check_pending_requests = MagicMock()
    nb.request_connect()
    nb.request_disconnect()
    await asyncio.sleep(0)
    assert nb._check_pending_requests.call_count == 2


def test_request_connect_without_loop_only_sets_flag(nb):
    nb.request_connect()
    nb.request_disconnect()
    assert nb._pending_connect.is_set() and nb._pending_disconnect.is_set()


# --- login ---

def test_request_login_non_windows(nb, monkeypatch):
    popen = MagicMock()
    monkeypatch.setattr(subprocess, "Popen", popen)
    nb.request_login()
    assert popen.call_args.args[0] == ["gnome-terminal", "--", "az", "login"]


def test_request_login_windows(nb, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "CREATE_NEW_CONSOLE", 16, raising=False)
    popen = MagicMock()
    monkeypatch.setattr(subprocess, "Popen", popen)
    nb.request_login()
    assert popen.call_args.args[0][0] == "powershell"
    assert popen.call_args.kwargs["creationflags"] == 16


def test_request_login_failure_notifies_tray(nb, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", MagicMock(side_effect=OSError("no term")))
    nb.tray = MagicMock()
    nb.request_login()
    assert nb.tray.show_notification.call_args.args[0] == "Error"
    assert "no term" in nb.tray.show_notification.call_args.args[1]


# --- keep-alive ---

async def test_keepalive_start_stop_toggle(nb, monkeypatch):
    started = asyncio.Event()

    async def loop(stop_event):
        started.set()
        await stop_event.wait()

    monkeypatch.setattr("netbridge_agent.keepalive.session_keepalive_loop", loop)
    monkeypatch.setattr(nb.config, "save", MagicMock())
    nb._start_keepalive()  # no stop event yet: nothing starts
    assert nb._keepalive_task is None
    nb._stop_event = asyncio.Event()
    nb._start_keepalive()
    task = nb._keepalive_task
    await asyncio.wait_for(started.wait(), 2)
    nb._start_keepalive()  # already running
    assert nb._keepalive_task is task
    nb._stop_keepalive()
    await asyncio.wait_for(task, 2)
    assert nb._keepalive_task is None

    nb._async_loop = asyncio.get_running_loop()
    nb.tray = MagicMock()
    nb.config.keep_session_alive = False
    nb.request_toggle_keepalive()
    assert nb.config.keep_session_alive is True
    nb.tray.update_menu.assert_called_once()
    await asyncio.sleep(0.05)
    assert nb._keepalive_task is not None
    nb.request_toggle_keepalive()
    assert nb.config.keep_session_alive is False
    await asyncio.sleep(0.05)
    assert nb._keepalive_stop.is_set()


# --- remote exec ---

async def test_remote_exec_toggle_and_auto_disable(nb, monkeypatch):
    monkeypatch.setattr(app_mod, "REMOTE_EXEC_TIMEOUT", 0.05)
    nb.tray = MagicMock()
    nb.request_toggle_remote_exec()  # no loop yet: ignored
    assert nb._remote_exec_enabled is False

    nb._async_loop = asyncio.get_running_loop()
    nb._exec_app = {}
    nb.request_toggle_remote_exec()
    assert nb._remote_exec_enabled is True
    assert nb.tray.show_notification.call_args.args[0] == "Remote Exec ENABLED"
    await asyncio.sleep(0.01)
    assert nb._exec_app[app_mod.REMOTE_EXEC_ENABLED] is True

    await asyncio.sleep(0.15)  # timer fires
    assert nb._remote_exec_enabled is False
    assert nb._exec_app[app_mod.REMOTE_EXEC_ENABLED] is False
    nb.tray.set_remote_exec.assert_called_with(False)
    assert nb.tray.show_notification.call_args.args[0] == "Remote Exec Disabled"


async def test_remote_exec_manual_disable(nb):
    nb.tray = MagicMock()
    nb._async_loop = asyncio.get_running_loop()
    nb._exec_app = {}
    nb.request_toggle_remote_exec()
    await asyncio.sleep(0.01)
    assert nb._remote_exec_timer is not None
    nb.request_toggle_remote_exec()
    await asyncio.sleep(0.01)
    assert nb._exec_app[app_mod.REMOTE_EXEC_ENABLED] is False
    assert nb._remote_exec_timer is None
    assert nb.tray.show_notification.call_args.args[0] == "Remote Exec Disabled"


async def test_remote_exec_enable_before_exec_app_ready_reverts(nb):
    nb.tray = MagicMock()
    nb._async_loop = asyncio.get_running_loop()
    nb.request_toggle_remote_exec()
    await asyncio.sleep(0.01)
    assert nb._remote_exec_enabled is False
    nb.tray.set_remote_exec.assert_called_with(False)


async def test_auto_disable_when_already_disabled_is_noop(nb):
    nb.tray = MagicMock()
    await nb._remote_exec_auto_disable()
    nb.tray.show_notification.assert_not_called()


# --- plugins ---

def _m(name, host):
    return SimpleNamespace(name=name, hostname=host)


@pytest.fixture
def plug(nb, monkeypatch):
    nb._intercept_server = SimpleNamespace(register_app=AsyncMock(), unregister_app=AsyncMock())
    state = {"manifests": [], "bad": set()}
    monkeypatch.setattr("netbridge_agent.plugin_loader.discover_plugins", lambda d: list(state["manifests"]))

    def load(m):
        if m.name in state["bad"]:
            raise ValueError("bad plugin")
        return f"app-{m.name}"

    monkeypatch.setattr("netbridge_agent.plugin_loader.load_plugin_app", load)
    return nb, state


async def test_plugins_added_reloaded_removed(plug):
    nb, st = plug
    st["manifests"] = [_m("a", "a.host"), _m("b", "b.host")]
    assert await nb._reload_plugins() == (["a.host", "b.host"], [])
    assert await nb._reload_plugins() == ([], [])  # reloaded
    st["manifests"] = [_m("a", "a.host")]
    assert await nb._reload_plugins() == ([], ["b.host"])
    nb._intercept_server.unregister_app.assert_awaited_once_with("b.host")


async def test_failing_plugin_does_not_unregister_others(plug):
    nb, st = plug
    st["manifests"] = [_m("a", "a.host"), _m("b", "b.host")]
    await nb._reload_plugins()
    st["bad"] = {"b"}
    added, removed = await nb._reload_plugins()
    assert (added, removed) == ([], ["b.host"])  # only the stale failed one goes
    assert [m.hostname for m in nb._plugin_manifests] == ["a.host"]


async def test_duplicate_hostname_shadowing_warns(plug, caplog):
    nb, st = plug
    st["manifests"] = [_m("first", "x.host"), _m("second", "x.host")]
    with caplog.at_level(logging.WARNING):
        added, _ = await nb._reload_plugins()
    assert added == ["x.host"]
    assert "second shadows first" in caplog.text
    nb._intercept_server.register_app.assert_awaited_once_with("x.host", "app-second")


async def test_concurrent_reloads_serialise(plug):
    nb, st = plug
    st["manifests"] = [_m("a", "a.host")]
    active, peak = 0, 0

    async def slow_register(host, app):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1

    nb._intercept_server.register_app = slow_register
    await asyncio.gather(nb._reload_plugins(), nb._reload_plugins(), nb._reload_plugins())
    assert peak == 1


# --- tray ---

def test_run_tray_returns_1_when_tray_unavailable(nb, monkeypatch):
    monkeypatch.setattr(app_mod, "TRAY_AVAILABLE", False)
    assert nb._run_tray() == 1


# --- update flow ---

class _FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _upd(version="9.9.9"):
    return SimpleNamespace(version=version, download_url="https://example.invalid/netbridge.exe")


@pytest.fixture
def upd(nb, monkeypatch):
    nb.tray = MagicMock()
    nb._available_update = None
    monkeypatch.setattr(app_mod.aiohttp, "ClientSession", lambda *a, **k: _FakeSession())
    monkeypatch.setattr("netbridge_agent.updater.check_for_update", AsyncMock(return_value=None))
    monkeypatch.setattr("netbridge_agent.updater.download_update", AsyncMock())
    return nb


async def test_check_for_update_found_stores_and_notifies(upd, monkeypatch):
    monkeypatch.setattr("netbridge_agent.updater.check_for_update", AsyncMock(return_value=_upd()))
    await upd._check_for_update()
    assert upd._available_update.version == "9.9.9"
    assert upd.tray.show_notification.call_args.args[0] == "Update Available"
    upd.tray.update_menu.assert_called_once()


async def test_check_for_update_none_is_silent(upd):
    await upd._check_for_update()
    assert upd._available_update is None
    upd.tray.show_notification.assert_not_called()


async def test_check_for_update_swallows_errors(upd, monkeypatch):
    monkeypatch.setattr("netbridge_agent.updater.check_for_update", AsyncMock(side_effect=RuntimeError("down")))
    await upd._check_for_update()  # must not raise
    assert upd._available_update is None


async def test_do_update_when_up_to_date_notifies_and_does_not_download(upd):
    await upd._do_update()
    titles = [c.args[0] for c in upd.tray.show_notification.call_args_list]
    assert titles == ["Updating", "No Update"]
    import netbridge_agent.updater as updater
    updater.download_update.assert_not_called()


async def test_do_update_download_failure_notifies_and_does_not_launch(upd, monkeypatch):
    upd._available_update = _upd()
    monkeypatch.setattr("netbridge_agent.updater.download_update", AsyncMock(side_effect=OSError("disk")))
    upd._launch_update_script = MagicMock()
    await upd._do_update()
    assert upd.tray.show_notification.call_args.args[0] == "Update Failed"
    upd._launch_update_script.assert_not_called()


async def test_do_update_rechecks_and_stores_found_update(upd, monkeypatch, tmp_path):
    from netbridge_agent.installer import Installer
    monkeypatch.setattr("netbridge_agent.updater.check_for_update", AsyncMock(return_value=_upd("1.2.3")))
    monkeypatch.setattr("netbridge_agent.config.get_app_dir", lambda: tmp_path)
    monkeypatch.setattr("netbridge_agent.installer.get_installed_exe_path", lambda: tmp_path / "netbridge.exe")
    monkeypatch.setattr(Installer, "terminate_running_instances", MagicMock())
    monkeypatch.setattr(Installer, "save_installed_version", MagicMock())
    upd._launch_update_script = MagicMock()
    await upd._do_update()
    assert upd._available_update.version == "1.2.3"
    upd._launch_update_script.assert_called_once()


async def test_do_update_success_saves_version_and_launches_script(upd, monkeypatch, tmp_path):
    from netbridge_agent.installer import Installer
    upd._available_update = _upd("9.9.9")
    target = tmp_path / "netbridge.exe"
    monkeypatch.setattr("netbridge_agent.config.get_app_dir", lambda: tmp_path)
    monkeypatch.setattr("netbridge_agent.installer.get_installed_exe_path", lambda: target)
    monkeypatch.setattr(Installer, "terminate_running_instances", MagicMock())
    save = MagicMock()
    monkeypatch.setattr(Installer, "save_installed_version", save)
    upd._launch_update_script = MagicMock()
    await upd._do_update()
    save.assert_called_once_with("9.9.9")
    upd._launch_update_script.assert_called_once_with(tmp_path / "netbridge-update.exe", target)


async def test_do_update_apply_failure_notifies_and_does_not_launch(upd, monkeypatch, tmp_path):
    from netbridge_agent.installer import Installer
    upd._available_update = _upd()
    monkeypatch.setattr("netbridge_agent.config.get_app_dir", lambda: tmp_path)
    monkeypatch.setattr("netbridge_agent.installer.get_installed_exe_path", lambda: tmp_path / "netbridge.exe")
    monkeypatch.setattr(Installer, "terminate_running_instances", MagicMock(side_effect=OSError("locked")))
    upd._launch_update_script = MagicMock()
    await upd._do_update()
    assert upd.tray.show_notification.call_args.args[0] == "Update Failed"
    upd._launch_update_script.assert_not_called()


def test_launch_update_script_writes_the_swap_script_and_exits(nb, monkeypatch, tmp_path):
    popen = MagicMock()
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(subprocess, "DETACHED_PROCESS", 8, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    nb.request_exit = MagicMock()
    source, target = tmp_path / "netbridge-update.exe", tmp_path / "netbridge.exe"
    nb._launch_update_script(source, target)
    script = (tmp_path / "_update.cmd").read_text(encoding="utf-8")
    assert f'move /Y "{source}" "{target}"' in script
    assert f'start "" "{target}" --no-install' in script
    assert f'"PID eq {app_mod.os.getpid()}"' in script
    assert popen.call_args.args[0] == ["cmd", "/C", str(tmp_path / "_update.cmd")]
    assert popen.call_args.kwargs["creationflags"] == 8 | 0x08000000
    nb.request_exit.assert_called_once()


async def test_request_check_update_schedules_do_update(nb):
    nb._do_update = AsyncMock()
    nb.request_check_update()  # no loop: nothing
    nb._do_update.assert_not_called()
    nb._async_loop = asyncio.get_running_loop()
    nb.request_check_update()
    await asyncio.sleep(0.01)
    nb._do_update.assert_awaited_once()
