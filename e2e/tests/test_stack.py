import os
import socket
import subprocess
import time

import pytest

from netbridge_e2e import stack


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def relay(tmp_path):
    env = dict(os.environ, HTTP_PROXY="http://127.0.0.1:9", http_proxy="http://127.0.0.1:9")
    r = stack.Relay(tmp_path, free_port(), blocked_port=1, env=env)
    r.start()
    yield r
    r.stop()


def test_relay_starts_in_no_auth_mode_even_with_a_bogus_http_proxy_env(relay):
    assert relay.wait_ready(120), relay.logs.tail()
    status = relay.status()
    assert status["auth_required"] is False
    assert status["agents"] == 0 and status["tunnel_clients"] == 0
    assert relay.wait_paired(1) is None


@pytest.mark.skipif(not os.environ.get("NETBRIDGE_E2E_RELAY_IMAGE"), reason="set NETBRIDGE_E2E_RELAY_IMAGE to a built relay image")
def test_relay_from_image_starts_restarts_and_leaves_no_container(tmp_path):
    r = stack.Relay(tmp_path, free_port(), blocked_port=1, env=dict(os.environ), image=os.environ["NETBRIDGE_E2E_RELAY_IMAGE"])
    try:
        for _ in range(2):  # the journey's reconnect step restarts the relay under the same container name
            r.start()
            assert r.wait_ready(60), r.logs.tail()
            assert r.status()["auth_required"] is False
            r.stop()
            assert not r.alive()
    finally:
        r.stop()
    left = subprocess.run(["docker", "ps", "-aq", "--filter", f"name=^{r._container}$"], capture_output=True, text=True)
    assert left.stdout.strip() == ""


def test_relay_refuses_a_busy_port(tmp_path):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        r = stack.Relay(tmp_path, busy.getsockname()[1], blocked_port=1, env=dict(os.environ))
        with pytest.raises(RuntimeError, match="already in use"):
            r.start()
        assert r.proc is None


def test_relay_wait_ready_fails_fast_when_the_process_dies(tmp_path):
    r = stack.Relay(tmp_path, free_port(), blocked_port=1, env=dict(os.environ))
    r.start()
    r.proc.stop()  # simulate a crash right after launch
    start = time.monotonic()
    assert r.wait_ready(120) is False
    assert time.monotonic() - start < 5


def test_exe_stop_and_logs_leave_foreign_installations_alone(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    logs = tmp_path / "NetBridge" / "logs"
    logs.mkdir(parents=True)
    (logs / "netbridge.log").write_text("someone else's log")
    killed = []
    monkeypatch.setattr(stack, "kill_exe_path", killed.append)
    comp = stack.make_exe_agent(tmp_path / "x.exe", "ws://127.0.0.1:1", {}, tmp_path / "work", console=False, allow_existing=False)
    with pytest.raises(RuntimeError):
        comp.install()
    comp.collect_logs(tmp_path / "out")
    comp.cleanup()
    assert killed == []
    assert not (tmp_path / "out").exists()
    assert (logs / "netbridge.log").exists()


def test_source_agent_install_writes_isolated_config(tmp_path):
    agent = stack.SourceAgent(tmp_path, "ws://127.0.0.1:1", env={})
    agent.install()
    cfg = (tmp_path / "localappdata" / "NetBridge" / "config.json").read_text()
    assert '"relay_url": "ws://127.0.0.1:1"' in cfg


def test_exe_install_refuses_an_existing_installation(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    (tmp_path / "NetBridge").mkdir()
    exe = tmp_path / "netbridge.exe"
    exe.write_bytes(b"MZ")
    comp = stack.make_exe_agent(exe, "ws://127.0.0.1:1", {}, tmp_path / "work", console=False, allow_existing=False)
    with pytest.raises(RuntimeError, match="already exists"):
        comp.install()


def test_exe_install_refuses_an_existing_run_value(tmp_path, monkeypatch):
    """Verify install() checks for existing Run value before writing anything."""
    import sys
    from types import SimpleNamespace
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    exe = tmp_path / "netbridge.exe"
    exe.write_bytes(b"MZ")
    # Inject a fake winsys module that reports the Run value exists
    fake_winsys = SimpleNamespace(
        run_value_exists=lambda name: True,
        set_run_value=lambda name, value: None,
        delete_run_value=lambda name: None,
    )
    monkeypatch.setitem(sys.modules, "netbridge_e2e.winsys", fake_winsys)
    comp = stack.make_exe_agent(exe, "ws://127.0.0.1:1", {}, tmp_path / "work", console=False, allow_existing=False)
    # The directory check happens first, passes (dir doesn't exist)
    # Then the Run value check should fail
    with pytest.raises(RuntimeError, match="HKCU Run value 'NetBridge' already exists"):
        comp.install()
    # Verify nothing was written
    assert not (tmp_path / "NetBridge").exists()
    # Cleanup should not delete the pre-existing Run value
    assert not comp._installed
    comp.cleanup()
    # The fake module should be cleaned up after the test
    monkeypatch.delitem(sys.modules, "netbridge_e2e.winsys", raising=False)
