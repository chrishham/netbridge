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


class FakeCov:
    def __init__(self):
        self.warnings = []

    def wrap(self, project, module_args):
        return ["COV", project, *module_args]

    def warn(self, msg):
        self.warnings.append(msg)


def captured_argv(monkeypatch):
    seen = {}

    class FakeProc:
        def __init__(self, name, argv, log_path, env=None, **kw):
            seen[name] = argv

        def start(self):
            return self

    monkeypatch.setattr(stack, "Proc", FakeProc)
    monkeypatch.setattr(stack, "port_in_use", lambda port: False)
    return seen


def test_relay_argv_under_coverage(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)
    stack.Relay(tmp_path, 1, blocked_port=2, env={}, cov=FakeCov()).start()
    assert seen["relay"][:4] == ["COV", "relay", "-m", "relay"]
    assert "--no-auth" in seen["relay"]


def test_relay_argv_without_coverage_is_unchanged(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)
    stack.Relay(tmp_path, 1, blocked_port=2, env={}).start()
    assert seen["relay"][:3] == ["uv", "run", "--project"]


def test_relay_image_is_not_instrumented(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)
    monkeypatch.setattr(stack.subprocess, "run", lambda *a, **k: None)
    fake = FakeCov()
    stack.Relay(tmp_path, 1, blocked_port=2, env={}, image="img", cov=fake).start()
    assert seen["relay"][0] == "docker"
    assert fake.warnings == ["relay runs from a docker image: not instrumented"]


def test_wrap_failure_falls_back_to_uninstrumented_argv(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)

    class BrokenCov(FakeCov):
        def wrap(self, project, module_args):
            return None

    stack.Relay(tmp_path, 1, blocked_port=2, env={}, cov=BrokenCov()).start()
    stack.SourceAgent(tmp_path, "ws://x", env={}, cov=BrokenCov()).start()
    stack.SourceProxy(tmp_path, "ws://x", 1, 2, env={}, cov=BrokenCov()).start()
    assert seen["relay"][:3] == ["uv", "run", "--project"]
    assert seen["agent"][:3] == ["uv", "run", "--project"]
    assert seen["proxy"][:3] == ["uv", "run", "--project"]


def test_agent_and_proxy_argv_under_coverage(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)
    stack.SourceAgent(tmp_path, "ws://x", env={}, cov=FakeCov()).start()
    stack.SourceProxy(tmp_path, "ws://x", 1, 2, env={}, cov=FakeCov()).start()
    assert seen["agent"] == ["COV", "netbridge-agent", "-m", "netbridge_agent", "--console"]
    assert seen["proxy"][:5] == ["COV", "socks-proxy", "-m", "socks_proxy", "serve"]
    assert "--no-tray" in seen["proxy"]


def test_relay_image_gets_fault_tuning(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)
    monkeypatch.setattr(stack.subprocess, "run", lambda *a, **k: None)
    stack.Relay(tmp_path, 1, blocked_port=2, env={}, image="img").start()
    argv = seen["relay"]
    pairs = [argv[i:i + 2] for i in range(len(argv) - 1)]
    assert ["-e", "RELAY_HEARTBEAT_INTERVAL=10"] in pairs
    assert ["-e", "RELAY_RATE_CONNECTIONS_PER_MIN=600"] in pairs
    assert ["-e", "RELAY_RATE_IP_CONNECTIONS_PER_MIN=49"] in pairs


def test_relay_source_env_gets_fault_tuning(tmp_path, monkeypatch):
    envs = {}

    class FakeProc:
        def __init__(self, name, argv, log_path, env=None, **kw):
            envs[name] = env

        def start(self):
            return self

    monkeypatch.setattr(stack, "Proc", FakeProc)
    monkeypatch.setattr(stack, "port_in_use", lambda port: False)
    stack.Relay(tmp_path, 1, blocked_port=2, env={}).start()
    assert {k: envs["relay"][k] for k in stack.FAULT_TUNING} == {
        "RELAY_HEARTBEAT_INTERVAL": "10", "RELAY_RATE_CONNECTIONS_PER_MIN": "600",
        "RELAY_RATE_IP_CONNECTIONS_PER_MIN": "49"}


class FakeStub:
    tenant = "33333333-3333-3333-3333-333333333333"
    jwks_url = f"http://127.0.0.1:9/{tenant}/discovery/v2.0/keys"

    def __init__(self):
        self.minted = []

    def mint(self, **kw):
        self.minted.append(kw)
        return "signed.test.token"


def captured_proc(monkeypatch):
    seen = {}

    class FakeProc:
        def __init__(self, name, argv, log_path, env=None, **kw):
            seen["argv"], seen["env"] = argv, env

        def start(self):
            return self

    monkeypatch.setattr(stack, "Proc", FakeProc)
    monkeypatch.setattr(stack, "port_in_use", lambda port: False)
    monkeypatch.setattr(stack.subprocess, "run", lambda *a, **k: None)
    return seen


def test_relay_source_with_auth(tmp_path, monkeypatch):
    seen = captured_proc(monkeypatch)
    stub = FakeStub()
    env = {"PYTHONPATH": "/existing", "NETBRIDGE_ALLOW_NO_AUTH": "true"}
    stack.Relay(tmp_path, 1, blocked_port=2, env=env, auth=stub).start()
    assert "--no-auth" not in seen["argv"]
    assert seen["argv"][-4:] == ["--host", "127.0.0.1", "--port", "1"]
    e = seen["env"]
    assert e["NETBRIDGE_ALLOWED_TENANTS"] == stub.tenant
    assert e["NETBRIDGE_E2E_JWKS_URL"] == stub.jwks_url
    assert e["PYTHONPATH"] == os.pathsep.join([str(stack.RELAYSITE_DIR), "/existing"])
    assert "NETBRIDGE_ALLOW_NO_AUTH" not in e
    assert e["RELAY_HEARTBEAT_INTERVAL"] == "10"
    assert e["NO_PROXY"] == "127.0.0.1,localhost"
    # Windows env names are case-insensitive, so only one spelling is set there
    assert ("no_proxy" in e) == (os.name != "nt")
    if os.name != "nt":
        assert e["no_proxy"] == "127.0.0.1,localhost"


def test_relay_source_with_auth_and_no_inherited_pythonpath(tmp_path, monkeypatch):
    seen = captured_proc(monkeypatch)
    var = "NO_PROXY" if os.name == "nt" else "no_proxy"  # os.environ is upper-cased on Windows
    stack.Relay(tmp_path, 1, blocked_port=2, env={var: "corp.example"}, auth=FakeStub()).start()
    assert seen["env"]["PYTHONPATH"] == str(stack.RELAYSITE_DIR)
    assert seen["env"][var] == "127.0.0.1,localhost,corp.example"


def test_relay_source_without_auth_keeps_no_auth_mode(tmp_path, monkeypatch):
    seen = captured_proc(monkeypatch)
    stack.Relay(tmp_path, 1, blocked_port=2, env={}).start()
    assert "--no-auth" in seen["argv"]
    assert seen["env"]["NETBRIDGE_ALLOW_NO_AUTH"] == "true"
    assert seen["env"]["NETBRIDGE_ALLOWED_TENANTS"] == stack.TEST_TENANT
    assert "NETBRIDGE_E2E_JWKS_URL" not in seen["env"] and "PYTHONPATH" not in seen["env"]


def test_relay_image_with_auth(tmp_path, monkeypatch):
    seen = captured_proc(monkeypatch)
    stub = FakeStub()
    stack.Relay(tmp_path, 1, blocked_port=2, env={}, image="img", auth=stub).start()
    argv = seen["argv"]
    pairs = [argv[i:i + 2] for i in range(len(argv) - 1)]
    assert "--no-auth" not in argv
    assert ["-v", f"{stack.RELAYSITE_DIR}:/e2e-site:ro"] in pairs
    assert ["-e", "PYTHONPATH=/e2e-site"] in pairs
    assert ["-e", f"NETBRIDGE_E2E_JWKS_URL={stub.jwks_url}"] in pairs
    assert ["-e", f"NETBRIDGE_ALLOWED_TENANTS={stub.tenant}"] in pairs
    assert not any(a.startswith("NETBRIDGE_ALLOW_NO_AUTH") for a in argv)
    assert argv.index("img") > argv.index("-v")  # docker options precede the image


def test_relay_status_sends_a_bearer_token_with_auth(tmp_path, monkeypatch):
    sent = []

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"auth_required": true, "agents": 0}'

    def fake_open(req, timeout):
        sent.append(req)
        return Resp()

    monkeypatch.setattr(stack._NO_PROXY, "open", fake_open)
    stub = FakeStub()
    assert stack.Relay(tmp_path, 5, blocked_port=2, env={}, auth=stub).status() == {"auth_required": True, "agents": 0}
    assert sent[0].full_url == "http://127.0.0.1:5/status"
    assert sent[0].get_header("Authorization") == "Bearer signed.test.token"
    assert stub.minted == [{"upn": "status@netbridge.test"}]
    stack.Relay(tmp_path, 5, blocked_port=2, env={}).status()
    assert sent[1].get_header("Authorization") is None


def test_relay_with_auth_validates_tokens_against_the_stub(tmp_path):
    import re

    from netbridge_e2e.authstub import AuthStub
    stub = AuthStub(tmp_path)
    stub.start()
    env = dict(os.environ, HTTP_PROXY="http://127.0.0.1:9", http_proxy="http://127.0.0.1:9")
    r = stack.Relay(tmp_path / "logs", free_port(), blocked_port=1, env=env, auth=stub)
    try:
        r.start()
        assert r.wait_ready(120), r.logs.tail()
        status = r.status()
        assert status["auth_required"] is True
        assert "agents" in status, status  # the stub-signed bearer was accepted
        assert re.search(stack.REDIRECTED + re.escape(stub.jwks_url), r.logs.text()), r.logs.tail()
        assert stub.requests() >= 1
    finally:
        r.stop()
        stub.close()


def test_add_plugins_copies_fixtures_substitutes_nonce_and_cleans_up(tmp_path):
    agent = stack.SourceAgent(tmp_path, "ws://127.0.0.1:1", env={})
    agent.install()
    dirs = agent.add_plugins("abc123")
    text = (agent.plugins_dir / "probe" / "plugin.py").read_text()
    assert "abc123" in text and "__NONCE__" not in text
    assert (agent.plugins_dir / "broken" / "manifest.json").exists()
    agent.cleanup()
    assert not any(d.exists() for d in dirs)


def test_fixture_plugins_work_with_the_agents_real_loader(tmp_path):
    pytest.importorskip("netbridge_agent")
    import asyncio
    from aiohttp.test_utils import TestClient, TestServer
    from netbridge_agent.plugin_loader import discover_plugins, load_plugin_app
    stack.install_plugin_fixtures(tmp_path, "n0nce")
    manifests = discover_plugins(tmp_path)                    # the broken one is skipped by the loader
    assert [m.hostname for m in manifests] == ["netbridge-e2e-probe"]
    app = load_plugin_app(manifests[0])

    async def fetch():
        async with TestClient(TestServer(app)) as c:
            return await (await c.get("/")).text()

    assert asyncio.run(fetch()) == "netbridge-e2e-plugin n0nce"


def test_add_plugins_is_idempotent(tmp_path):
    agent = stack.SourceAgent(tmp_path, "ws://127.0.0.1:1", env={})
    agent.install()
    agent.add_plugins("first")
    agent.add_plugins("second")
    assert "second" in (agent.plugins_dir / "probe" / "plugin.py").read_text()


def test_exe_add_plugins_installs_under_the_install_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    comp = stack.make_exe_agent(tmp_path / "x.exe", "ws://127.0.0.1:1", {}, tmp_path / "work", console=False, allow_existing=False)
    dirs = comp.add_plugins("n1")
    assert [d.parent for d in dirs] == [comp.install_dir / "plugins"] * 2
    assert "n1" in (comp.install_dir / "plugins" / "probe" / "plugin.py").read_text()


def test_relay_extra_env_reaches_process_and_container(tmp_path, monkeypatch):
    extra = {"RELAY_TRUSTED_PROXIES": "127.0.0.1/32", "RELAY_CLIENT_IP_HEADER": "X-Forwarded-For"}
    seen = captured_argv(monkeypatch)
    r = stack.Relay(tmp_path, 1, blocked_port=2, env={}, extra_env=extra)
    assert extra.items() <= r._env.items()
    monkeypatch.setattr(stack.Relay, "_remove_container", lambda self: None)
    stack.Relay(tmp_path, 1, blocked_port=2, env={}, image="img", extra_env=extra).start()
    assert "RELAY_TRUSTED_PROXIES=127.0.0.1/32" in seen["relay"]
    assert "RELAY_CLIENT_IP_HEADER=X-Forwarded-For" in seen["relay"]


def test_relay_without_extra_env_trusts_no_proxy(tmp_path):
    r = stack.Relay(tmp_path, 1, blocked_port=2, env={})
    assert "RELAY_TRUSTED_PROXIES" not in r._env
