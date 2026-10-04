"""The relay and the two clients.

source mode: everything from this checkout via `uv run` (any OS); the relay
             can come from a built docker image instead (--relay-image, Linux).
exe mode:    the PyInstaller exes, installed where their installers put
             them and launched from there in normal tray mode (Windows).
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

from .netinfo import port_in_use
from .procs import LogWatch, Proc, kill_exe_path

if TYPE_CHECKING:
    from .authstub import AuthStub

IS_WINDOWS = sys.platform == "win32"

REPO = Path(__file__).resolve().parents[3]
# e2e-only sitecustomize that points the relay's key fetch at the local key stub
RELAYSITE_DIR = Path(__file__).resolve().parent / "relaysite"
TEST_TENANT = "11111111-1111-1111-1111-111111111111"
CONNECTED = r"Status changed: \S+ -> connected"
PROXY_READY = r"Bridge agent reachable - tunnel is working end to end"
RELAY_SESSION = r"Connected to relay \(session: \w+\)"
REDIRECTED = r"E2E: relay key URL redirected to "
# fault steps: detect a half-open link in ~15 s; the per-user limit is raised so fault-driven reconnects are
# never throttled. The per-IP limit only counts failed auth, so it stays near the production default.
# 49 = measured failed auths before the flood step (34) + 15; re-measure if the pentest suite or auth matrix adds failing requests.
FAULT_TUNING = {"RELAY_HEARTBEAT_INTERVAL": "10", "RELAY_RATE_CONNECTIONS_PER_MIN": "600",
                "RELAY_RATE_IP_CONNECTIONS_PER_MIN": "49",
                # low enough that the journey's data bursts cross it: over the rate the relay must
                # delay a tunnel's messages, never drop them (a dropped tcp_connect stalls a later step)
                "RELAY_RATE_MESSAGES_PER_SEC": "50"}
CLIENT_TUNING = {"NETBRIDGE_CLIENT_HEARTBEAT_INTERVAL": "10"}
FIXTURES = Path(__file__).resolve().parent / "plugin_fixtures"
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def install_plugin_fixtures(plugins_dir: Path, nonce: str) -> list[Path]:
    """Copy the probe and broken fixture plugins into `plugins_dir` (nonce stamped into the probe)."""
    dirs = []
    for name in ("probe", "broken"):
        dest = plugins_dir / name
        shutil.copytree(FIXTURES / name, dest, dirs_exist_ok=True)
        dirs.append(dest)
    probe = plugins_dir / "probe" / "plugin.py"
    probe.write_text(probe.read_text().replace("__NONCE__", nonce))
    return dirs


def _uv(project: str, *args: str) -> list[str]:
    return ["uv", "run", "--project", str(REPO / project), *args]


def _poll(predicate, timeout: float, alive=None, interval: float = 0.5):
    deadline = time.monotonic() + timeout
    while True:
        result = predicate()
        if result:
            return result
        if time.monotonic() >= deadline or (alive is not None and not alive()):
            return None
        time.sleep(interval)


class Relay:
    def __init__(self, logs_dir: Path, port: int, blocked_port: int, env: dict, image: str | None = None, cov=None,
                 auth: "AuthStub | None" = None, extra_env: dict[str, str] | None = None):
        self.port = port
        self.image = image
        self.auth = auth
        self._cov = None if image else cov
        if image and cov:
            cov.warn("relay runs from a docker image: not instrumented")
        self._logs_dir = logs_dir
        if auth:
            auth_env = dict(NETBRIDGE_ALLOWED_TENANTS=auth.tenant, NETBRIDGE_E2E_JWKS_URL=auth.jwks_url)
        else:
            auth_env = dict(NETBRIDGE_ALLOW_NO_AUTH="true", NETBRIDGE_ALLOWED_TENANTS=TEST_TENANT)
        self._relay_env = dict(auth_env, RELAY_BLOCKED_PORTS=str(blocked_port), **FAULT_TUNING, **(extra_env or {}))
        self._env = {k: v for k, v in env.items() if k != "NETBRIDGE_ALLOW_NO_AUTH"} if auth else dict(env)
        self._env.update(self._relay_env)
        if auth:
            self._env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(RELAYSITE_DIR), env.get("PYTHONPATH")]))
            # the key stub is on loopback: an inherited HTTP_PROXY must not swallow the relay's key fetch
            # Windows env names are case-insensitive: setting both would duplicate the variable
            for var in ("NO_PROXY",) if os.name == "nt" else ("NO_PROXY", "no_proxy"):
                self._env[var] = ",".join(filter(None, ["127.0.0.1,localhost", env.get(var)]))
        self._container = f"netbridge-e2e-relay-{port}"
        self._runs = 0
        self.proc: Proc | None = None
        self.logs = LogWatch(logs_dir / "relay-*.log")

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}"

    def start(self) -> None:
        if port_in_use(self.port):
            raise RuntimeError(f"relay port {self.port} is already in use (stale process from an earlier run?)")
        self._runs += 1
        relay_args = ["-m", "relay", *([] if self.auth else ["--no-auth"]), "--host", "127.0.0.1", "--port", str(self.port)]
        if self.image:
            self._remove_container()
            # host network: the relay binds loopback, which must be the runner's loopback (and the key stub's)
            env_args = [a for k, v in self._relay_env.items() for a in ("-e", f"{k}={v}")]
            if self.auth:
                env_args += ["-v", f"{RELAYSITE_DIR}:/e2e-site:ro", "-e", "PYTHONPATH=/e2e-site"]
            argv = ["docker", "run", "--rm", "--name", self._container, "--network", "host", *env_args,
                    self.image, ".venv/bin/python", *relay_args]
        else:
            argv = (self._cov and self._cov.wrap("relay", relay_args)) or _uv("relay", "python", *relay_args)
        self.proc = Proc("relay", argv, self._logs_dir / f"relay-{self._runs}.log", env=self._env).start()

    def _remove_container(self) -> None:
        subprocess.run(["docker", "rm", "-f", self._container], capture_output=True, timeout=60)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.alive()

    def stop(self) -> None:
        if self.image and self.proc:
            self._remove_container()  # killing the docker client alone can leave the container running
        if self.proc:
            self.proc.stop()

    def status(self) -> dict | None:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/status")
        if self.auth:
            # authenticated callers also get the agent/client counts that wait_paired needs
            req.add_header("Authorization", f"Bearer {self.auth.mint(upn='status@netbridge.test')}")
        try:
            with _NO_PROXY.open(req, timeout=3) as r:
                return json.loads(r.read())
        except (OSError, ValueError):
            return None

    def wait_ready(self, timeout: float) -> bool:
        # the port was free before start(), so an answer can only come from our process
        return _poll(self.status, timeout, alive=self.alive) is not None and self.alive()

    def wait_paired(self, timeout: float) -> dict | None:
        def paired():
            s = self.status()
            return s if s and s.get("agents", 0) >= 1 and s.get("tunnel_clients", 0) >= 1 else None
        return _poll(paired, timeout)


class _Component:
    name = ""
    proc: Proc | None = None
    logs: LogWatch

    def alive(self) -> bool:
        return self.proc is not None and self.proc.alive()

    def stop(self) -> None:
        if self.proc:
            self.proc.stop()

    def cleanup(self) -> None:
        self.stop()

    def collect_logs(self, dest: Path) -> None:
        out = dest / self.name
        out.mkdir(parents=True, exist_ok=True)
        for f in self.logs.files():
            if f.parent != out:
                shutil.copy2(f, out / f.name)


class SourceAgent(_Component):
    """Agent from source in --console mode (same NetBridgeApp as the tray, minus the icon)."""

    def __init__(self, work: Path, relay_url: str, env: dict, cov=None):
        self.name = "agent"
        self._relay_url = relay_url
        self._cov = cov
        localappdata = work / "localappdata"
        self.app_dir = localappdata / "NetBridge"
        self._stdout = work / "logs" / "agent-stdout.log"
        self._env = dict(env, LOCALAPPDATA=str(localappdata))
        self.logs = LogWatch(self.app_dir / "logs" / "*.log", self._stdout)
        self.plugins_dir = self.app_dir / "plugins"
        self._plugin_dirs: list[Path] = []

    def add_plugins(self, nonce: str) -> list[Path]:
        self._plugin_dirs = install_plugin_fixtures(self.plugins_dir, nonce)
        return self._plugin_dirs

    def cleanup(self) -> None:
        self.stop()
        for d in self._plugin_dirs:
            shutil.rmtree(d, ignore_errors=True)

    def install(self) -> str:
        self.app_dir.mkdir(parents=True, exist_ok=True)
        (self.app_dir / "config.json").write_text(json.dumps({"relay_url": self._relay_url, "auto_connect": True}, indent=2))
        return f"source agent, config in {self.app_dir}"

    def start(self) -> None:
        module = ["-m", "netbridge_agent", "--console"]
        argv = (self._cov and self._cov.wrap("netbridge-agent", module)) or _uv("netbridge-agent", "python", *module)
        self.proc = Proc("agent", argv, self._stdout, env=self._env).start()


class SourceProxy(_Component):
    """`netbridge-socks serve` from source, config dir isolated from the user's."""

    def __init__(self, work: Path, relay_url: str, socks_port: int, http_port: int, env: dict, cov=None):
        self.name = "proxy"
        self._serve = ["serve", "--relay", relay_url, "--host", "127.0.0.1", "--port", str(socks_port),
                       "--http-port", str(http_port), "--no-tray"]
        self._cov = cov
        self._stdout = work / "logs" / "proxy-stdout.log"
        self._env = dict(env, XDG_CONFIG_HOME=str(work / "xdg-config"))
        self.logs = LogWatch(self._stdout)

    def install(self) -> str:
        return "source proxy, CLI flags only"

    def start(self) -> None:
        # python -m socks_proxy runs the same main() as the netbridge-socks entry point
        argv = ((self._cov and self._cov.wrap("socks-proxy", ["-m", "socks_proxy", *self._serve]))
                or _uv("socks-proxy", "netbridge-socks", *self._serve))
        self.proc = Proc("proxy", argv, self._stdout, env=self._env).start()


class ExeComponent(_Component):
    """An installed release exe, launched from its install location."""

    def __init__(self, *, name: str, source_exe: Path, app_name: str, exe_name: str, config: dict,
                 args: list[str], env: dict, work: Path, allow_existing: bool):
        self.name = name
        self.app_name = app_name
        self.source_exe = source_exe
        self.install_dir = Path(os.environ["LOCALAPPDATA"]) / app_name
        self.plugins_dir = self.install_dir / "plugins"
        self.installed_exe = self.install_dir / exe_name
        self._config = config
        self._args = args
        self._env = env
        self._stdout = work / "logs" / f"{name}-stdout.log"
        self._allow_existing = allow_existing
        self._installed = False
        self._started = False
        self._uninstalled = False
        self.logs = LogWatch(self.install_dir / "logs" / "*.log")

    def add_plugins(self, nonce: str) -> list[Path]:
        return install_plugin_fixtures(self.plugins_dir, nonce)

    def install(self) -> str:
        if self.install_dir.exists() and not self._allow_existing:
            raise RuntimeError(f"{self.install_dir} already exists; use --allow-existing-install on a disposable machine")
        from . import winsys
        if winsys.run_value_exists(self.app_name) and not self._allow_existing:
            raise RuntimeError(f"HKCU Run value {self.app_name!r} already exists; use --allow-existing-install on a disposable machine")
        self.install_dir.mkdir(parents=True, exist_ok=True)
        self._installed = True
        shutil.copy2(self.source_exe, self.installed_exe)
        (self.install_dir / "config.json").write_text(json.dumps(self._config, indent=2))
        winsys.set_run_value(self.app_name, f'"{self.installed_exe}"')  # what install_fresh registers
        return f"{self.installed_exe}"

    def start(self) -> None:
        self._started = True
        flags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
        self.proc = Proc(self.name, [str(self.installed_exe), *self._args], self._stdout, env=self._env, creationflags=flags).start()

    def stop(self) -> None:
        # never touch processes or files this run did not create (a developer's real install)
        super().stop()
        if self._started:
            kill_exe_path(self.installed_exe)

    def collect_logs(self, dest: Path) -> None:
        if self._installed:
            super().collect_logs(dest)

    def uninstall(self) -> tuple[bool, str]:
        from . import winsys
        self.stop()
        flags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
        p = subprocess.Popen([str(self.installed_exe), "--uninstall"], env=self._env, creationflags=flags)
        clicked = winsys.click_messagebox_yes(
            f"Uninstall {self.app_name}",
            timeout=30,
            accept_pid=lambda pid: pid == p.pid or winsys.parent_pid(pid) == p.pid,
        )
        try:
            code = p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            p.kill()
            return False, f"--uninstall did not exit (confirmation clicked: {clicked})"
        if not clicked or code != 0:
            return False, f"--uninstall exit {code}, confirmation clicked: {clicked}"
        # the exe deletes its own directory through a detached retry script
        gone = _poll(lambda: not self.install_dir.exists(), 60)
        run_left = winsys.run_value_exists(self.app_name)
        self._uninstalled = bool(gone) and not run_left
        return self._uninstalled, f"dir removed: {bool(gone)}, Run value removed: {not run_left}"

    def cleanup(self) -> None:
        self.stop()
        if self._installed and not self._uninstalled:
            from . import winsys
            winsys.delete_run_value(self.app_name)
            shutil.rmtree(self.install_dir, ignore_errors=True)


def make_exe_agent(exe: Path, relay_url: str, env: dict, work: Path, console: bool, allow_existing: bool) -> ExeComponent:
    return ExeComponent(
        name="agent", source_exe=exe, app_name="NetBridge", exe_name="netbridge.exe",
        config={"relay_url": relay_url, "auto_connect": True},
        args=["--console"] if console else [], env=env, work=work, allow_existing=allow_existing,
    )


def make_exe_proxy(exe: Path, relay_url: str, socks_port: int, http_port: int,
                   env: dict, work: Path, allow_existing: bool) -> ExeComponent:
    return ExeComponent(
        name="proxy", source_exe=exe, app_name="NetBridgeSocks", exe_name="netbridge-socks.exe",
        # no probe_target: the default probe (netbridge-exec, answered by the agent) is what users run
        config={"relay_url": relay_url, "socks_port": socks_port, "http_port": http_port, "auto_connect": True},
        args=[], env=env, work=work, allow_existing=allow_existing,
    )
