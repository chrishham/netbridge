# Release-binary E2E Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An E2E driver (`e2e/`) that runs relay + agent + proxy — from source on any OS, or as the installed Windows release exes — through install → connect → traffic → filter → reconnect → uninstall, wired into CI and into the two Windows release workflows so only a gate-passing exe is published.

**Architecture:** A stdlib-only Python package `netbridge_e2e` (own uv project under `e2e/`). The relay always runs from source with `--no-auth` on loopback; the clients authenticate through a fake `az` placed first on `PATH`; target servers run in driver threads on the machine's non-loopback IPv4. Two modes share the journey: `source` (agent `--console`, `netbridge-socks serve`) and `exe` (installed `netbridge.exe` / `netbridge-socks.exe` in tray mode).

**Tech Stack:** Python 3.14, uv, pytest, GitHub Actions (`windows-latest`, `ubuntu-latest`), PyInstaller (existing specs).

**Spec:** `docs/superpowers/specs/2026-09-26-release-binary-e2e-design.md`

## Global Constraints

- No product code changes (relay, shared, agent, socks-proxy, socks-proxy-win). Only exception allowed by the spec: adding a log line if a needed signal has none.
- Driver is stdlib only at runtime; `pytest` and `shared-auth` (path `../shared`) are dev-only.
- `requires-python = ">=3.14"`, every command via `uv` (never bare `python`/`pip`).
- Relay: `--no-auth --host 127.0.0.1`, env `NETBRIDGE_ALLOW_NO_AUTH=true`, `NETBRIDGE_ALLOWED_TENANTS=11111111-1111-1111-1111-111111111111`.
- Default ports: relay `18080`, SOCKS5 `11080`, HTTP proxy `13128` (never the user-facing 1080/3128 — a developer's real proxy may be running).
- Every process the driver launches gets `NO_PROXY`/`no_proxy` = `127.0.0.1,localhost,<target ip>`; the driver's own HTTP calls use no proxy.
- Connected marker, both apps: log line matching `Status changed: \S+ -> connected`.
- Exe mode install dirs: `%LOCALAPPDATA%\NetBridge\netbridge.exe` and `%LOCALAPPDATA%\NetBridgeSocks\netbridge-socks.exe`; Run values `NetBridge` / `NetBridgeSocks` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`; uninstall MessageBox titles `Uninstall NetBridge` / `Uninstall NetBridgeSocks`.
- Commit messages: plain human style, no AI attribution lines.

## Decisions made while planning (deviations from / additions to the spec)

1. **`source` mode added** (spec only described exe mode). The same journey runs relay/agent/proxy from source on Linux: it verifies the driver locally (the Windows job cannot be run before a push) and gives every PR a cheap Linux E2E job. Feasibility was proven on 2026-09-26: fake az + `--no-auth` relay + agent `--console` + `netbridge-socks serve` → relay `/status` showed `agents: 1, tunnel_clients: 1` and SOCKS5 + HTTP-proxy GETs reached a target on the LAN IP.
2. **Uninstall confirmation is clicked by the driver** (`FindWindowW("#32770", title)` + `PostMessageW(WM_COMMAND, IDYES)`), because `--uninstall` always shows a Yes/No MessageBox. Keeps the real user path, no product change.
3. **The driver writes the HKCU Run value at install time** exactly like `install_fresh` does, instead of automating the custom ctypes relay-URL dialog. Uninstall's removal of it is still asserted.
4. **`--agent-console`** exe-mode flag: fallback if pystray cannot run in the hosted runner session (spec risk). Proxy has no such fallback without a product change.
5. **Exe mode refuses to run when an install dir already exists** unless `--allow-existing-install` — protects a developer's real installation.
6. **Traffic clients are exercised by unit tests against in-test fake proxies**; the real proxies are exercised by the source-mode journey itself.

## Review Focus

- **A previous run left a relay/proxy bound to the port** → `relay_up`/`proxy_started` must fail fast with the log tail, not wait out the full timeout. Test: `Relay.wait_ready` returns `False` promptly once the process dies (Task 5).
- **Developer shell has `HTTP_PROXY`/`HTTPS_PROXY` set** → driver's `/status` polling must not go through it. Test: `Relay.status()` works with `HTTP_PROXY=http://127.0.0.1:9` (Task 5).
- **Proxy hangs instead of refusing** (e.g. blocked port) → every client call is bounded by a timeout and reports failure. Test: `socks5_connect` against a silent server raises `TimeoutError` (Task 3).
- **A real Azure CLI is already on PATH** (hosted runners have one) → the fake must win. Test: `env_with_fake_az` resolves `az` to the fake even when another `az` dir is on PATH (Task 1).
- **Exe mode started on a machine with a real NetBridge install** → refuse before touching it. Test: exe component `install()` raises when the install dir exists (Task 5).

---

## File Structure

```
e2e/
  pyproject.toml                  uv project netbridge-e2e (stdlib runtime; pytest + shared-auth dev)
  README.md                       how to run both modes locally / what CI runs
  src/netbridge_e2e/
    __init__.py
    __main__.py                   `python -m netbridge_e2e` → journey.main()
    fakeaz/
      __init__.py                 FAKE_AZ_DIR, env_with_fake_az(), token_seconds_left()
      bin/az.py                   the fake CLI (account show / account get-access-token)
      bin/az                      POSIX wrapper (mode 100755)
      bin/az.cmd                  Windows wrapper
    netinfo.py                    private_ipv4()
    targets.py                    Targets (HTTP page + 5 MiB payload, echo, blocked-port echo)
    clients.py                    socks5_connect, http_connect, http_get, http_forward_get, echo_roundtrip
    procs.py                      Proc (process tree start/stop), LogWatch (poll logs for regex)
    stack.py                      Relay, SourceAgent, SourceProxy, ExeComponent + factories
    winsys.py                     Windows-only: Run registry value, MessageBox "Yes" click
    journey.py                    Journey (steps, checks, cleanup, summary), parse_args, main
  tests/
    __init__.py
    fakeproxy.py                  in-test SOCKS5 + HTTP proxies used by test_clients
    test_fakeaz.py  test_targets.py  test_clients.py  test_procs.py  test_stack.py  test_journey.py
.github/workflows/
  ci.yml                          + job e2e-source (ubuntu)
  e2e-windows.yml                 NEW reusable: build both exes, smoke, exe-mode journey, artifacts
  release-agent.yml               prepare → e2e (reusable) → publish tested artifact
  release-socks-exe.yml           prepare → e2e (reusable) → publish tested artifact
README.md                         + short "End-to-end tests" section
```

---

### Task 1: e2e project scaffold + fake Azure CLI

**Files:**
- Create: `e2e/pyproject.toml`, `e2e/src/netbridge_e2e/__init__.py`, `e2e/src/netbridge_e2e/fakeaz/__init__.py`, `e2e/src/netbridge_e2e/fakeaz/bin/az.py`, `e2e/src/netbridge_e2e/fakeaz/bin/az`, `e2e/src/netbridge_e2e/fakeaz/bin/az.cmd`, `e2e/tests/__init__.py`
- Test: `e2e/tests/test_fakeaz.py`

**Interfaces:**
- Produces: `fakeaz.FAKE_AZ_DIR: Path`, `fakeaz.ENV_LOG = "NETBRIDGE_E2E_AZ_LOG"`, `fakeaz.ENV_PYTHON = "NETBRIDGE_E2E_PYTHON"`, `fakeaz.env_with_fake_az(base: Mapping[str, str], python: str, log: Path) -> dict[str, str]`, `fakeaz.token_seconds_left(token: str) -> float`.

- [ ] **Step 1: Create the project files**

`e2e/pyproject.toml`:
```toml
[project]
name = "netbridge-e2e"
version = "0.1.0"
description = "End-to-end gate: relay + agent + proxy, from source or as installed Windows exes"
requires-python = ">=3.14"
dependencies = []

[tool.uv]
package = true

[tool.uv.sources]
shared-auth = { path = "../shared" }

[dependency-groups]
dev = [
    "pytest>=9.0.3",
    "shared-auth",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

`e2e/src/netbridge_e2e/__init__.py`:
```python
"""NetBridge end-to-end gate driver."""
```

`e2e/tests/__init__.py`: empty file.

- [ ] **Step 2: Write the failing tests**

`e2e/tests/test_fakeaz.py`:
```python
import json
import shutil
import subprocess
import sys
from pathlib import Path

from shared_auth.token import check_token_expiration

from netbridge_e2e import fakeaz

AZ_NAME = "az.cmd" if sys.platform == "win32" else "az"


def run_az(env, *args):
    az = shutil.which(AZ_NAME, path=env["PATH"])
    return subprocess.run([az, *args], env=env, capture_output=True, text=True, timeout=30)


def test_fake_az_shadows_a_real_az_on_path(tmp_path):
    real = tmp_path / "real-bin"
    real.mkdir()
    (real / AZ_NAME).write_text("echo real")
    (real / AZ_NAME).chmod(0o755)
    env = fakeaz.env_with_fake_az({"PATH": str(real)}, sys.executable, tmp_path / "calls.log")
    resolved = Path(shutil.which(AZ_NAME, path=env["PATH"])).resolve()
    assert resolved.parent == fakeaz.FAKE_AZ_DIR


def test_account_show_returns_a_user(tmp_path):
    env = fakeaz.env_with_fake_az({"PATH": ""}, sys.executable, tmp_path / "calls.log")
    out = run_az(env, "account", "show")
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout)
    assert data["user"]["name"]
    assert data["tenantId"]


def test_token_is_accepted_by_the_real_expiry_check(tmp_path):
    env = fakeaz.env_with_fake_az({"PATH": ""}, sys.executable, tmp_path / "calls.log")
    out = run_az(env, "account", "get-access-token", "--resource", "https://management.azure.com/")
    assert out.returncode == 0, out.stderr
    token = json.loads(out.stdout)["accessToken"]
    ok, message = check_token_expiration(token)
    assert ok, message
    assert fakeaz.token_seconds_left(token) > 3000


def test_calls_are_logged_and_unknown_commands_fail(tmp_path):
    log = tmp_path / "calls.log"
    env = fakeaz.env_with_fake_az({"PATH": ""}, sys.executable, log)
    run_az(env, "account", "show")
    bad = run_az(env, "login")
    assert bad.returncode == 2
    assert log.read_text().splitlines() == ["account show", "login"]
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd e2e && uv sync && uv run pytest tests/test_fakeaz.py -v`
Expected: FAIL — `ImportError: cannot import name 'fakeaz'`.

- [ ] **Step 4: Implement the fake**

`e2e/src/netbridge_e2e/fakeaz/__init__.py`:
```python
"""Fake Azure CLI put first on PATH for the binaries under test.

The relay runs with --no-auth and ignores the bearer token, but the agent
and proxy still run their real auth path: `az account show`, then
`az account get-access-token` via a subprocess, then a local check of the
token's `exp` claim. This fake answers both.
"""
import base64
import json
import os
import time
from collections.abc import Mapping
from pathlib import Path

FAKE_AZ_DIR = Path(__file__).resolve().parent / "bin"
ENV_PYTHON = "NETBRIDGE_E2E_PYTHON"
ENV_LOG = "NETBRIDGE_E2E_AZ_LOG"


def env_with_fake_az(base: Mapping[str, str], python: str, log: Path) -> dict[str, str]:
    """Copy of `base` with the fake az first on PATH."""
    env = dict(base)
    env["PATH"] = os.pathsep.join(p for p in (str(FAKE_AZ_DIR), base.get("PATH", "")) if p)
    env[ENV_PYTHON] = python
    env[ENV_LOG] = str(log)
    return env


def token_seconds_left(token: str) -> float:
    """Seconds until the (unverified) JWT's exp claim."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["exp"] - time.time()
```

`e2e/src/netbridge_e2e/fakeaz/bin/az.py`:
```python
"""Fake `az` for the E2E gate (see netbridge_e2e.fakeaz)."""
import base64
import json
import os
import sys
import time

ACCOUNT = {
    "name": "netbridge-e2e",
    "tenantId": "00000000-0000-0000-0000-0000000000e2",
    "user": {"name": "e2e@netbridge.test", "type": "user"},
}


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def make_token(lifetime: int = 3600) -> str:
    now = int(time.time())
    claims = {"exp": now + lifetime, "iat": now, "upn": ACCOUNT["user"]["name"], "tid": ACCOUNT["tenantId"]}
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}.e2e"


def main(argv: list[str]) -> int:
    log = os.environ.get("NETBRIDGE_E2E_AZ_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write(" ".join(argv) + "\n")
    if argv[:2] == ["account", "show"]:
        print(json.dumps(ACCOUNT))
        return 0
    if argv[:2] == ["account", "get-access-token"]:
        print(json.dumps({"accessToken": make_token(), "tokenType": "Bearer"}))
        return 0
    print(f"fake az: unsupported command: {' '.join(argv)}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

`e2e/src/netbridge_e2e/fakeaz/bin/az`:
```sh
#!/bin/sh
exec "${NETBRIDGE_E2E_PYTHON:-python3}" "$(dirname "$0")/az.py" "$@"
```

`e2e/src/netbridge_e2e/fakeaz/bin/az.cmd`:
```bat
@echo off
"%NETBRIDGE_E2E_PYTHON%" "%~dp0az.py" %*
exit /b %ERRORLEVEL%
```

Then: `chmod +x e2e/src/netbridge_e2e/fakeaz/bin/az` and after `git add`, `git update-index --chmod=+x e2e/src/netbridge_e2e/fakeaz/bin/az` (so the mode survives on Windows checkouts).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd e2e && uv run pytest tests/test_fakeaz.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add e2e/pyproject.toml e2e/uv.lock e2e/src e2e/tests
git update-index --chmod=+x e2e/src/netbridge_e2e/fakeaz/bin/az
git commit -m "Add e2e driver project with a fake Azure CLI"
```

---

### Task 2: Target servers and network discovery

**Files:**
- Create: `e2e/src/netbridge_e2e/targets.py`, `e2e/src/netbridge_e2e/netinfo.py`
- Test: `e2e/tests/test_targets.py`

**Interfaces:**
- Produces: `targets.PAGE: bytes`, `targets.PAYLOAD: bytes`, `targets.PAYLOAD_SHA256: str`, `targets.Targets(host: str)` with attributes `host, http_port, echo_port, blocked_port: int`, `close()`, context manager; `netinfo.private_ipv4() -> str`.

- [ ] **Step 1: Write the failing tests**

`e2e/tests/test_targets.py`:
```python
import hashlib
import ipaddress
import socket
import urllib.request

from netbridge_e2e import netinfo, targets
from netbridge_e2e.targets import PAGE, PAYLOAD, PAYLOAD_SHA256, Targets

NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(url):
    with NO_PROXY.open(url, timeout=10) as r:
        return r.status, r.read()


def test_payload_is_5_mib_and_position_dependent():
    assert len(PAYLOAD) == targets.PAYLOAD_SIZE == 5 * 1024 * 1024
    assert hashlib.sha256(PAYLOAD).hexdigest() == PAYLOAD_SHA256
    assert PAYLOAD[:32] != PAYLOAD[32:64]


def test_http_page_payload_and_404():
    with Targets("127.0.0.1") as t:
        assert get(f"http://127.0.0.1:{t.http_port}/") == (200, PAGE)
        status, body = get(f"http://127.0.0.1:{t.http_port}/payload")
        assert status == 200 and hashlib.sha256(body).hexdigest() == PAYLOAD_SHA256
        try:
            get(f"http://127.0.0.1:{t.http_port}/nope")
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404


def test_echo_and_blocked_listeners_echo():
    with Targets("127.0.0.1") as t:
        assert len({t.http_port, t.echo_port, t.blocked_port}) == 3
        for port in (t.echo_port, t.blocked_port):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.sendall(b"ping")
                assert s.recv(4) == b"ping"


def test_private_ipv4_is_not_loopback_or_link_local():
    ip = ipaddress.ip_address(netinfo.private_ipv4())
    assert ip.version == 4
    assert not ip.is_loopback and not ip.is_link_local
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd e2e && uv run pytest tests/test_targets.py -v`
Expected: FAIL — `ImportError: cannot import name 'netinfo'`.

- [ ] **Step 3: Implement**

`e2e/src/netbridge_e2e/netinfo.py`:
```python
"""Network facts the journey needs."""
import ipaddress
import socket


def private_ipv4() -> str:
    """IPv4 of the default-route interface.

    Targets must not listen on loopback: the agent always blocks loopback
    destinations with its default config, which is what we want to test.
    connect() on a UDP socket only selects the route; no packet is sent.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1
        ip = s.getsockname()[0]
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        raise RuntimeError(f"no usable non-loopback IPv4 (default route source is {ip})")
    return ip
```

`e2e/src/netbridge_e2e/targets.py`:
```python
"""Target servers the tunnelled traffic must reach (driver threads)."""
import hashlib
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"netbridge-e2e ok\n"
PAYLOAD_SIZE = 5 * 1024 * 1024
# sha256 counter stream: incompressible and position-dependent, so dropped,
# duplicated or reordered chunks change the digest
PAYLOAD = b"".join(hashlib.sha256(i.to_bytes(8, "big")).digest() for i in range(PAYLOAD_SIZE // 32))
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


class _HttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = {"/": PAGE, "/payload": PAYLOAD}.get(self.path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class _EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class Targets:
    """HTTP server, echo server and a second echo server the relay must block."""

    def __init__(self, host: str):
        self.host = host
        http = ThreadingHTTPServer((host, 0), _HttpHandler)
        http.daemon_threads = True
        self._servers = [http, _EchoServer((host, 0), _EchoHandler), _EchoServer((host, 0), _EchoHandler)]
        self.http_port, self.echo_port, self.blocked_port = (s.server_address[1] for s in self._servers)
        for server in self._servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def close(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd e2e && uv run pytest tests/test_targets.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add e2e/src/netbridge_e2e/targets.py e2e/src/netbridge_e2e/netinfo.py e2e/tests/test_targets.py
git commit -m "Add e2e target servers and default-route IPv4 discovery"
```

---

### Task 3: SOCKS5 / HTTP-proxy clients

**Files:**
- Create: `e2e/src/netbridge_e2e/clients.py`, `e2e/tests/fakeproxy.py`
- Test: `e2e/tests/test_clients.py`

**Interfaces:**
- Consumes: `targets.Targets`, `targets.PAGE` (tests only).
- Produces (`proxy` is always a `(host, port)` tuple):
  - `class ProxyError(Exception)` with `.code: int` (SOCKS5 reply code or HTTP status; `-1` protocol error)
  - `recv_exact(sock, n: int) -> bytes`
  - `socks5_connect(proxy, dest_host: str, dest_port: int, timeout: float = 15.0) -> socket.socket` (ATYP=domain, remote resolution)
  - `http_connect(proxy, dest_host: str, dest_port: int, timeout: float = 15.0) -> socket.socket`
  - `http_get(sock, host_header: str, path: str = "/") -> tuple[int, bytes]`
  - `http_forward_get(proxy, url: str, timeout: float = 15.0) -> tuple[int, bytes]`
  - `echo_roundtrip(sock, data: bytes) -> bytes`

- [ ] **Step 1: Write the in-test fake proxies**

`e2e/tests/fakeproxy.py`:
```python
"""Tiny direct-connect SOCKS5 and HTTP proxies to test the e2e clients."""
import socket
import socketserver
import threading
import urllib.parse


def _pipe(a: socket.socket, b: socket.socket) -> None:
    def copy(src, dst):
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=copy, args=(b, a), daemon=True)
    t.start()
    copy(a, b)
    t.join()


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, handler, **opts):
        super().__init__(("127.0.0.1", 0), handler)
        self.opts = opts
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def address(self):
        return self.server_address

    def close(self):
        self.shutdown()
        self.server_close()


class _Socks5Handler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        _ver, n = _recv_exact(s, 2)
        _recv_exact(s, n)
        s.sendall(b"\x05\x00")
        _ver, _cmd, _rsv, atyp = _recv_exact(s, 4)
        assert atyp == 3, "client must send ATYP=domain"
        host = _recv_exact(s, _recv_exact(s, 1)[0]).decode()
        port = int.from_bytes(_recv_exact(s, 2), "big")
        fail = self.server.opts.get("fail_code")
        if fail:
            s.sendall(bytes([5, fail, 0, 1, 0, 0, 0, 0, 0, 0]))
            return
        up = socket.create_connection((host, port), timeout=10)
        s.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        _pipe(s, up)


class _HttpProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            head += _recv_exact(s, 1)
        method, target, _ = head.decode().split("\r\n")[0].split(" ")
        if method == "CONNECT":
            if self.server.opts.get("refuse"):
                s.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            host, port = target.rsplit(":", 1)
            up = socket.create_connection((host, int(port)), timeout=10)
            s.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            _pipe(s, up)
            return
        url = urllib.parse.urlsplit(target)
        up = socket.create_connection((url.hostname, url.port), timeout=10)
        up.sendall(f"GET {url.path or '/'} HTTP/1.1\r\nHost: {url.netloc}\r\nConnection: close\r\n\r\n".encode())
        _pipe(s, up)


def socks5_proxy(**opts) -> _Server:
    return _Server(_Socks5Handler, **opts)


def http_proxy(**opts) -> _Server:
    return _Server(_HttpProxyHandler, **opts)


def silent_server() -> tuple[socket.socket, tuple[str, int]]:
    """Accepts connections and never answers (a hung proxy)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    return srv, srv.getsockname()
```

- [ ] **Step 2: Write the failing tests**

`e2e/tests/test_clients.py`:
```python
import time

import pytest

from netbridge_e2e import clients
from netbridge_e2e.targets import PAGE, Targets
from tests import fakeproxy


@pytest.fixture
def targets():
    with Targets("127.0.0.1") as t:
        yield t


def test_socks5_http_get(targets):
    proxy = fakeproxy.socks5_proxy()
    try:
        with clients.socks5_connect(proxy.address, "127.0.0.1", targets.http_port) as s:
            assert clients.http_get(s, f"127.0.0.1:{targets.http_port}") == (200, PAGE)
    finally:
        proxy.close()


def test_socks5_refusal_carries_reply_code(targets):
    proxy = fakeproxy.socks5_proxy(fail_code=4)
    try:
        with pytest.raises(clients.ProxyError) as err:
            clients.socks5_connect(proxy.address, "127.0.0.1", targets.echo_port)
        assert err.value.code == 4
    finally:
        proxy.close()


def test_socks5_hung_proxy_times_out():
    srv, address = fakeproxy.silent_server()
    try:
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            clients.socks5_connect(address, "127.0.0.1", 9, timeout=1.0)
        assert time.monotonic() - start < 5
    finally:
        srv.close()


def test_http_connect_echo_large_block(targets):
    proxy = fakeproxy.http_proxy()
    data = bytes(range(256)) * 1024  # 256 KiB: larger than typical socket buffers
    try:
        with clients.http_connect(proxy.address, "127.0.0.1", targets.echo_port) as s:
            assert clients.echo_roundtrip(s, data) == data
    finally:
        proxy.close()


def test_http_connect_refusal_carries_status(targets):
    proxy = fakeproxy.http_proxy(refuse=True)
    try:
        with pytest.raises(clients.ProxyError) as err:
            clients.http_connect(proxy.address, "127.0.0.1", targets.echo_port)
        assert err.value.code == 403
    finally:
        proxy.close()


def test_http_forward_get(targets):
    proxy = fakeproxy.http_proxy()
    try:
        url = f"http://127.0.0.1:{targets.http_port}/"
        assert clients.http_forward_get(proxy.address, url) == (200, PAGE)
    finally:
        proxy.close()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd e2e && uv run pytest tests/test_clients.py -v`
Expected: FAIL — `ImportError: cannot import name 'clients'`.

- [ ] **Step 4: Implement**

`e2e/src/netbridge_e2e/clients.py`:
```python
"""Minimal SOCKS5 / HTTP-proxy clients (stdlib, so no curl-version surprises).

Every socket carries a timeout: a proxy that hangs fails the step instead
of hanging the gate.
"""
import socket
import threading
import urllib.parse

Address = tuple[str, int]


class ProxyError(Exception):
    """The proxy refused the request (SOCKS5 reply code / HTTP status, -1 = protocol error)."""

    def __init__(self, code: int, message: str):
        super().__init__(f"{message} (code {code})")
        self.code = code


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return bytes(buf)


def socks5_connect(proxy: Address, dest_host: str, dest_port: int, timeout: float = 15.0) -> socket.socket:
    """CONNECT with ATYP=domain, so the far side (the agent) resolves the name."""
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise ProxyError(-1, "SOCKS5 no-auth method rejected")
        host = dest_host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + dest_port.to_bytes(2, "big"))
        ver, rep, _rsv, atyp = recv_exact(sock, 4)
        if ver != 5:
            raise ProxyError(-1, f"bad SOCKS version {ver}")
        if rep != 0:
            raise ProxyError(rep, f"SOCKS5 CONNECT {dest_host}:{dest_port} refused")
        addr_len = {1: 4, 4: 16}.get(atyp) or recv_exact(sock, 1)[0]
        recv_exact(sock, addr_len + 2)
        return sock
    except BaseException:
        sock.close()
        raise


def _read_head(sock: socket.socket) -> tuple[int, dict[str, str]]:
    # byte by byte: never consume tunnel bytes that follow the header
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        head += recv_exact(sock, 1)
        if len(head) > 65536:
            raise ProxyError(-1, "response header too large")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return status, headers


def _read_response(sock: socket.socket) -> tuple[int, bytes]:
    status, headers = _read_head(sock)
    if "content-length" in headers:
        return status, recv_exact(sock, int(headers["content-length"]))
    body = bytearray()
    while chunk := sock.recv(65536):
        body += chunk
    return status, bytes(body)


def http_connect(proxy: Address, dest_host: str, dest_port: int, timeout: float = 15.0) -> socket.socket:
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        target = f"{dest_host}:{dest_port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        status, _ = _read_head(sock)
        if status != 200:
            raise ProxyError(status, f"HTTP CONNECT {target} refused")
        return sock
    except BaseException:
        sock.close()
        raise


def http_get(sock: socket.socket, host_header: str, path: str = "/") -> tuple[int, bytes]:
    """GET over an already-established tunnel."""
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode())
    return _read_response(sock)


def http_forward_get(proxy: Address, url: str, timeout: float = 15.0) -> tuple[int, bytes]:
    """Plain HTTP proxying: absolute-URI GET sent to the proxy."""
    host_header = urllib.parse.urlsplit(url).netloc
    with socket.create_connection(proxy, timeout=timeout) as sock:
        sock.sendall(f"GET {url} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode())
        return _read_response(sock)


def echo_roundtrip(sock: socket.socket, data: bytes) -> bytes:
    """Send and read back concurrently: large blocks would deadlock otherwise."""
    sender = threading.Thread(target=sock.sendall, args=(data,), daemon=True)
    sender.start()
    got = recv_exact(sock, len(data))
    sender.join()
    return got
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd e2e && uv run pytest tests/test_clients.py -v`
Expected: 6 passed.

- [ ] **Step 6: Commit**

```bash
git add e2e/src/netbridge_e2e/clients.py e2e/tests/fakeproxy.py e2e/tests/test_clients.py
git commit -m "Add stdlib SOCKS5 and HTTP-proxy clients for the e2e driver"
```

---

### Task 4: Process and log helpers

**Files:**
- Create: `e2e/src/netbridge_e2e/procs.py`
- Test: `e2e/tests/test_procs.py`

**Interfaces:**
- Produces: `procs.IS_WINDOWS: bool`; `procs.Proc(name: str, argv: list[str], log_path: Path, env: dict | None = None, cwd: Path | None = None)` with `start() -> Proc`, `alive() -> bool`, `stop(timeout: float = 10.0) -> None`, `.popen`; `procs.kill_image(image: str) -> None` (Windows only, no-op elsewhere); `procs.LogWatch(*patterns: Path)` with `files() -> list[Path]`, `mark() -> dict[Path, int]`, `text(since: dict[Path, int] | None = None) -> str`, `wait_for(pattern: str, timeout: float, since=None, alive=None) -> re.Match | None`, `tail(n: int = 1500) -> str`.

- [ ] **Step 1: Write the failing tests**

`e2e/tests/test_procs.py`:
```python
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
    time.sleep(0.5)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd e2e && uv run pytest tests/test_procs.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'netbridge_e2e.procs'`.

- [ ] **Step 3: Implement**

`e2e/src/netbridge_e2e/procs.py`:
```python
"""Process-tree and log helpers for everything the driver launches."""
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"


class Proc:
    """A process tree (uv run → python, PyInstaller bootloader → app) with its output in a file."""

    def __init__(self, name: str, argv: list[str], log_path: Path, env: dict | None = None, cwd: Path | None = None):
        self.name = name
        self.argv = argv
        self.log_path = log_path
        self.env = env
        self.cwd = cwd
        self.popen: subprocess.Popen | None = None
        self._log = None

    def start(self) -> "Proc":
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = open(self.log_path, "ab")
        group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if IS_WINDOWS else {"start_new_session": True}
        self.popen = subprocess.Popen(
            self.argv, cwd=self.cwd, env=self.env,
            stdin=subprocess.DEVNULL, stdout=self._log, stderr=subprocess.STDOUT, **group,
        )
        return self

    def alive(self) -> bool:
        return self.popen is not None and self.popen.poll() is None

    def stop(self, timeout: float = 10.0) -> None:
        if self.popen is None:
            return
        pid = self.popen.pid
        if IS_WINDOWS:
            if self.popen.poll() is None:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
        else:
            _killpg(pid, signal.SIGTERM)
        try:
            self.popen.wait(timeout)
        except subprocess.TimeoutExpired:
            if not IS_WINDOWS:
                _killpg(pid, signal.SIGKILL)
            self.popen.wait(timeout)
        if not IS_WINDOWS:
            _killpg(pid, signal.SIGKILL)  # stragglers left in the group
        if self._log:
            self._log.close()
            self._log = None


def _killpg(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def kill_image(image: str) -> None:
    """Kill every process with this image name (Windows; PyInstaller onefile leftovers)."""
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/F", "/T", "/IM", image], capture_output=True)


class LogWatch:
    """Poll one or more log files (paths or glob patterns) for a regex."""

    def __init__(self, *patterns: Path):
        self.patterns = patterns

    def files(self) -> list[Path]:
        found: list[Path] = []
        for p in self.patterns:
            if any(ch in p.name for ch in "*?["):
                found += sorted(p.parent.glob(p.name))
            elif p.exists():
                found.append(p)
        return found

    def mark(self) -> dict[Path, int]:
        return {f: f.stat().st_size for f in self.files()}

    def text(self, since: dict[Path, int] | None = None) -> str:
        parts = []
        for f in self.files():
            try:
                with open(f, "rb") as fh:
                    fh.seek((since or {}).get(f, 0))
                    parts.append(fh.read().decode("utf-8", errors="replace"))
            except OSError:
                continue
        return "".join(parts)

    def wait_for(self, pattern: str, timeout: float, since=None, alive=None) -> re.Match | None:
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while True:
            m = rx.search(self.text(since))
            if m:
                return m
            if time.monotonic() >= deadline or (alive is not None and not alive()):
                return None
            time.sleep(0.5)

    def tail(self, n: int = 1500) -> str:
        return self.text()[-n:]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd e2e && uv run pytest tests/test_procs.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add e2e/src/netbridge_e2e/procs.py e2e/tests/test_procs.py
git commit -m "Add process-tree and log-polling helpers for the e2e driver"
```

---

### Task 5: The stack — relay, source-mode and exe-mode components

**Files:**
- Create: `e2e/src/netbridge_e2e/stack.py`, `e2e/src/netbridge_e2e/winsys.py`
- Test: `e2e/tests/test_stack.py`

**Interfaces:**
- Consumes: `procs.Proc`, `procs.LogWatch`, `procs.kill_image`, `procs.IS_WINDOWS`.
- Produces:
  - `stack.REPO: Path`, `stack.CONNECTED = r"Status changed: \S+ -> connected"`
  - `stack.Relay(logs_dir: Path, port: int, blocked_port: int, env: dict)` — `.url -> str`, `.logs: LogWatch`, `start()`, `stop()`, `alive() -> bool`, `status() -> dict | None`, `wait_ready(timeout: float) -> bool`, `wait_paired(timeout: float) -> dict | None`
  - Component protocol (all of `SourceAgent`, `SourceProxy`, `ExeComponent`): `.name: str`, `.logs: LogWatch`, `install() -> str` (detail; raises `RuntimeError` on unusable environment), `start()`, `alive() -> bool`, `stop()`, `cleanup()`, `collect_logs(dest: Path)`; `ExeComponent` also `uninstall() -> tuple[bool, str]`
  - `stack.SourceAgent(work: Path, relay_url: str, env: dict)`, `stack.SourceProxy(work: Path, relay_url: str, socks_port: int, http_port: int, env: dict)`
  - `stack.make_exe_agent(exe: Path, relay_url: str, env: dict, work: Path, console: bool, allow_existing: bool) -> ExeComponent`
  - `stack.make_exe_proxy(exe: Path, relay_url: str, socks_port: int, http_port: int, probe_target: str, env: dict, work: Path, allow_existing: bool) -> ExeComponent`
  - `winsys.set_run_value(name: str, value: str)`, `winsys.delete_run_value(name: str)`, `winsys.run_value_exists(name: str) -> bool`, `winsys.click_messagebox_yes(title: str, timeout: float) -> bool`

- [ ] **Step 1: Write the failing tests**

`e2e/tests/test_stack.py`:
```python
import os
import socket
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


def test_relay_wait_ready_fails_fast_when_port_is_taken(tmp_path):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        r = stack.Relay(tmp_path, busy.getsockname()[1], blocked_port=1, env=dict(os.environ))
        r.start()
        try:
            start = time.monotonic()
            assert r.wait_ready(120) is False
            assert time.monotonic() - start < 60
        finally:
            r.stop()


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd relay && uv sync && cd ../e2e && uv run pytest tests/test_stack.py -v`
Expected: FAIL — `ImportError: cannot import name 'stack'`.

- [ ] **Step 3: Implement `winsys.py`**

`e2e/src/netbridge_e2e/winsys.py`:
```python
"""Windows-only helpers: the startup Run value and the uninstall confirmation."""
import ctypes
import time
import winreg
from ctypes import wintypes

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
WM_COMMAND = 0x0111
IDYES = 6

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
_user32.FindWindowW.restype = wintypes.HWND
_user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.PostMessageW.restype = wintypes.BOOL


def set_run_value(name: str, value: str) -> None:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


def delete_run_value(name: str) -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def run_value_exists(name: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, name)
        return True
    except FileNotFoundError:
        return False


def click_messagebox_yes(title: str, timeout: float) -> bool:
    """Answer "Yes" on the MessageBox (dialog class #32770) with this title."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hwnd = _user32.FindWindowW("#32770", title)
        if hwnd:
            return bool(_user32.PostMessageW(hwnd, WM_COMMAND, IDYES, 0))
        time.sleep(0.5)
    return False
```

- [ ] **Step 4: Implement `stack.py`**

`e2e/src/netbridge_e2e/stack.py`:
```python
"""The relay and the two clients.

source mode: everything from this checkout via `uv run` (any OS).
exe mode:    the PyInstaller exes, installed where their installers put
             them and launched from there in normal tray mode (Windows).
"""
import json
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

from .procs import LogWatch, Proc, kill_image

REPO = Path(__file__).resolve().parents[3]
TEST_TENANT = "11111111-1111-1111-1111-111111111111"
CONNECTED = r"Status changed: \S+ -> connected"
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


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
    def __init__(self, logs_dir: Path, port: int, blocked_port: int, env: dict):
        self.port = port
        self._logs_dir = logs_dir
        self._env = dict(env, NETBRIDGE_ALLOW_NO_AUTH="true", NETBRIDGE_ALLOWED_TENANTS=TEST_TENANT,
                         RELAY_BLOCKED_PORTS=str(blocked_port))
        self._runs = 0
        self.proc: Proc | None = None
        self.logs = LogWatch(logs_dir / "relay-*.log")

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}"

    def start(self) -> None:
        self._runs += 1
        argv = _uv("relay", "python", "-m", "relay", "--no-auth", "--host", "127.0.0.1", "--port", str(self.port))
        self.proc = Proc("relay", argv, self._logs_dir / f"relay-{self._runs}.log", env=self._env).start()

    def alive(self) -> bool:
        return self.proc is not None and self.proc.alive()

    def stop(self) -> None:
        if self.proc:
            self.proc.stop()

    def status(self) -> dict | None:
        try:
            with _NO_PROXY.open(f"http://127.0.0.1:{self.port}/status", timeout=3) as r:
                return json.loads(r.read())
        except (OSError, ValueError):
            return None

    def wait_ready(self, timeout: float) -> bool:
        return _poll(self.status, timeout, alive=self.alive) is not None

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

    def __init__(self, work: Path, relay_url: str, env: dict):
        self.name = "agent"
        self._relay_url = relay_url
        localappdata = work / "localappdata"
        self.app_dir = localappdata / "NetBridge"
        self._stdout = work / "logs" / "agent-stdout.log"
        self._env = dict(env, LOCALAPPDATA=str(localappdata))
        self.logs = LogWatch(self.app_dir / "logs" / "*.log", self._stdout)

    def install(self) -> str:
        self.app_dir.mkdir(parents=True, exist_ok=True)
        (self.app_dir / "config.json").write_text(json.dumps({"relay_url": self._relay_url, "auto_connect": True}, indent=2))
        return f"source agent, config in {self.app_dir}"

    def start(self) -> None:
        argv = _uv("netbridge-agent", "python", "-m", "netbridge_agent", "--console")
        self.proc = Proc("agent", argv, self._stdout, env=self._env).start()


class SourceProxy(_Component):
    """`netbridge-socks serve` from source, config dir isolated from the user's."""

    def __init__(self, work: Path, relay_url: str, socks_port: int, http_port: int, env: dict):
        self.name = "proxy"
        self._argv = _uv("socks-proxy", "netbridge-socks", "serve", "--relay", relay_url, "--host", "127.0.0.1",
                         "--port", str(socks_port), "--http-port", str(http_port), "--no-tray")
        self._stdout = work / "logs" / "proxy-stdout.log"
        self._env = dict(env, XDG_CONFIG_HOME=str(work / "xdg-config"))
        self.logs = LogWatch(self._stdout)

    def install(self) -> str:
        return "source proxy, CLI flags only"

    def start(self) -> None:
        self.proc = Proc("proxy", self._argv, self._stdout, env=self._env).start()


class ExeComponent(_Component):
    """An installed release exe, launched from its install location."""

    def __init__(self, *, name: str, source_exe: Path, app_name: str, exe_name: str, config: dict,
                 args: list[str], env: dict, work: Path, allow_existing: bool):
        self.name = name
        self.app_name = app_name
        self.source_exe = source_exe
        self.install_dir = Path(os.environ["LOCALAPPDATA"]) / app_name
        self.installed_exe = self.install_dir / exe_name
        self._config = config
        self._args = args
        self._env = env
        self._stdout = work / "logs" / f"{name}-stdout.log"
        self._allow_existing = allow_existing
        self._installed = False
        self._uninstalled = False
        self.logs = LogWatch(self.install_dir / "logs" / "*.log")

    def install(self) -> str:
        if self.install_dir.exists() and not self._allow_existing:
            raise RuntimeError(f"{self.install_dir} already exists; use --allow-existing-install on a disposable machine")
        from . import winsys
        self.install_dir.mkdir(parents=True, exist_ok=True)
        self._installed = True
        shutil.copy2(self.source_exe, self.installed_exe)
        (self.install_dir / "config.json").write_text(json.dumps(self._config, indent=2))
        winsys.set_run_value(self.app_name, f'"{self.installed_exe}"')  # what install_fresh registers
        return f"{self.installed_exe}"

    def start(self) -> None:
        self.proc = Proc(self.name, [str(self.installed_exe), *self._args], self._stdout, env=self._env).start()

    def stop(self) -> None:
        super().stop()
        kill_image(self.installed_exe.name)

    def uninstall(self) -> tuple[bool, str]:
        from . import winsys
        self.stop()
        p = subprocess.Popen([str(self.installed_exe), "--uninstall"], env=self._env)
        clicked = winsys.click_messagebox_yes(f"Uninstall {self.app_name}", timeout=30)
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


def make_exe_proxy(exe: Path, relay_url: str, socks_port: int, http_port: int, probe_target: str,
                   env: dict, work: Path, allow_existing: bool) -> ExeComponent:
    return ExeComponent(
        name="proxy", source_exe=exe, app_name="NetBridgeSocks", exe_name="netbridge-socks.exe",
        config={"relay_url": relay_url, "socks_port": socks_port, "http_port": http_port,
                "auto_connect": True, "probe_target": probe_target},
        args=[], env=env, work=work, allow_existing=allow_existing,
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd e2e && uv run pytest tests/test_stack.py -v`
Expected: 4 passed. (`winsys` is not imported on Linux: the refuse test raises before the lazy import.)

- [ ] **Step 6: Commit**

```bash
git add e2e/src/netbridge_e2e/stack.py e2e/src/netbridge_e2e/winsys.py e2e/tests/test_stack.py
git commit -m "Add e2e stack: no-auth relay, source and installed-exe components"
```

---

### Task 6: The journey, CLI entry point and a local source-mode run

**Files:**
- Create: `e2e/src/netbridge_e2e/journey.py`, `e2e/src/netbridge_e2e/__main__.py`
- Test: `e2e/tests/test_journey.py`

**Interfaces:**
- Consumes: everything from Tasks 1–5 with the exact names listed there.
- Produces: `journey.StepFailed(Exception)`, `journey.Journey(args: argparse.Namespace)` with `step(name, ok, detail="")`, `check(name, fn)`, `run() -> int`, `.results: list[dict]`, `.cleanups: list[Callable]`; `journey.parse_args(argv: list[str] | None) -> argparse.Namespace`; `journey.main(argv=None) -> int`. Summary file `<work>/e2e-summary.json` = `{"mode": str, "ok": bool, "steps": [{"step", "ok", "detail"}]}`.

- [ ] **Step 1: Write the failing tests**

`e2e/tests/test_journey.py`:
```python
import json

import pytest

from netbridge_e2e import journey


def make(tmp_path, body):
    args = journey.parse_args(["--mode", "source", "--work", str(tmp_path)])

    class J(journey.Journey):
        def _journey(self):
            body(self)

    return J(args)


def test_first_failure_stops_runs_cleanups_in_reverse_and_writes_summary(tmp_path):
    order = []

    def body(j):
        j.cleanups.append(lambda: order.append("first"))
        j.cleanups.append(lambda: order.append("second"))
        j.step("ok_step", True, "fine")
        j.step("bad_step", False, "broken")
        j.step("never", True)

    j = make(tmp_path, body)
    assert j.run() == 1
    assert order == ["second", "first"]
    summary = json.loads((tmp_path / "e2e-summary.json").read_text())
    assert summary["ok"] is False and summary["mode"] == "source"
    assert [s["step"] for s in summary["steps"]] == ["ok_step", "bad_step"]


def test_check_turns_exceptions_into_failures(tmp_path):
    def body(j):
        j.check("raises", lambda: (_ for _ in ()).throw(TimeoutError("hung")))

    j = make(tmp_path, body)
    assert j.run() == 1
    assert j.results[-1] == {"step": "raises", "ok": False, "detail": "TimeoutError: hung"}


def test_unexpected_driver_error_is_reported(tmp_path):
    def body(j):
        raise RuntimeError("boom")

    j = make(tmp_path, body)
    assert j.run() == 1
    assert j.results[-1]["step"] == "driver_error"
    assert "boom" in j.results[-1]["detail"]


def test_cleanup_errors_do_not_mask_success(tmp_path):
    def body(j):
        j.cleanups.append(lambda: 1 / 0)
        j.step("only", True)

    assert make(tmp_path, body).run() == 0


def test_exe_mode_requires_both_exes(tmp_path):
    with pytest.raises(SystemExit):
        journey.parse_args(["--mode", "exe", "--work", str(tmp_path)])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd e2e && uv run pytest tests/test_journey.py -v`
Expected: FAIL — `ImportError: cannot import name 'journey'`.

- [ ] **Step 3: Implement**

`e2e/src/netbridge_e2e/journey.py`:
```python
"""The E2E journey: every step must pass; the first failure stops the run.

  uv run --project e2e python -m netbridge_e2e --mode source
  uv run --project e2e python -m netbridge_e2e --mode exe --agent-exe netbridge.exe --proxy-exe netbridge-socks.exe

install → connect (relay pairs agent and proxy, fake az used) → SOCKS5 /
HTTP CONNECT / HTTP forward / 5 MiB / 20 parallel streams → relay port
filter → relay restart and reconnect → uninstall (exe mode).
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import clients, fakeaz, netinfo
from .procs import IS_WINDOWS
from .stack import CONNECTED, Relay, SourceAgent, SourceProxy, make_exe_agent, make_exe_proxy
from .targets import PAGE, PAYLOAD_SHA256, Targets


class StepFailed(Exception):
    pass


class Journey:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.work = Path(args.work).resolve()
        self.results: list[dict] = []
        self.cleanups: list = []
        self.socks = ("127.0.0.1", args.socks_port)
        self.http = ("127.0.0.1", args.http_port)

    # --- bookkeeping -------------------------------------------------------

    def step(self, name: str, ok, detail: str = "") -> None:
        self.results.append({"step": name, "ok": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}", flush=True)
        if not ok:
            raise StepFailed(name)

    def check(self, name: str, fn) -> None:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001 — any error is a failed step
            ok, detail = False, f"{type(e).__name__}: {e}"
        self.step(name, ok, detail)

    def run(self) -> int:
        self.work.mkdir(parents=True, exist_ok=True)
        code = 1
        try:
            self._journey()
            code = 0
        except StepFailed:
            pass
        except Exception as e:  # noqa: BLE001 — a driver bug fails the gate too
            self.results.append({"step": "driver_error", "ok": False, "detail": f"{type(e).__name__}: {e}"})
            print(f"FAIL  driver_error: {type(e).__name__}: {e}", flush=True)
        finally:
            for fn in reversed(self.cleanups):
                try:
                    fn()
                except Exception as e:  # noqa: BLE001
                    print(f"cleanup: {type(e).__name__}: {e}", flush=True)
            self._write_summary(code)
        return code

    def _write_summary(self, code: int) -> None:
        summary = {"mode": self.args.mode, "ok": code == 0, "steps": self.results}
        (self.work / "e2e-summary.json").write_text(json.dumps(summary, indent=2))
        print("\n==== E2E summary ====")
        for r in self.results:
            print(f"  {'✓' if r['ok'] else '✗'} {r['step']}: {r['detail']}")

    # --- the journey -------------------------------------------------------

    def _journey(self) -> None:
        a = self.args
        logs = self.work / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        ip = netinfo.private_ipv4()
        env = fakeaz.env_with_fake_az(os.environ, sys.executable, self.work / "az-calls.log")
        no_proxy = f"127.0.0.1,localhost,{ip}"
        env.update(NO_PROXY=no_proxy, no_proxy=no_proxy)

        self.check("fake_az", lambda: self._check_fake_az(env))

        targets = Targets(ip)
        self.cleanups.append(targets.close)
        self.step("targets_up", True, f"http {ip}:{targets.http_port}, echo :{targets.echo_port}, blocked :{targets.blocked_port}")

        relay = Relay(logs, a.relay_port, targets.blocked_port, env)
        self.cleanups.append(relay.stop)
        relay.start()
        self.step("relay_up", relay.wait_ready(180), f"{relay.url} {'' if relay.alive() else relay.logs.tail()}")

        agent, proxy = self._components(relay.url, ip, targets, env)
        for comp in (agent, proxy):
            self.cleanups.append(comp.cleanup)
            self.cleanups.append(lambda c=comp: c.collect_logs(logs))  # runs before cleanup
        self.step("install_agent", True, agent.install())
        self.step("install_proxy", True, proxy.install())

        for comp in (agent, proxy):
            comp.start()
            time.sleep(10)
            self.step(f"{comp.name}_started", comp.alive(), "running" if comp.alive() else comp.logs.tail())
        for comp in (agent, proxy):
            m = comp.logs.wait_for(CONNECTED, 120, alive=comp.alive)
            self.step(f"{comp.name}_connected", m is not None, m.group(0) if m else comp.logs.tail())
        paired = relay.wait_paired(30)
        self.step("relay_paired", paired is not None, json.dumps(paired or relay.status()))

        calls_log = self.work / "az-calls.log"
        calls = calls_log.read_text() if calls_log.exists() else ""
        n = calls.count("account get-access-token")
        self.step("az_called", n >= 2, f"{n} token requests went through the fake az")

        self._traffic(ip, targets)
        self._filter(ip, targets, relay)
        self._reconnect(relay, agent, proxy, ip, targets)

        if a.mode == "exe":
            for comp in (agent, proxy):
                comp.collect_logs(logs)  # uninstall deletes the install dir, logs included
                self.check(f"uninstall_{comp.name}", comp.uninstall)

    def _check_fake_az(self, env: dict) -> tuple[bool, str]:
        az = shutil.which("az.cmd" if IS_WINDOWS else "az", path=env["PATH"])
        if not az or Path(az).resolve().parent != fakeaz.FAKE_AZ_DIR:
            return False, f"az resolves to {az}, not the fake in {fakeaz.FAKE_AZ_DIR}"
        own = {k: v for k, v in env.items() if k != fakeaz.ENV_LOG}  # keep az_called counting the apps only
        out = subprocess.run([az, "account", "get-access-token", "--resource", "https://management.azure.com/"],
                             env=own, capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return False, f"exit {out.returncode}: {out.stderr.strip()}"
        left = fakeaz.token_seconds_left(json.loads(out.stdout)["accessToken"])
        return left > 600, f"{az} (token valid {left:.0f}s)"

    def _components(self, relay_url: str, ip: str, targets: Targets, env: dict):
        a = self.args
        if a.mode == "source":
            return (SourceAgent(self.work, relay_url, env),
                    SourceProxy(self.work, relay_url, a.socks_port, a.http_port, env))
        return (make_exe_agent(Path(a.agent_exe), relay_url, env, self.work,
                               console=a.agent_console, allow_existing=a.allow_existing_install),
                make_exe_proxy(Path(a.proxy_exe), relay_url, a.socks_port, a.http_port,
                               f"{ip}:{targets.http_port}", env, self.work, allow_existing=a.allow_existing_install))

    def _socks_get(self, ip: str, targets: Targets, path: str = "/", timeout: float = 15.0) -> tuple[int, bytes]:
        with clients.socks5_connect(self.socks, ip, targets.http_port, timeout=timeout) as s:
            return clients.http_get(s, f"{ip}:{targets.http_port}", path)

    def _traffic(self, ip: str, targets: Targets) -> None:
        def socks5_http():
            status, body = self._socks_get(ip, targets)
            return status == 200 and body == PAGE, f"HTTP {status}, {len(body)} bytes"

        def http_connect():
            data = b"netbridge-e2e-echo\n" * 1000
            with clients.http_connect(self.http, ip, targets.echo_port) as s:
                got = clients.echo_roundtrip(s, data)
            return got == data, f"{len(got)} bytes echoed"

        def http_forward():
            status, body = clients.http_forward_get(self.http, f"http://{ip}:{targets.http_port}/")
            return status == 200 and body == PAGE, f"HTTP {status}, {len(body)} bytes"

        def bulk_payload():
            status, body = self._socks_get(ip, targets, "/payload", timeout=60)
            digest = hashlib.sha256(body).hexdigest()
            return status == 200 and digest == PAYLOAD_SHA256, f"HTTP {status}, {len(body)} bytes, sha256 {digest[:16]}"

        def concurrency():
            def one(i: int) -> bool:
                data = hashlib.sha256(str(i).encode()).digest() * 2048  # 64 KiB, distinct per stream
                with clients.socks5_connect(self.socks, ip, targets.echo_port, timeout=60) as s:
                    return clients.echo_roundtrip(s, data) == data
            with ThreadPoolExecutor(20) as pool:
                results = list(pool.map(one, range(20)))
            return all(results), f"{sum(results)}/20 parallel streams round-tripped"

        self.check("socks5_http", socks5_http)
        self.check("http_connect", http_connect)
        self.check("http_forward", http_forward)
        self.check("bulk_payload", bulk_payload)
        self.check("concurrency", concurrency)

    def _filter(self, ip: str, targets: Targets, relay: Relay) -> None:
        def blocked():
            start = time.monotonic()
            try:
                sock = clients.socks5_connect(self.socks, ip, targets.blocked_port, timeout=30)
            except clients.ProxyError as e:
                logged = relay.logs.wait_for(rf"Blocked port {targets.blocked_port}\b", 5)
                return logged is not None, (f"SOCKS5 reply {e.code} after {time.monotonic() - start:.1f}s, "
                                            f"relay logged the block: {logged is not None}")
            sock.close()
            return False, f"connection to blocked port {targets.blocked_port} was allowed"

        self.check("relay_filter", blocked)

    def _reconnect(self, relay: Relay, agent, proxy, ip: str, targets: Targets) -> None:
        marks = {agent.name: agent.logs.mark(), proxy.name: proxy.logs.mark()}
        relay.stop()
        time.sleep(3)
        relay.start()
        self.step("relay_restarted", relay.wait_ready(60), relay.url)
        start = time.monotonic()
        last = "never paired"
        while time.monotonic() - start < 150:
            if relay.wait_paired(5):
                try:
                    status, body = self._socks_get(ip, targets)
                    if status == 200 and body == PAGE:
                        break
                    last = f"HTTP {status}"
                except Exception as e:  # noqa: BLE001 — retried until the deadline
                    last = f"{type(e).__name__}: {e}"
            time.sleep(2)
        else:
            self.step("reconnect", False, f"no working tunnel 150s after the restart ({last}; relay {relay.status()})")
        self.step("reconnect", True, f"traffic flows again {time.monotonic() - start:.0f}s after the restart")
        for comp in (agent, proxy):
            m = comp.logs.wait_for(CONNECTED, 10, since=marks[comp.name])
            self.step(f"{comp.name}_reconnected", m is not None, m.group(0) if m else comp.logs.tail())


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="netbridge_e2e", description="NetBridge end-to-end gate")
    p.add_argument("--mode", choices=["source", "exe"], required=True)
    p.add_argument("--work", default="e2e-work", help="reports, logs and state (default: ./e2e-work)")
    p.add_argument("--relay-port", type=int, default=18080)
    p.add_argument("--socks-port", type=int, default=11080)
    p.add_argument("--http-port", type=int, default=13128)
    p.add_argument("--agent-exe", help="exe mode: built netbridge.exe")
    p.add_argument("--proxy-exe", help="exe mode: built netbridge-socks.exe")
    p.add_argument("--agent-console", action="store_true",
                   help="exe mode: run the agent with --console instead of the tray")
    p.add_argument("--allow-existing-install", action="store_true",
                   help="exe mode: overwrite an existing installation (disposable machines only)")
    args = p.parse_args(argv)
    if args.mode == "exe":
        if not IS_WINDOWS:
            p.error("--mode exe runs on Windows only")
        for flag in ("agent_exe", "proxy_exe"):
            value = getattr(args, flag)
            if not value or not Path(value).is_file():
                p.error(f"--{flag.replace('_', '-')} must point to the built exe")
    return args


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # cp1252 consoles vs ✓/✗
    return Journey(parse_args(argv)).run()
```

Note on `test_exe_mode_requires_both_exes`: on Linux it exits via "runs on Windows only", on Windows via the missing-exe check — `SystemExit` either way.

`e2e/src/netbridge_e2e/__main__.py`:
```python
import sys

from .journey import main

sys.exit(main())
```

- [ ] **Step 4: Run unit tests to verify they pass**

Run: `cd e2e && uv run pytest -v`
Expected: all tests in `tests/` pass (4 + 4 + 6 + 5 + 4 + 5 = 28).

- [ ] **Step 5: Run the whole journey locally in source mode**

Precondition: nothing listening on 18080/11080/13128 (`ss -ltn | grep -E ':(18080|11080|13128)\b'` prints nothing). Pre-sync: `for p in relay netbridge-agent socks-proxy; do (cd $p && uv sync); done`.

Run: `uv run --project e2e python -m netbridge_e2e --mode source --work /tmp/nb-e2e`
Expected: exit 0; summary lists PASS for `fake_az, targets_up, relay_up, install_agent, install_proxy, agent_started, proxy_started, agent_connected, proxy_connected, relay_paired, az_called, socks5_http, http_connect, http_forward, bulk_payload, concurrency, relay_filter, relay_restarted, reconnect, agent_reconnected, proxy_reconnected`. Afterwards `pgrep -af 'relay --no-auth|netbridge_agent --console|netbridge-socks serve --relay ws://127.0.0.1:18080'` prints nothing (cleanup worked).

If a marker or behaviour differs from the plan (e.g. the source proxy never logs `-> connected`), inspect `/tmp/nb-e2e/logs/` and fix the driver, not the product.

- [ ] **Step 6: Commit**

```bash
git add e2e/src/netbridge_e2e/journey.py e2e/src/netbridge_e2e/__main__.py e2e/tests/test_journey.py
git commit -m "Add the e2e journey: connect, traffic, filter, reconnect, uninstall"
```

---

### Task 7: CI and release wiring

**Files:**
- Modify: `.github/workflows/ci.yml` (add job `e2e-source`)
- Create: `.github/workflows/e2e-windows.yml`
- Modify: `.github/workflows/release-agent.yml`, `.github/workflows/release-socks-exe.yml`

**Interfaces:**
- Consumes: CLI from Task 6 (`python -m netbridge_e2e --mode source|exe ...`).
- Produces: reusable workflow `./.github/workflows/e2e-windows.yml` with `workflow_call` input `version` (string, default `""`), uploading artifact **`netbridge-exes`** (flat: `netbridge.exe`, `netbridge-socks.exe`) only when the journey passed, and **`e2e-windows-report`** always.

- [ ] **Step 1: Add the source-mode job to `ci.yml`** (append under `jobs:`)

```yaml
  e2e-source:
    runs-on: ubuntu-latest
    timeout-minutes: 20

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"

      - uses: astral-sh/setup-uv@v5

      - name: Install system dependencies for socks-proxy tray
        run: sudo apt-get update && sudo apt-get install -y libgirepository-2.0-dev libcairo2-dev

      - name: Sync components
        run: for p in relay netbridge-agent socks-proxy e2e; do (cd "$p" && uv sync); done

      - name: Test the E2E driver
        run: |
          cd e2e
          uv run pytest

      - name: E2E journey (source mode)
        run: uv run --project e2e python -m netbridge_e2e --mode source --work "$RUNNER_TEMP/e2e"

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: e2e-source-report
          path: ${{ runner.temp }}/e2e
          if-no-files-found: ignore
```

- [ ] **Step 2: Create `.github/workflows/e2e-windows.yml`**

```yaml
name: E2E Windows

# Builds both Windows exes from this commit, smoke-tests them, then drives
# the INSTALLED exes (tray mode, fake az, local --no-auth relay) through the
# e2e journey. Release workflows call it and publish the tested artifact.
on:
  workflow_call:
    inputs:
      version:
        description: Version to inject into both exes (empty = 0.0.0 dev build)
        type: string
        default: ""
  pull_request:
    paths:
      - "relay/**"
      - "shared/**"
      - "socks-proxy/**"
      - "socks-proxy-win/**"
      - "netbridge-agent/**"
      - "e2e/**"
      - ".github/workflows/e2e-windows.yml"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  windows-exe:
    runs-on: windows-latest
    timeout-minutes: 45

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"

      - uses: astral-sh/setup-uv@v5

      - name: Inject version
        if: ${{ inputs.version }}
        shell: bash
        env:
          VERSION: ${{ inputs.version }}
        run: |
          if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
            echo "::error::Invalid version format: $VERSION"
            exit 1
          fi
          for f in netbridge-agent/src/netbridge_agent/__init__.py socks-proxy/src/socks_proxy/__init__.py socks-proxy-win/src/socks_proxy_win/__init__.py; do
            sed -i "s|__version__ = .*|__version__ = \"${VERSION}\"|" "$f"
          done

      - name: Build agent exe
        run: |
          cd netbridge-agent
          uv sync
          uv run pyinstaller netbridge-agent.spec --clean --noconfirm

      - name: Build socks exe
        run: |
          cd socks-proxy-win
          uv sync
          uv run pyinstaller netbridge-socks.spec --clean --noconfirm

      - name: Smoke test exes (--version, --import-check)
        shell: pwsh
        run: |
          foreach ($exe in @("netbridge-agent/dist/netbridge.exe", "socks-proxy-win/dist/netbridge-socks.exe")) {
            foreach ($flag in @("--version", "--import-check")) {
              $output = & $exe $flag 2>&1
              Write-Host "$exe $flag -> $output"
              if ($LASTEXITCODE -ne 0) { throw "$exe $flag failed (exit code $LASTEXITCODE): $output" }
            }
          }

      - name: Sync relay and driver
        run: |
          cd relay
          uv sync
          cd ../e2e
          uv sync

      - name: Test the E2E driver
        run: |
          cd e2e
          uv run pytest

      - name: E2E journey (installed exes)
        run: >
          uv run --project e2e python -m netbridge_e2e --mode exe
          --agent-exe netbridge-agent/dist/netbridge.exe
          --proxy-exe socks-proxy-win/dist/netbridge-socks.exe
          --work "${{ runner.temp }}/e2e"

      - name: Stage tested exes
        shell: bash
        run: |
          mkdir -p out
          cp netbridge-agent/dist/netbridge.exe socks-proxy-win/dist/netbridge-socks.exe out/

      - uses: actions/upload-artifact@v4
        with:
          name: netbridge-exes
          path: out/
          if-no-files-found: error

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: e2e-windows-report
          path: ${{ runner.temp }}/e2e
          if-no-files-found: ignore
```

- [ ] **Step 3: Rewrite `release-agent.yml`**

```yaml
name: Release Agent

on:
  push:
    tags: ["agent-v*"]

permissions:
  contents: write

jobs:
  prepare:
    runs-on: windows-latest
    outputs:
      version: ${{ steps.version.outputs.version }}

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.14"

      - uses: astral-sh/setup-uv@v5

      - name: Get version
        id: version
        shell: bash
        run: |
          VERSION=${GITHUB_REF_NAME#agent-v}
          if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
            echo "::error::Invalid version format: $VERSION"
            exit 1
          fi
          echo "version=${VERSION}" >> "$GITHUB_OUTPUT"

      - name: Run tests
        run: |
          cd netbridge-agent
          uv sync --group dev
          uv run pytest

  e2e:
    needs: prepare
    uses: ./.github/workflows/e2e-windows.yml
    with:
      version: ${{ needs.prepare.outputs.version }}

  publish:
    needs: [prepare, e2e]
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/download-artifact@v4
        with:
          name: netbridge-exes
          path: dist

      - uses: softprops/action-gh-release@v2
        with:
          files: dist/netbridge.exe
          generate_release_notes: true
          name: Agent v${{ needs.prepare.outputs.version }}

      - name: Update latest release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          # Create the 'latest' release if it doesn't exist
          gh release view latest >/dev/null 2>&1 || \
            gh release create latest --title "Latest Installers" --notes "Always-updated release with the latest Windows installers." --latest
          # Replace the exe in the latest release
          gh release upload latest dist/netbridge.exe --clobber
```

- [ ] **Step 4: Rewrite `release-socks-exe.yml`** (same shape; no unit-test step existed before, keep it that way)

```yaml
name: Release Socks Exe

on:
  push:
    tags: ["socks-exe-v*"]

permissions:
  contents: write

jobs:
  prepare:
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.version.outputs.version }}

    steps:
      - name: Get version
        id: version
        run: |
          VERSION=${GITHUB_REF_NAME#socks-exe-v}
          if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
            echo "::error::Invalid version format: $VERSION"
            exit 1
          fi
          echo "version=${VERSION}" >> "$GITHUB_OUTPUT"

  e2e:
    needs: prepare
    uses: ./.github/workflows/e2e-windows.yml
    with:
      version: ${{ needs.prepare.outputs.version }}

  publish:
    needs: [prepare, e2e]
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/download-artifact@v4
        with:
          name: netbridge-exes
          path: dist

      - uses: softprops/action-gh-release@v2
        with:
          files: dist/netbridge-socks.exe
          generate_release_notes: true
          name: Socks Proxy v${{ needs.prepare.outputs.version }}

      - name: Update latest release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          # Create the 'latest' release if it doesn't exist
          gh release view latest >/dev/null 2>&1 || \
            gh release create latest --title "Latest Installers" --notes "Always-updated release with the latest Windows installers." --latest
          # Replace the exe in the latest release
          gh release upload latest dist/netbridge-socks.exe --clobber
```

- [ ] **Step 5: Validate the workflows**

Run: `uvx --from actionlint-py actionlint .github/workflows/*.yml`
Expected: no errors. (If `actionlint-py` cannot be fetched, at least parse: `uv run --with pyyaml python -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]"`.)

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml .github/workflows/e2e-windows.yml .github/workflows/release-agent.yml .github/workflows/release-socks-exe.yml
git commit -m "Gate Windows releases on the installed-exe e2e journey; run source e2e in CI"
```

---

### Task 8: Documentation

**Files:**
- Create: `e2e/README.md`
- Modify: `README.md` (new section before "## Configuration")

- [ ] **Step 1: Write `e2e/README.md`**

````markdown
# End-to-end gate

Drives the whole path — client → proxy (SOCKS5 `:11080`, HTTP `:13128`) → relay → agent → target — and fails on the first broken promise. Reports: `<work>/e2e-summary.json` plus every component's logs in `<work>/logs/`.

| Mode | What runs | Where |
|------|-----------|-------|
| `source` | relay, agent (`--console`) and `netbridge-socks serve` from this checkout | any OS; CI job `e2e-source` on every push/PR |
| `exe` | the PyInstaller `netbridge.exe` / `netbridge-socks.exe`, installed to `%LOCALAPPDATA%` and started from there in tray mode | Windows; workflow `e2e-windows.yml` on PRs and before every Windows release |

No Azure is involved: the relay runs with `--no-auth` on loopback, and a fake `az` placed first on `PATH` hands the apps a dummy token, so their real auth code path still runs. Targets listen on the machine's default-route IPv4 because the agent always blocks loopback.

## Run locally

```bash
for p in relay netbridge-agent socks-proxy e2e; do (cd "$p" && uv sync); done
uv run --project e2e python -m netbridge_e2e --mode source --work /tmp/nb-e2e
```

Windows, with built exes (refuses to touch an existing installation unless `--allow-existing-install`):

```powershell
uv run --project e2e python -m netbridge_e2e --mode exe `
  --agent-exe netbridge-agent\dist\netbridge.exe `
  --proxy-exe socks-proxy-win\dist\netbridge-socks.exe --work $env:TEMP\nb-e2e
```

Ports: `--relay-port` (18080), `--socks-port` (11080), `--http-port` (13128). `--agent-console` runs the agent with `--console` instead of the tray.

## Steps

`fake_az` → `targets_up` → `relay_up` → `install_agent` / `install_proxy` → `*_started` → `*_connected` → `relay_paired` → `az_called` → `socks5_http` → `http_connect` → `http_forward` → `bulk_payload` (5 MiB, sha256) → `concurrency` (20 streams) → `relay_filter` (`RELAY_BLOCKED_PORTS`) → `relay_restarted` → `reconnect` → `*_reconnected` → `uninstall_*` (exe mode; the driver clicks "Yes" on the confirmation).

Driver unit tests: `cd e2e && uv run pytest`.
````

- [ ] **Step 2: Add to root `README.md`** (insert before `## Configuration`)

```markdown
## End-to-end tests

`e2e/` drives the full client → proxy → relay → agent → target path. CI runs it from source on Linux for every push, and against the installed Windows exes (`e2e-windows.yml`) on PRs and before every Windows release; releases publish exactly the exe that passed. See [e2e/README.md](e2e/README.md).
```

- [ ] **Step 3: Commit**

```bash
git add e2e/README.md README.md
git commit -m "Document the e2e gate"
```
