# Remote Exec Intercept Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users execute commands and manage files on the VDI through the existing netbridge tunnel, without running any HTTP server or binding any port. The agent intercepts `tcp_connect` requests for magic hostnames (`netbridge-exec`) and handles them internally with an in-process HTTP handler. Remote exec is toggled from the VDI tray (always OFF at startup, auto-disables after 1 hour, purple icon when active).

**Architecture:** When a `tcp_connect` arrives for a `netbridge-*` hostname, the agent short-circuits the normal TCP flow and instead pipes the stream through an internal `aiohttp` application. The tray gets a new checked menu item that toggles a runtime-only flag on `NetBridgeApp`. The tray icon turns purple when exec is enabled. A 1-hour asyncio timer auto-disables it. All exec handlers catch exceptions so they never crash the WebSocket loop. A new "Open Install Folder" tray item opens the netbridge installation directory.

**Tech Stack:** Python 3.10+, aiohttp (already a dependency), asyncio, pystray, PIL

---

## File Structure

| File | Responsibility |
|------|---------------|
| `remote_exec.py` (new) | In-process aiohttp app with health/file/exec handlers. `create_app()` returns an `aiohttp.web.Application`. No server startup — the app is used directly via `TestClient`-style internal routing. |
| `intercept.py` (new) | Stream intercept logic. When a `tcp_connect` arrives for `netbridge-exec`, creates a pair of asyncio streams, pipes data between the WebSocket stream and the internal HTTP app. |
| `agent.py` (modify) | In `handle_tcp_connect`, check hostname against magic prefix before opening a real TCP connection. Delegate to `intercept.py` when matched. Pass `remote_exec_enabled` flag from app. |
| `app.py` (modify) | Add `_remote_exec_enabled` runtime flag, `request_toggle_remote_exec()`, 1-hour auto-disable timer, pass flag to agent state. |
| `tray.py` (modify) | Add "Remote Exec" checked menu item with purple icon override, add "Open Install Folder" item. |
| `config.py` (modify) | Add `get_install_dir()` helper (same as `get_app_dir()`). |
| `__main__.py` (modify) | Add `remote_exec, intercept` to `--import-check`. |
| `tests/test_remote_exec.py` (new) | Tests for all HTTP handlers. |
| `tests/test_intercept.py` (new) | Tests for stream intercept and magic hostname matching. |
| `tests/test_tray_remote_exec.py` (new) | Tests for tray toggle, icon override, auto-disable timer. |

---

### Task 1: Remote Exec HTTP Handlers

**Files:**
- Create: `netbridge-agent/src/netbridge_agent/remote_exec.py`
- Create: `netbridge-agent/tests/test_remote_exec.py`

This task creates the aiohttp application with all handlers from `vdi-remote.py`, adapted as a module (no `main()`, no standalone server). All handlers catch exceptions and return JSON error responses.

- [ ] **Step 1: Write failing tests for the health endpoint**

```python
# tests/test_remote_exec.py
import json
import pytest
from aiohttp.test_utils import AioHTTPTestCase, TestClient
from netbridge_agent.remote_exec import create_app


@pytest.fixture
def client(aiohttp_client):
    app = create_app()
    return aiohttp_client(app)


class TestHealth:
    @pytest.mark.asyncio
    async def test_health_returns_ok(self, client):
        c = await client
        resp = await c.get("/health")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"
        assert "hostname" in data
        assert "pid" in data
        assert "cwd" in data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd netbridge-agent && uv run pytest tests/test_remote_exec.py::TestHealth -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'netbridge_agent.remote_exec'`

- [ ] **Step 3: Write failing tests for file list endpoint**

```python
class TestFileList:
    @pytest.mark.asyncio
    async def test_list_existing_directory(self, client, tmp_path):
        c = await client
        (tmp_path / "hello.txt").write_text("hi")
        (tmp_path / "subdir").mkdir()
        resp = await c.get(f"/files?dir={tmp_path}")
        assert resp.status == 200
        data = await resp.json()
        assert data["dir"] == str(tmp_path)
        names = [e["name"] for e in data["entries"]]
        assert "hello.txt" in names
        assert "subdir" in names

    @pytest.mark.asyncio
    async def test_list_nonexistent_directory(self, client):
        c = await client
        resp = await c.get("/files?dir=/nonexistent_path_xyz")
        assert resp.status == 404
```

- [ ] **Step 4: Write failing tests for file read/write/delete endpoints**

```python
class TestFileReadWriteDelete:
    @pytest.mark.asyncio
    async def test_read_file(self, client, tmp_path):
        c = await client
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        resp = await c.get(f"/files/{f}")
        assert resp.status == 200
        body = await resp.read()
        assert body == b"hello world"

    @pytest.mark.asyncio
    async def test_read_nonexistent(self, client):
        c = await client
        resp = await c.get("/files/nonexistent_xyz_123")
        assert resp.status == 404

    @pytest.mark.asyncio
    async def test_write_file(self, client, tmp_path):
        c = await client
        target = tmp_path / "output.txt"
        resp = await c.put(f"/files/{target}", data=b"content here")
        assert resp.status == 200
        data = await resp.json()
        assert data["ok"] is True
        assert target.read_text() == "content here"

    @pytest.mark.asyncio
    async def test_write_creates_parent_dirs(self, client, tmp_path):
        c = await client
        target = tmp_path / "a" / "b" / "deep.txt"
        resp = await c.put(f"/files/{target}", data=b"deep")
        assert resp.status == 200
        assert target.read_text() == "deep"

    @pytest.mark.asyncio
    async def test_delete_file(self, client, tmp_path):
        c = await client
        f = tmp_path / "doomed.txt"
        f.write_text("bye")
        resp = await c.delete(f"/files/{f}")
        assert resp.status == 200
        assert not f.exists()

    @pytest.mark.asyncio
    async def test_delete_directory(self, client, tmp_path):
        c = await client
        d = tmp_path / "doomed_dir"
        d.mkdir()
        (d / "inner.txt").write_text("x")
        resp = await c.delete(f"/files/{d}")
        assert resp.status == 200
        assert not d.exists()

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, client):
        c = await client
        resp = await c.delete("/files/nonexistent_xyz_456")
        assert resp.status == 404
```

- [ ] **Step 5: Write failing tests for exec endpoint**

```python
class TestExec:
    @pytest.mark.asyncio
    async def test_exec_simple_command(self, client):
        c = await client
        import sys
        if sys.platform == "win32":
            cmd = "echo hello"
        else:
            cmd = "echo hello"
        resp = await c.post("/exec", json={"cmd": cmd})
        assert resp.status == 200
        data = await resp.json()
        assert data["exit_code"] == 0
        assert "hello" in data["stdout"]

    @pytest.mark.asyncio
    async def test_exec_missing_cmd(self, client):
        c = await client
        resp = await c.post("/exec", json={})
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_exec_invalid_json(self, client):
        c = await client
        resp = await c.post("/exec", data=b"not json",
                           headers={"Content-Type": "application/json"})
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_exec_timeout(self, client):
        c = await client
        import sys
        if sys.platform == "win32":
            cmd = "ping -n 10 127.0.0.1"
        else:
            cmd = "sleep 10"
        resp = await c.post("/exec", json={"cmd": cmd, "timeout": 1})
        assert resp.status == 504
```

- [ ] **Step 6: Write failing tests for exec/stream endpoint**

```python
class TestExecStream:
    @pytest.mark.asyncio
    async def test_stream_simple_command(self, client):
        c = await client
        import sys
        if sys.platform == "win32":
            cmd = "echo streamed"
        else:
            cmd = "echo streamed"
        resp = await c.post("/exec/stream", json={"cmd": cmd})
        assert resp.status == 200
        body = await resp.text()
        assert "streamed" in body
        assert "exit code:" in body

    @pytest.mark.asyncio
    async def test_stream_missing_cmd(self, client):
        c = await client
        resp = await c.post("/exec/stream", json={})
        assert resp.status == 400
```

- [ ] **Step 7: Run all tests to verify they fail**

Run: `cd netbridge-agent && uv run pytest tests/test_remote_exec.py -v`
Expected: FAIL — module not found

- [ ] **Step 8: Implement `remote_exec.py`**

```python
# netbridge-agent/src/netbridge_agent/remote_exec.py
import asyncio
import logging
import os
import shutil
import socket

from aiohttp import web

LOG = logging.getLogger(__name__)


def _resolve_path(raw: str) -> str:
    if os.path.isabs(raw):
        return os.path.normpath(raw)
    return os.path.normpath(os.path.join(os.getcwd(), raw))


async def handle_health(request: web.Request) -> web.Response:
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "unknown"
    return web.json_response({
        "status": "ok",
        "hostname": hostname,
        "ip": local_ip,
        "cwd": os.getcwd(),
        "pid": os.getpid(),
    })


async def handle_file_list(request: web.Request) -> web.Response:
    dir_path = _resolve_path(request.query.get("dir", os.getcwd()))
    if not os.path.isdir(dir_path):
        return web.json_response({"error": f"not a directory: {dir_path}"}, status=404)
    entries = []
    for name in sorted(os.listdir(dir_path)):
        full = os.path.join(dir_path, name)
        entry = {"name": name, "is_dir": os.path.isdir(full)}
        try:
            st = os.stat(full)
            entry["size"] = st.st_size
            entry["mtime"] = int(st.st_mtime)
        except OSError:
            pass
        entries.append(entry)
    return web.json_response({"dir": dir_path, "entries": entries})


async def handle_file_read(request: web.Request) -> web.Response:
    file_path = _resolve_path(request.match_info["path"])
    if not os.path.isfile(file_path):
        return web.json_response({"error": f"not found: {file_path}"}, status=404)
    return web.FileResponse(file_path)


async def handle_file_write(request: web.Request) -> web.Response:
    file_path = _resolve_path(request.match_info["path"])
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    data = await request.read()
    with open(file_path, "wb") as f:
        f.write(data)
    LOG.info("Written: %s (%d bytes)", file_path, len(data))
    return web.json_response({"ok": True, "path": file_path, "size": len(data)})


async def handle_file_delete(request: web.Request) -> web.Response:
    file_path = _resolve_path(request.match_info["path"])
    if not os.path.exists(file_path):
        return web.json_response({"error": f"not found: {file_path}"}, status=404)
    if os.path.isdir(file_path):
        shutil.rmtree(file_path)
    else:
        os.remove(file_path)
    LOG.info("Deleted: %s", file_path)
    return web.json_response({"ok": True, "path": file_path})


async def handle_exec(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON body"}, status=400)

    cmd = body.get("cmd")
    if not cmd:
        return web.json_response({"error": "missing 'cmd'"}, status=400)

    cwd = body.get("cwd", os.getcwd())
    timeout = body.get("timeout", 300)

    LOG.info("exec: %s (cwd=%s, timeout=%ds)", cmd, cwd, timeout)
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return web.json_response({
            "exit_code": proc.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        })
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return web.json_response({"error": f"timed out after {timeout}s"}, status=504)
    except Exception as e:
        LOG.exception("exec failed")
        return web.json_response({"error": str(e)}, status=500)


async def handle_exec_stream(request: web.Request) -> web.StreamResponse:
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON body"}, status=400)

    cmd = body.get("cmd")
    if not cmd:
        return web.json_response({"error": "missing 'cmd'"}, status=400)

    cwd = body.get("cwd", os.getcwd())
    timeout = body.get("timeout", 600)

    LOG.info("exec/stream: %s (cwd=%s, timeout=%ds)", cmd, cwd, timeout)

    resp = web.StreamResponse()
    resp.content_type = "text/plain; charset=utf-8"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    await resp.prepare(request)

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
        )

        async def _read_stream():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                await resp.write(line)

        await asyncio.wait_for(_read_stream(), timeout=timeout)
        await proc.wait()
        await resp.write(f"\n--- exit code: {proc.returncode} ---\n".encode("utf-8"))
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        await resp.write(f"\n--- timed out after {timeout}s ---\n".encode("utf-8"))
    except Exception as e:
        await resp.write(f"\n--- error: {e} ---\n".encode("utf-8"))

    await resp.write_eof()
    return resp


def create_app() -> web.Application:
    app = web.Application(client_max_size=50 * 1024 * 1024)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/files", handle_file_list)
    app.router.add_get("/files/{path:.+}", handle_file_read)
    app.router.add_put("/files/{path:.+}", handle_file_write)
    app.router.add_delete("/files/{path:.+}", handle_file_delete)
    app.router.add_post("/exec", handle_exec)
    app.router.add_post("/exec/stream", handle_exec_stream)
    return app
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `cd netbridge-agent && uv run pytest tests/test_remote_exec.py -v`
Expected: All PASS

- [ ] **Step 10: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/remote_exec.py netbridge-agent/tests/test_remote_exec.py
git commit -m "feat(agent): add remote exec HTTP handlers module"
```

---

### Task 2: Stream Intercept for Magic Hostnames

**Files:**
- Create: `netbridge-agent/src/netbridge_agent/intercept.py`
- Create: `netbridge-agent/tests/test_intercept.py`
- Modify: `netbridge-agent/src/netbridge_agent/agent.py:211-224` (AgentState — add `remote_exec_enabled`)
- Modify: `netbridge-agent/src/netbridge_agent/agent.py:406-522` (handle_tcp_connect — add intercept check)

The intercept module bridges a WebSocket-tunneled stream to the internal aiohttp app. When `handle_tcp_connect` sees `host == "netbridge-exec"`, it creates a pair of asyncio streams (one side for the WebSocket data, one for the HTTP app), runs the HTTP request through the app, and sends responses back through the tunnel. The key challenge: the tunnel protocol sends raw TCP bytes (base64-encoded), so the intercept must act as a minimal TCP<->HTTP bridge.

The simplest correct approach: use `aiohttp.test_utils.TestServer` to start the app on a random local port, then connect to that port internally. This avoids reimplementing HTTP framing. The `TestServer` binds to a random port on 127.0.0.1 — but since the agent controls when it starts/stops and the port is ephemeral, there's negligible collision risk. The server only runs while remote exec is enabled.

- [ ] **Step 1: Write failing tests for magic hostname detection**

```python
# tests/test_intercept.py
import pytest
from netbridge_agent.intercept import is_magic_hostname, MAGIC_HOSTS


class TestMagicHostname:
    def test_netbridge_exec_is_magic(self):
        assert is_magic_hostname("netbridge-exec") is True

    def test_regular_hostname_is_not_magic(self):
        assert is_magic_hostname("google.com") is False

    def test_ip_address_is_not_magic(self):
        assert is_magic_hostname("127.0.0.1") is False

    def test_case_insensitive(self):
        assert is_magic_hostname("NETBRIDGE-EXEC") is True
        assert is_magic_hostname("Netbridge-Exec") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd netbridge-agent && uv run pytest tests/test_intercept.py::TestMagicHostname -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write failing tests for intercept server lifecycle**

```python
class TestInterceptServer:
    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        from netbridge_agent.intercept import InterceptServer
        server = InterceptServer()
        await server.start()
        assert server.port is not None
        assert server.port > 0
        await server.stop()

    @pytest.mark.asyncio
    async def test_health_through_intercept(self):
        from netbridge_agent.intercept import InterceptServer
        import aiohttp
        server = InterceptServer()
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://127.0.0.1:{server.port}/health") as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["status"] == "ok"
        finally:
            await server.stop()
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd netbridge-agent && uv run pytest tests/test_intercept.py::TestInterceptServer -v`
Expected: FAIL

- [ ] **Step 5: Implement `intercept.py`**

```python
# netbridge-agent/src/netbridge_agent/intercept.py
import logging
from typing import Optional

from aiohttp import web

from .remote_exec import create_app

LOG = logging.getLogger(__name__)

MAGIC_HOSTS = {"netbridge-exec"}


def is_magic_hostname(host: str) -> bool:
    return host.lower() in MAGIC_HOSTS


class InterceptServer:
    """In-process HTTP server for intercepted magic-hostname streams.

    Runs the remote_exec aiohttp app on an ephemeral loopback port.
    The agent connects intercepted streams to this port instead of
    opening real TCP connections.
    """

    def __init__(self) -> None:
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self.port: Optional[int] = None

    async def start(self) -> None:
        app = create_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await self._site.start()
        # Extract the actual port from the bound socket
        sockets = self._site._server.sockets
        self.port = sockets[0].getsockname()[1]
        LOG.info("Intercept server started on 127.0.0.1:%d", self.port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            LOG.info("Intercept server stopped")
            self.port = None
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd netbridge-agent && uv run pytest tests/test_intercept.py -v`
Expected: All PASS

- [ ] **Step 7: Write failing test for agent intercept integration**

```python
# tests/test_intercept.py (append)
from unittest.mock import AsyncMock, patch
from netbridge_agent.agent import AgentState, handle_tcp_connect


class TestAgentIntercept:
    @pytest.mark.asyncio
    async def test_magic_host_rejected_when_disabled(self):
        state = AgentState()
        state.remote_exec_enabled = False
        ws = AsyncMock()

        await handle_tcp_connect(state, ws, {
            "type": "tcp_connect",
            "stream_id": "test-123",
            "host": "netbridge-exec",
            "port": 80,
        })

        ws.send_str.assert_called_once()
        import json
        sent = json.loads(ws.send_str.call_args[0][0])
        assert sent["success"] is False
        assert "not allowed" in sent["error"].lower() or "disabled" in sent["error"].lower()

    @pytest.mark.asyncio
    async def test_magic_host_uses_intercept_when_enabled(self):
        state = AgentState()
        state.remote_exec_enabled = True

        from netbridge_agent.intercept import InterceptServer
        state.intercept_server = InterceptServer()
        await state.intercept_server.start()

        ws = AsyncMock()

        try:
            await handle_tcp_connect(state, ws, {
                "type": "tcp_connect",
                "stream_id": "test-456",
                "host": "netbridge-exec",
                "port": 80,
            })

            import json
            sent = json.loads(ws.send_str.call_args[0][0])
            assert sent["success"] is True
        finally:
            await state.intercept_server.stop()
```

- [ ] **Step 8: Run test to verify it fails**

Run: `cd netbridge-agent && uv run pytest tests/test_intercept.py::TestAgentIntercept -v`
Expected: FAIL — `AgentState` has no `remote_exec_enabled`

- [ ] **Step 9: Modify `agent.py` — add intercept support**

Add to `AgentState.__init__` (after line 224):
```python
self.remote_exec_enabled: bool = False
self.intercept_server: Optional["InterceptServer"] = None
```

Add the `Optional` import for `InterceptServer` at the type level — use a string annotation to avoid circular imports.

Modify `handle_tcp_connect` — insert this block after the `validate_destination` check (after line 449) and before the `logger.info(f"Connect: ...")` line:

```python
    # Intercept magic hostnames (e.g. netbridge-exec)
    from .intercept import is_magic_hostname
    if is_magic_hostname(host):
        if not state.remote_exec_enabled or not state.intercept_server or not state.intercept_server.port:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": f"Remote exec is disabled",
            })
            return
        # Redirect to internal intercept server
        port = state.intercept_server.port
        host = "127.0.0.1"
        logger.info(f"Intercept: {stream_id[:8]} -> {request.get('host')}:{request.get('port')} via 127.0.0.1:{port}")
```

This replaces `host` and `port` with the intercept server's loopback address, so the existing `do_connect()` logic connects to the internal server. No need for a separate code path.

- [ ] **Step 10: Run tests to verify they pass**

Run: `cd netbridge-agent && uv run pytest tests/test_intercept.py -v`
Expected: All PASS

- [ ] **Step 11: Run full test suite**

Run: `cd netbridge-agent && uv run pytest tests/ -x -q`
Expected: All pass, no regressions

- [ ] **Step 12: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/intercept.py netbridge-agent/src/netbridge_agent/agent.py netbridge-agent/tests/test_intercept.py
git commit -m "feat(agent): intercept magic hostnames for remote exec"
```

---

### Task 3: Tray Toggle, Purple Icon Override, Auto-Disable Timer

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/tray.py`
- Modify: `netbridge-agent/src/netbridge_agent/app.py`
- Create: `netbridge-agent/tests/test_tray_remote_exec.py`

This task adds the runtime toggle, purple icon, 1-hour auto-disable, and "Open Install Folder" menu item.

- [ ] **Step 1: Write failing tests for app toggle and auto-disable**

```python
# tests/test_tray_remote_exec.py
import asyncio
import threading
from unittest.mock import MagicMock, patch, AsyncMock
import pytest


class TestRemoteExecToggle:
    def test_remote_exec_off_by_default(self):
        with patch("netbridge_agent.app.setup_logging"):
            from netbridge_agent.app import NetBridgeApp
            app = NetBridgeApp(console=True)
            assert app._remote_exec_enabled is False

    def test_toggle_enables(self):
        with patch("netbridge_agent.app.setup_logging"):
            from netbridge_agent.app import NetBridgeApp
            app = NetBridgeApp(console=True)
            app.tray = MagicMock()
            app._async_loop = MagicMock()
            app.request_toggle_remote_exec()
            assert app._remote_exec_enabled is True

    def test_toggle_disables(self):
        with patch("netbridge_agent.app.setup_logging"):
            from netbridge_agent.app import NetBridgeApp
            app = NetBridgeApp(console=True)
            app.tray = MagicMock()
            app._async_loop = MagicMock()
            app._remote_exec_enabled = True
            app.request_toggle_remote_exec()
            assert app._remote_exec_enabled is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd netbridge-agent && uv run pytest tests/test_tray_remote_exec.py -v`
Expected: FAIL — no `_remote_exec_enabled` attribute

- [ ] **Step 3: Write failing tests for purple icon override**

```python
class TestPurpleIconOverride:
    def test_icon_purple_when_exec_enabled(self):
        with patch("netbridge_agent.app.setup_logging"):
            from netbridge_agent.app import NetBridgeApp
            from netbridge_agent.tray import TrayIcon, Status, TRAY_AVAILABLE
            if not TRAY_AVAILABLE:
                pytest.skip("pystray not available")
            app = NetBridgeApp(console=True)
            tray = TrayIcon(app)
            app._remote_exec_enabled = True
            tray.set_status(Status.CONNECTED)
            # The icon should be purple, not green
            from netbridge_agent.tray import REMOTE_EXEC_COLOR
            assert tray._icon_cache.get("remote_exec") is not None
```

- [ ] **Step 4: Write failing test for auto-disable timer**

```python
class TestAutoDisable:
    @pytest.mark.asyncio
    async def test_auto_disable_after_timeout(self):
        with patch("netbridge_agent.app.setup_logging"):
            from netbridge_agent.app import NetBridgeApp, REMOTE_EXEC_TIMEOUT
            app = NetBridgeApp(console=True)
            app._remote_exec_enabled = True
            app.tray = MagicMock()
            app._async_loop = asyncio.get_event_loop()

            # Simulate the timer firing with a short timeout for testing
            await app._remote_exec_auto_disable()
            assert app._remote_exec_enabled is False
```

- [ ] **Step 5: Implement app.py changes**

Add to `NetBridgeApp.__init__` (after `self._keepalive_task`):
```python
self._remote_exec_enabled: bool = False
self._remote_exec_timer: Optional[asyncio.TimerHandle] = None
```

Add constant at module level:
```python
REMOTE_EXEC_TIMEOUT = 3600  # 1 hour
```

Add methods to `NetBridgeApp`:
```python
def request_toggle_remote_exec(self) -> None:
    """Toggle remote exec mode (from tray menu)."""
    self._remote_exec_enabled = not self._remote_exec_enabled
    logger.info(f"Remote exec: {'ENABLED' if self._remote_exec_enabled else 'disabled'}")

    if self._async_loop:
        self._async_loop.call_soon_threadsafe(self._apply_remote_exec)

    if self.tray:
        self.tray.set_remote_exec(self._remote_exec_enabled)
        if self._remote_exec_enabled:
            self.tray.show_notification(
                "Remote Exec ENABLED",
                f"Remote execution is active. Auto-disables in {REMOTE_EXEC_TIMEOUT // 60} minutes.",
            )
        else:
            self.tray.show_notification("Remote Exec Disabled", "Remote execution is now off.")

def _apply_remote_exec(self) -> None:
    """Start or stop intercept server and auto-disable timer (called in async loop)."""
    if self._remote_exec_enabled:
        asyncio.create_task(self._start_remote_exec())
    else:
        asyncio.create_task(self._stop_remote_exec())

async def _start_remote_exec(self) -> None:
    """Start the intercept server and schedule auto-disable."""
    from .intercept import InterceptServer
    if not hasattr(self, '_intercept_server') or self._intercept_server is None:
        self._intercept_server = InterceptServer()
    await self._intercept_server.start()
    # Schedule auto-disable
    if self._remote_exec_timer:
        self._remote_exec_timer.cancel()
    loop = asyncio.get_event_loop()
    self._remote_exec_timer = loop.call_later(
        REMOTE_EXEC_TIMEOUT, lambda: asyncio.create_task(self._remote_exec_auto_disable())
    )

async def _stop_remote_exec(self) -> None:
    """Stop the intercept server and cancel timer."""
    if self._remote_exec_timer:
        self._remote_exec_timer.cancel()
        self._remote_exec_timer = None
    if hasattr(self, '_intercept_server') and self._intercept_server:
        await self._intercept_server.stop()

async def _remote_exec_auto_disable(self) -> None:
    """Auto-disable remote exec after timeout."""
    if self._remote_exec_enabled:
        self._remote_exec_enabled = False
        logger.info("Remote exec auto-disabled after timeout")
        await self._stop_remote_exec()
        if self.tray:
            self.tray.set_remote_exec(False)
            self.tray.show_notification(
                "Remote Exec Disabled",
                "Remote execution auto-disabled after timeout.",
            )
```

Wire the intercept server into `_run_agent` — pass it to agent state. In `_run_agent`, after `self._stop_event = asyncio.Event()`:
```python
# Pass remote exec state to agent
# (done inside run_agent via a callback or by passing the flag)
```

Modify `_run_agent` to pass a callback that the agent can call to check exec status. Or simpler: modify `run_agent` to accept an `intercept_server` and `remote_exec_enabled` check. The cleanest way is to pass a callable:

In `_run_agent`, pass additional kwargs to `run_agent`:
```python
await run_agent(
    relay_url=self.config.relay_url,
    stop_event=self._stop_event,
    on_status_change=self._on_agent_status,
    on_session_info=self.set_session_info,
    on_proxy_auth_rejected=self._on_proxy_auth_rejected,
    get_remote_exec_state=self._get_remote_exec_state,
)
```

Add helper:
```python
def _get_remote_exec_state(self) -> tuple[bool, Optional["InterceptServer"]]:
    """Return (enabled, server) for remote exec."""
    server = getattr(self, '_intercept_server', None)
    return self._remote_exec_enabled, server
```

In `agent.py`, `run_agent` accepts the new kwarg and sets it on state before the connection loop:
```python
async def run_agent(
    ...
    get_remote_exec_state: Optional[Callable[[], tuple[bool, Optional[Any]]]] = None,
) -> None:
```

Then in `handle_tcp_connect`, when a magic hostname is detected, call `state.get_remote_exec_state()` to get the live enabled/server values.

- [ ] **Step 6: Implement tray.py changes**

Add purple color constant:
```python
REMOTE_EXEC_COLOR = "#9B59B6"  # Purple
```

Add to `TrayIcon.__init__`:
```python
self._remote_exec = False
# Pre-generate purple icon
self._remote_exec_icon = create_icon_image(REMOTE_EXEC_COLOR)
```

Add method:
```python
def set_remote_exec(self, enabled: bool) -> None:
    """Toggle remote exec mode (changes icon to purple)."""
    self._remote_exec = enabled
    if self._icon:
        if enabled:
            self._icon.icon = self._remote_exec_icon
        else:
            self._icon.icon = self._icon_cache[self._status]
        self._icon.update_menu()

def set_status(self, status: Status) -> None:
    """Update the icon and tooltip based on status."""
    self._status = status
    if self._icon:
        # Purple overrides all status colors when remote exec is active
        if self._remote_exec:
            self._icon.icon = self._remote_exec_icon
        else:
            self._icon.icon = self._icon_cache[status]
        self._icon.title = STATUS_TOOLTIPS[status]
```

Add menu items in `_create_menu`:

Callback:
```python
def on_toggle_remote_exec(icon, item):
    self.app.request_toggle_remote_exec()

def is_remote_exec_enabled(item):
    return self.app._remote_exec_enabled
```

Menu item (after "View Logs", before "Restart"):
```python
pystray.MenuItem(
    "Remote Exec",
    on_toggle_remote_exec,
    checked=is_remote_exec_enabled,
),
```

"Open Install Folder" item (after "View Logs"):
```python
def on_open_install_folder(icon, item):
    self._open_install_folder()
```

```python
pystray.MenuItem(
    "Open Install Folder",
    on_open_install_folder,
),
```

Add method:
```python
def _open_install_folder(self) -> None:
    """Open the netbridge installation directory."""
    from .config import get_app_dir
    app_dir = get_app_dir()
    app_dir.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        os.startfile(app_dir)
    elif sys.platform == "darwin":
        subprocess.run(["open", str(app_dir)])
    else:
        subprocess.run(["xdg-open", str(app_dir)])
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd netbridge-agent && uv run pytest tests/test_tray_remote_exec.py -v`
Expected: All PASS

- [ ] **Step 8: Run full test suite**

Run: `cd netbridge-agent && uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 9: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/app.py netbridge-agent/src/netbridge_agent/tray.py netbridge-agent/tests/test_tray_remote_exec.py
git commit -m "feat(agent): tray toggle for remote exec with purple icon and auto-disable"
```

---

### Task 4: Wire Agent State and Import Check

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/agent.py:755-780` (run_agent — accept and wire remote exec state)
- Modify: `netbridge-agent/src/netbridge_agent/__main__.py:172` (import check)

- [ ] **Step 1: Modify `run_agent` to accept remote exec callback**

In `agent.py`, update `run_agent` signature:
```python
async def run_agent(
    relay_url: str,
    stop_event: asyncio.Event,
    on_status_change: Optional[StatusCallback] = None,
    on_session_info: Optional[SessionInfoCallback] = None,
    on_proxy_auth_rejected: Optional[Callable[[], None]] = None,
    get_remote_exec_state: Optional[Callable] = None,
) -> None:
```

After `state.denied_destinations = config.denied_destinations` (line 782), add:
```python
state.get_remote_exec_state = get_remote_exec_state
```

And in `AgentState.__init__`, add:
```python
self.get_remote_exec_state: Optional[Callable] = None
```

Update the intercept check in `handle_tcp_connect` to use the callback:
```python
    from .intercept import is_magic_hostname
    if is_magic_hostname(host):
        if not state.get_remote_exec_state:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": "Remote exec is not configured",
            })
            return
        enabled, server = state.get_remote_exec_state()
        if not enabled or not server or not server.port:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": "Remote exec is disabled",
            })
            return
        port = server.port
        host = "127.0.0.1"
        logger.info(f"Intercept: {stream_id[:8]} -> {request.get('host')}:{request.get('port')} via 127.0.0.1:{port}")
```

- [ ] **Step 2: Update `__main__.py` import check**

Change line 172 from:
```python
from . import agent, app, auth, config, credstore, dialogs, installer, legacy, tray, tunnel, winauth, winproxy  # noqa: F401
```
to:
```python
from . import agent, app, auth, config, credstore, dialogs, installer, intercept, legacy, remote_exec, tray, tunnel, winauth, winproxy  # noqa: F401
```

- [ ] **Step 3: Run full test suite**

Run: `cd netbridge-agent && uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/agent.py netbridge-agent/src/netbridge_agent/__main__.py
git commit -m "feat(agent): wire remote exec state through agent and update import check"
```

---

### Task 5: Integration Test — End-to-End Magic Hostname Flow

**Files:**
- Modify: `netbridge-agent/tests/test_intercept.py` (add e2e test)

- [ ] **Step 1: Write integration test**

```python
class TestEndToEndIntercept:
    """Test the full flow: tcp_connect for netbridge-exec -> intercept -> HTTP response."""

    @pytest.mark.asyncio
    async def test_exec_through_tunnel_simulation(self):
        """Simulate what happens when a SOCKS client connects to netbridge-exec."""
        import aiohttp
        from netbridge_agent.intercept import InterceptServer
        from netbridge_agent.agent import AgentState

        server = InterceptServer()
        await server.start()

        try:
            # Simulate: the agent would connect to 127.0.0.1:{server.port}
            # and forward TCP data. We test the HTTP layer directly.
            async with aiohttp.ClientSession() as session:
                # Health check
                async with session.get(f"http://127.0.0.1:{server.port}/health") as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["status"] == "ok"

                # Exec
                import sys
                cmd = "echo integration-test"
                async with session.post(
                    f"http://127.0.0.1:{server.port}/exec",
                    json={"cmd": cmd}
                ) as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["exit_code"] == 0
                    assert "integration-test" in data["stdout"]
        finally:
            await server.stop()
```

- [ ] **Step 2: Run test**

Run: `cd netbridge-agent && uv run pytest tests/test_intercept.py::TestEndToEndIntercept -v`
Expected: PASS

- [ ] **Step 3: Run full test suite one final time**

Run: `cd netbridge-agent && uv run pytest tests/ -x -q`
Expected: All pass, no regressions

- [ ] **Step 4: Commit**

```bash
git add netbridge-agent/tests/test_intercept.py
git commit -m "test(agent): add end-to-end integration test for remote exec intercept"
```

---

## Summary

After all tasks:
- `curl --proxy socks5://localhost:1080 http://netbridge-exec/health` works through the tunnel
- No port bound on the VDI, no localhost exposure
- Purple tray icon when remote exec is active
- Always OFF at startup, auto-disables after 1 hour
- "Open Install Folder" tray item for easy access
- All exec handlers catch exceptions — never crash the tunnel
- `--import-check` updated for CI
