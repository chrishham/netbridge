# Plugin System (Revised) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a plugin system to the NetBridge agent that discovers, loads, and hot-reloads plugins on the VDI, routed via magic hostnames through the existing tunnel. Revises agent-side tasks from the original `2026-05-19-cli-rename-and-plugin-system.md` plan with validated architectural decisions.

**Architecture:** The `InterceptServer` is rewritten to use a catch-all dispatcher pattern — a single aiohttp app with a wildcard route that dispatches to sub-app routers by HTTP `Host` header. This enables hot-plug (register/unregister apps at runtime without restarting). The server lifecycle is decoupled from the remote exec tray toggle: it starts at boot and always runs. The remote exec toggle only controls whether the `netbridge-exec` hostname is registered. Plugin apps are discovered from `%LOCALAPPDATA%/NetBridge/plugins/` and registered at startup, with a `/plugins/reload` endpoint for hot-reloading after install/uninstall.

**Tech Stack:** Python 3.14+, aiohttp 3.13+, importlib (dynamic module loading), pytest + pytest-aiohttp

**Supersedes:** Tasks 3, 4, 5 from `2026-05-19-cli-rename-and-plugin-system.md`. Tasks 1, 2, 6, 7, 8 from that plan remain valid and should be executed separately.

---

## File Structure

### Agent (VDI-side)

| File | Responsibility |
|------|---------------|
| `netbridge-agent/src/netbridge_agent/intercept.py` (rewrite) | Catch-all dispatcher InterceptServer with register/unregister, Host-header routing, per-plugin error isolation |
| `netbridge-agent/src/netbridge_agent/plugin_loader.py` (new) | Discover plugins in plugins dir, validate manifests, load plugin apps via importlib |
| `netbridge-agent/src/netbridge_agent/remote_exec.py` (modify) | Add `/plugins` list and `/plugins/reload` endpoints |
| `netbridge-agent/src/netbridge_agent/app.py` (modify) | Always-on InterceptServer, plugin discovery at boot, reload callback, decoupled remote exec toggle |
| `netbridge-agent/src/netbridge_agent/agent.py` (modify) | Simplified intercept routing — just check server exists, delegate hostname gating to dispatcher |
| `netbridge-agent/src/netbridge_agent/__main__.py` (modify) | Add `plugin_loader` to import check |
| `netbridge-agent/tests/test_intercept.py` (rewrite) | Tests for dispatcher routing, hot-plug, error isolation, streaming |
| `netbridge-agent/tests/test_plugin_loader.py` (new) | Tests for manifest validation and plugin discovery |
| `netbridge-agent/tests/test_remote_exec.py` (modify) | Tests for /plugins and /plugins/reload endpoints |

---

## Task 1: InterceptServer with catch-all dispatcher

**Files:**
- Rewrite: `netbridge-agent/src/netbridge_agent/intercept.py`
- Rewrite: `netbridge-agent/tests/test_intercept.py`

- [ ] **Step 1: Write failing tests for the new InterceptServer**

Replace the contents of `netbridge-agent/tests/test_intercept.py` with:

```python
"""Tests for netbridge_agent.intercept module.

Covers magic hostname detection, InterceptServer dispatcher routing,
hot-plug register/unregister, error isolation, and streaming.
"""

import asyncio
import json

import aiohttp
import pytest
from aiohttp import web

from netbridge_agent.intercept import InterceptServer, is_magic_hostname, MAGIC_HOSTS


# ---------------------------------------------------------------------------
# is_magic_hostname
# ---------------------------------------------------------------------------


class TestMagicHostname:
    def test_netbridge_exec_is_magic(self):
        assert is_magic_hostname("netbridge-exec") is True

    def test_regular_hostname_is_not_magic(self):
        assert is_magic_hostname("example.com") is False

    def test_ip_address_is_not_magic(self):
        assert is_magic_hostname("10.0.0.1") is False
        assert is_magic_hostname("127.0.0.1") is False

    def test_case_insensitive(self):
        assert is_magic_hostname("NETBRIDGE-EXEC") is True
        assert is_magic_hostname("Netbridge-Exec") is True


# ---------------------------------------------------------------------------
# InterceptServer — dispatcher routing
# ---------------------------------------------------------------------------


def _make_app(routes: dict[str, str]) -> web.Application:
    """Build a trivial aiohttp app from {path: response_text} pairs."""
    app = web.Application()
    for path, text in routes.items():

        async def handler(request, _text=text):
            return web.json_response({"msg": _text})

        app.router.add_get(path, handler)
    return app


class TestInterceptServerRouting:
    @pytest.mark.asyncio
    async def test_register_and_route_by_host_header(self):
        server = InterceptServer()
        server.register_app("netbridge-alpha", _make_app({"/hello": "alpha"}))
        server.register_app("netbridge-beta", _make_app({"/hello": "beta"}))
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/hello",
                    headers={"Host": "netbridge-alpha"},
                ) as r:
                    assert r.status == 200
                    assert (await r.json())["msg"] == "alpha"

                async with s.get(
                    f"http://127.0.0.1:{server.port}/hello",
                    headers={"Host": "netbridge-beta"},
                ) as r:
                    assert r.status == 200
                    assert (await r.json())["msg"] == "beta"
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_unknown_hostname_returns_404(self):
        server = InterceptServer()
        server.register_app("netbridge-known", _make_app({"/x": "ok"}))
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/x",
                    headers={"Host": "netbridge-unknown"},
                ) as r:
                    assert r.status == 404
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_unmatched_route_in_registered_app_returns_404(self):
        server = InterceptServer()
        server.register_app("netbridge-app", _make_app({"/exists": "yes"}))
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/nope",
                    headers={"Host": "netbridge-app"},
                ) as r:
                    assert r.status == 404
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_registered_hostnames_property(self):
        server = InterceptServer()
        server.register_app("netbridge-a", _make_app({}))
        server.register_app("netbridge-b", _make_app({}))
        assert server.registered_hostnames == {"netbridge-a", "netbridge-b"}


# ---------------------------------------------------------------------------
# InterceptServer — error isolation
# ---------------------------------------------------------------------------


class TestInterceptServerIsolation:
    @pytest.mark.asyncio
    async def test_crashing_plugin_returns_500_others_survive(self):
        crash_app = web.Application()

        async def crash(request):
            raise RuntimeError("plugin exploded")

        crash_app.router.add_get("/boom", crash)

        ok_app = _make_app({"/check": "alive"})

        server = InterceptServer()
        server.register_app("netbridge-crash", crash_app)
        server.register_app("netbridge-ok", ok_app)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/boom",
                    headers={"Host": "netbridge-crash"},
                ) as r:
                    assert r.status == 500

                async with s.get(
                    f"http://127.0.0.1:{server.port}/check",
                    headers={"Host": "netbridge-ok"},
                ) as r:
                    assert r.status == 200
                    assert (await r.json())["msg"] == "alive"
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_streaming_response_through_dispatcher(self):
        stream_app = web.Application()

        async def stream_handler(request):
            resp = web.StreamResponse(
                status=200, headers={"Content-Type": "text/plain"}
            )
            await resp.prepare(request)
            for i in range(3):
                await resp.write(f"line {i}\n".encode())
            await resp.write_eof()
            return resp

        stream_app.router.add_get("/stream", stream_handler)

        server = InterceptServer()
        server.register_app("netbridge-stream", stream_app)
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/stream",
                    headers={"Host": "netbridge-stream"},
                ) as r:
                    assert r.status == 200
                    body = await r.text()
                    assert body.count("\n") == 3
        finally:
            await server.stop()


# ---------------------------------------------------------------------------
# InterceptServer — hot-plug
# ---------------------------------------------------------------------------


class TestInterceptServerHotPlug:
    @pytest.mark.asyncio
    async def test_hot_add_after_start(self):
        server = InterceptServer()
        await server.start()
        try:
            server.register_app("netbridge-late", _make_app({"/ping": "pong"}))
            assert "netbridge-late" in MAGIC_HOSTS

            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/ping",
                    headers={"Host": "netbridge-late"},
                ) as r:
                    assert r.status == 200
                    assert (await r.json())["msg"] == "pong"
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_hot_remove_after_start(self):
        server = InterceptServer()
        server.register_app("netbridge-temp", _make_app({"/hi": "there"}))
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/hi",
                    headers={"Host": "netbridge-temp"},
                ) as r:
                    assert r.status == 200

            server.unregister_app("netbridge-temp")
            assert "netbridge-temp" not in MAGIC_HOSTS

            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/hi",
                    headers={"Host": "netbridge-temp"},
                ) as r:
                    assert r.status == 404
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_unregister_nonexistent_is_noop(self):
        server = InterceptServer()
        server.unregister_app("netbridge-nope")  # should not raise


# ---------------------------------------------------------------------------
# InterceptServer — lifecycle
# ---------------------------------------------------------------------------


class TestInterceptServerLifecycle:
    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        server = InterceptServer()
        assert server.port is None
        await server.start()
        assert server.port is not None
        assert server.port > 0
        await server.stop()
        assert server.port is None

    @pytest.mark.asyncio
    async def test_start_with_no_apps_serves_404(self):
        server = InterceptServer()
        await server.start()
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"http://127.0.0.1:{server.port}/anything",
                    headers={"Host": "netbridge-whatever"},
                ) as r:
                    assert r.status == 404
        finally:
            await server.stop()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/test_intercept.py -v`
Expected: FAIL — `InterceptServer` has no `register_app` method, no `registered_hostnames` property, no `unregister_app` method

- [ ] **Step 3: Rewrite `intercept.py` with catch-all dispatcher**

Replace the contents of `netbridge-agent/src/netbridge_agent/intercept.py` with:

```python
"""Stream intercept for magic hostnames.

When the relay requests a TCP connection to a "magic" hostname like
``netbridge-exec``, the agent redirects the stream to an in-process
HTTP server instead of opening a real TCP connection.

The InterceptServer uses a catch-all dispatcher pattern: a single
aiohttp app with a wildcard route dispatches to sub-app routers
based on the HTTP Host header.  Apps can be registered and
unregistered at runtime (hot-plug) without restarting the server.
"""

from __future__ import annotations

import logging
from typing import Optional

from aiohttp import web

logger = logging.getLogger(__name__)

MAGIC_HOSTS: set[str] = {"netbridge-exec"}


def is_magic_hostname(host: str) -> bool:
    """Check if *host* is a magic hostname (case-insensitive)."""
    return host.lower() in MAGIC_HOSTS


class InterceptServer:
    """In-process HTTP server with hostname-based routing.

    Each registered hostname maps to its own aiohttp Application.
    Requests are dispatched by the Host header.  Apps can be added
    or removed at any time — even after the server is started.
    """

    def __init__(self) -> None:
        self._apps: dict[str, web.Application] = {}
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self.port: Optional[int] = None

    @property
    def registered_hostnames(self) -> set[str]:
        return set(self._apps)

    def register_app(self, hostname: str, app: web.Application) -> None:
        hostname = hostname.lower()
        self._apps[hostname] = app
        MAGIC_HOSTS.add(hostname)
        logger.info("Registered app: %s", hostname)

    def unregister_app(self, hostname: str) -> None:
        hostname = hostname.lower()
        self._apps.pop(hostname, None)
        MAGIC_HOSTS.discard(hostname)
        logger.info("Unregistered app: %s", hostname)

    async def start(self) -> None:
        server = self

        async def dispatch(request: web.Request) -> web.Response:
            host = request.host.split(":")[0].lower()
            sub_app = server._apps.get(host)
            if sub_app is None:
                return web.json_response(
                    {"error": f"unknown service: {host}"}, status=404
                )
            try:
                match = await sub_app.router.resolve(request)
                if isinstance(match, web.UrlMappingMatchInfo):
                    return await match.handler(request)
                return web.json_response({"error": "not found"}, status=404)
            except Exception:
                logger.exception("Handler error for %s", host)
                return web.json_response(
                    {"error": f"plugin error: {host}"}, status=500
                )

        dispatcher = web.Application()
        dispatcher.router.add_route("*", "/{path_info:.*}", dispatch)

        self._runner = web.AppRunner(dispatcher)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await self._site.start()
        sockets = self._site._server.sockets  # type: ignore[union-attr]
        self.port = sockets[0].getsockname()[1]
        logger.info("InterceptServer listening on 127.0.0.1:%d", self.port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            self.port = None
            logger.info("InterceptServer stopped")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/test_intercept.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/intercept.py netbridge-agent/tests/test_intercept.py
git commit -m "Rewrite InterceptServer with catch-all dispatcher for plugin hot-plug"
```

---

## Task 2: Plugin manifest loader and discovery

**Files:**
- Create: `netbridge-agent/src/netbridge_agent/plugin_loader.py`
- Create: `netbridge-agent/tests/test_plugin_loader.py`

- [ ] **Step 1: Write failing tests for manifest validation**

Create `netbridge-agent/tests/test_plugin_loader.py`:

```python
"""Tests for netbridge_agent.plugin_loader module."""

import json

import pytest

from netbridge_agent.plugin_loader import (
    PluginLoadError,
    PluginManifest,
    discover_plugins,
    load_manifest,
    load_plugin_app,
)


# ---------------------------------------------------------------------------
# load_manifest
# ---------------------------------------------------------------------------


class TestLoadManifest:
    def _write_manifest(self, plugin_dir, data):
        plugin_dir.mkdir(exist_ok=True)
        (plugin_dir / "manifest.json").write_text(json.dumps(data))

    def test_valid_manifest(self, tmp_path):
        self._write_manifest(tmp_path, {
            "name": "test-plugin",
            "hostname": "netbridge-test",
            "description": "A test plugin",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        })
        m = load_manifest(tmp_path)
        assert m.name == "test-plugin"
        assert m.hostname == "netbridge-test"
        assert m.version == "1.0.0"
        assert m.path == tmp_path

    def test_missing_manifest_file(self, tmp_path):
        with pytest.raises(PluginLoadError, match="manifest.json not found"):
            load_manifest(tmp_path)

    def test_invalid_json(self, tmp_path):
        tmp_path.mkdir(exist_ok=True)
        (tmp_path / "manifest.json").write_text("not json{{{")
        with pytest.raises(PluginLoadError, match="invalid JSON"):
            load_manifest(tmp_path)

    def test_missing_required_field(self, tmp_path):
        self._write_manifest(tmp_path, {"name": "x"})
        with pytest.raises(PluginLoadError, match="missing required field"):
            load_manifest(tmp_path)

    def test_hostname_must_start_with_netbridge(self, tmp_path):
        self._write_manifest(tmp_path, {
            "name": "bad",
            "hostname": "not-netbridge",
            "description": "bad hostname",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        })
        with pytest.raises(PluginLoadError, match="must start with 'netbridge-'"):
            load_manifest(tmp_path)

    def test_reserved_hostname_rejected(self, tmp_path):
        self._write_manifest(tmp_path, {
            "name": "sneaky",
            "hostname": "netbridge-exec",
            "description": "hijack attempt",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        })
        with pytest.raises(PluginLoadError, match="reserved"):
            load_manifest(tmp_path)


# ---------------------------------------------------------------------------
# load_plugin_app
# ---------------------------------------------------------------------------


class TestLoadPluginApp:
    def test_loads_create_app(self, tmp_path):
        (tmp_path / "manifest.json").write_text(json.dumps({
            "name": "test",
            "hostname": "netbridge-test",
            "description": "test",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (tmp_path / "handlers.py").write_text(
            "from aiohttp import web\n"
            "def create_app():\n"
            "    app = web.Application()\n"
            "    return app\n"
        )
        manifest = load_manifest(tmp_path)
        app = load_plugin_app(manifest)
        from aiohttp.web import Application
        assert isinstance(app, Application)

    def test_missing_entry_point_file(self, tmp_path):
        (tmp_path / "manifest.json").write_text(json.dumps({
            "name": "test",
            "hostname": "netbridge-test",
            "description": "test",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        manifest = load_manifest(tmp_path)
        with pytest.raises(PluginLoadError, match="not found"):
            load_plugin_app(manifest)

    def test_missing_create_app_function(self, tmp_path):
        (tmp_path / "manifest.json").write_text(json.dumps({
            "name": "test",
            "hostname": "netbridge-test",
            "description": "test",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (tmp_path / "handlers.py").write_text("x = 1\n")
        manifest = load_manifest(tmp_path)
        with pytest.raises(PluginLoadError, match="no create_app"):
            load_plugin_app(manifest)


# ---------------------------------------------------------------------------
# discover_plugins
# ---------------------------------------------------------------------------


class TestDiscoverPlugins:
    def _make_plugin(self, plugins_dir, name, hostname=None):
        d = plugins_dir / name
        d.mkdir()
        (d / "manifest.json").write_text(json.dumps({
            "name": name,
            "hostname": hostname or f"netbridge-{name}",
            "description": f"{name} plugin",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (d / "handlers.py").write_text(
            "from aiohttp import web\n"
            "def create_app():\n"
            "    return web.Application()\n"
        )

    def test_empty_dir(self, tmp_path):
        assert discover_plugins(tmp_path) == []

    def test_nonexistent_dir(self, tmp_path):
        assert discover_plugins(tmp_path / "nope") == []

    def test_discovers_valid_plugin(self, tmp_path):
        self._make_plugin(tmp_path, "myplugin")
        plugins = discover_plugins(tmp_path)
        assert len(plugins) == 1
        assert plugins[0].name == "myplugin"

    def test_skips_invalid_plugin(self, tmp_path):
        self._make_plugin(tmp_path, "good")
        bad = tmp_path / "bad"
        bad.mkdir()
        # No manifest — should be skipped
        plugins = discover_plugins(tmp_path)
        assert len(plugins) == 1
        assert plugins[0].name == "good"

    def test_skips_non_directory_entries(self, tmp_path):
        self._make_plugin(tmp_path, "valid")
        (tmp_path / "readme.txt").write_text("not a plugin")
        plugins = discover_plugins(tmp_path)
        assert len(plugins) == 1

    def test_discovers_multiple_sorted(self, tmp_path):
        self._make_plugin(tmp_path, "beta")
        self._make_plugin(tmp_path, "alpha")
        plugins = discover_plugins(tmp_path)
        assert [p.name for p in plugins] == ["alpha", "beta"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/test_plugin_loader.py -v`
Expected: FAIL — module `netbridge_agent.plugin_loader` not found

- [ ] **Step 3: Implement `plugin_loader.py`**

Create `netbridge-agent/src/netbridge_agent/plugin_loader.py`:

```python
"""Plugin discovery and manifest validation.

Plugins live under ``%LOCALAPPDATA%/NetBridge/plugins/<name>/``.
Each plugin directory must contain a ``manifest.json`` declaring
its hostname, description, version, and entry point module.  The
entry point module must export a ``create_app()`` function
returning an ``aiohttp.web.Application``.
"""

from __future__ import annotations

import importlib.util
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from aiohttp import web

LOG = logging.getLogger(__name__)

RESERVED_HOSTNAMES = {"netbridge-exec"}


class PluginLoadError(Exception):
    pass


@dataclass
class PluginManifest:
    name: str
    hostname: str
    description: str
    version: str
    entry_point: str
    path: Path


def load_manifest(plugin_dir: Path) -> PluginManifest:
    manifest_path = plugin_dir / "manifest.json"
    if not manifest_path.exists():
        raise PluginLoadError(f"manifest.json not found in {plugin_dir}")

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        raise PluginLoadError(f"invalid JSON in {manifest_path}")

    required = ("name", "hostname", "description", "version", "entry_point")
    for field in required:
        if field not in data:
            raise PluginLoadError(
                f"missing required field '{field}' in {manifest_path}"
            )

    hostname = data["hostname"]
    if not hostname.startswith("netbridge-"):
        raise PluginLoadError(
            f"hostname '{hostname}' must start with 'netbridge-'"
        )
    if hostname in RESERVED_HOSTNAMES:
        raise PluginLoadError(f"hostname '{hostname}' is reserved")

    return PluginManifest(
        name=data["name"],
        hostname=hostname,
        description=data["description"],
        version=data["version"],
        entry_point=data["entry_point"],
        path=plugin_dir,
    )


def load_plugin_app(manifest: PluginManifest) -> web.Application:
    entry = manifest.path / manifest.entry_point
    if not entry.exists():
        raise PluginLoadError(f"entry point {entry} not found")

    spec = importlib.util.spec_from_file_location(
        f"netbridge_plugin_{manifest.name}", entry
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, "create_app"):
        raise PluginLoadError(
            f"plugin {manifest.name}: {entry} has no create_app()"
        )

    return module.create_app()


def discover_plugins(plugins_dir: Path) -> list[PluginManifest]:
    if not plugins_dir.is_dir():
        return []

    manifests = []
    for child in sorted(plugins_dir.iterdir()):
        if not child.is_dir():
            continue
        try:
            manifest = load_manifest(child)
            manifests.append(manifest)
        except PluginLoadError as e:
            LOG.warning("Skipping plugin %s: %s", child.name, e)

    return manifests
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/test_plugin_loader.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/plugin_loader.py netbridge-agent/tests/test_plugin_loader.py
git commit -m "Add plugin manifest loader and discovery"
```

---

## Task 3: Add `/plugins` and `/plugins/reload` endpoints

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/remote_exec.py`
- Modify: `netbridge-agent/tests/test_remote_exec.py`

- [ ] **Step 1: Write failing tests for `/plugins` endpoint**

Append to `netbridge-agent/tests/test_remote_exec.py`:

```python
# ---------------------------------------------------------------------------
# /plugins  (plugin listing)
# ---------------------------------------------------------------------------


class TestPlugins:
    async def test_plugins_returns_empty_list(self, client: TestClient):
        resp = await client.get("/plugins")
        assert resp.status == 200
        data = await resp.json()
        assert data["plugins"] == []

    async def test_plugins_returns_discovered_plugins(self, client: TestClient, tmp_path):
        # Create a fake plugin
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text(json.dumps({
            "name": "test-plugin",
            "hostname": "netbridge-test",
            "description": "A test plugin",
            "version": "2.0.0",
            "entry_point": "handlers.py",
        }))
        (plugin_dir / "handlers.py").write_text(
            "from aiohttp import web\n"
            "def create_app():\n"
            "    return web.Application()\n"
        )

        # Override the plugins dir for this test
        import netbridge_agent.remote_exec as mod
        original = mod._get_plugins_dir
        mod._get_plugins_dir = lambda: tmp_path
        try:
            resp = await client.get("/plugins")
            assert resp.status == 200
            data = await resp.json()
            assert len(data["plugins"]) == 1
            p = data["plugins"][0]
            assert p["name"] == "test-plugin"
            assert p["hostname"] == "netbridge-test"
            assert p["version"] == "2.0.0"
        finally:
            mod._get_plugins_dir = original
```

Add `import json` to the top of the test file if not present.

- [ ] **Step 2: Write failing test for `/plugins/reload` endpoint**

Append to the same file:

```python
# ---------------------------------------------------------------------------
# /plugins/reload  (hot-reload trigger)
# ---------------------------------------------------------------------------


class TestPluginsReload:
    async def test_reload_without_callback_returns_501(self, client: TestClient):
        resp = await client.post("/plugins/reload")
        assert resp.status == 501

    async def test_reload_with_callback_invokes_it(self, aiohttp_client):
        from unittest.mock import AsyncMock

        app = create_app()
        reload_mock = AsyncMock(return_value=(["netbridge-new"], ["netbridge-old"]))
        app["_plugin_reload_callback"] = reload_mock

        c = await aiohttp_client(app)
        resp = await c.post("/plugins/reload")
        assert resp.status == 200
        data = await resp.json()
        assert data["added"] == ["netbridge-new"]
        assert data["removed"] == ["netbridge-old"]
        reload_mock.assert_awaited_once()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/test_remote_exec.py::TestPlugins tests/test_remote_exec.py::TestPluginsReload -v`
Expected: FAIL — 404 (routes don't exist)

- [ ] **Step 4: Add endpoints to `remote_exec.py`**

Add the following to `netbridge-agent/src/netbridge_agent/remote_exec.py`:

After the existing imports, add:

```python
from .config import get_app_dir
```

Before the `create_app()` function, add:

```python
def _get_plugins_dir():
    """Return the plugins directory path. Extracted for test overrides."""
    return get_app_dir() / "plugins"


# ---------------------------------------------------------------------------
# /plugins  — plugin listing
# ---------------------------------------------------------------------------


async def handle_plugins(request: web.Request) -> web.Response:
    """List installed plugins."""
    try:
        from .plugin_loader import discover_plugins

        plugins_dir = _get_plugins_dir()
        manifests = discover_plugins(plugins_dir)
        return web.json_response({
            "plugins": [
                {
                    "name": m.name,
                    "hostname": m.hostname,
                    "description": m.description,
                    "version": m.version,
                }
                for m in manifests
            ]
        })
    except Exception:
        LOG.exception("handle_plugins failed")
        return web.json_response({"error": "internal error"}, status=500)


# ---------------------------------------------------------------------------
# /plugins/reload  — hot-reload trigger
# ---------------------------------------------------------------------------


async def handle_plugins_reload(request: web.Request) -> web.Response:
    """Trigger re-discovery of plugins. Called after install/uninstall."""
    try:
        reload_fn = request.app.get("_plugin_reload_callback")
        if not reload_fn:
            return web.json_response(
                {"error": "reload not available"}, status=501
            )
        added, removed = await reload_fn()
        return web.json_response({
            "status": "ok",
            "added": added,
            "removed": removed,
        })
    except Exception:
        LOG.exception("handle_plugins_reload failed")
        return web.json_response({"error": "internal error"}, status=500)
```

In the `create_app()` function, add the two new routes after the existing ones:

```python
    app.router.add_get("/plugins", handle_plugins)
    app.router.add_post("/plugins/reload", handle_plugins_reload)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/test_remote_exec.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/remote_exec.py netbridge-agent/tests/test_remote_exec.py
git commit -m "Add /plugins and /plugins/reload endpoints to remote exec"
```

---

## Task 4: Always-on InterceptServer and plugin loading in app.py

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/app.py`

- [ ] **Step 1: Add plugin state to `__init__`**

In `NetBridgeApp.__init__`, after the `self._intercept_server = None` line, add:

```python
        self._plugin_manifests: list = []
```

- [ ] **Step 2: Start InterceptServer unconditionally in `_async_main`**

In `_async_main()`, after the keep-alive start block (`if self.config.keep_session_alive:`) and before `await self._stop_event.wait()`, add:

```python
        # Start intercept server (always-on for plugins)
        from .intercept import InterceptServer
        self._intercept_server = InterceptServer()
        await self._intercept_server.start()

        # Discover and register plugins
        from .plugin_loader import discover_plugins, load_plugin_app
        plugins_dir = get_app_dir() / "plugins"
        for manifest in discover_plugins(plugins_dir):
            try:
                plugin_app = load_plugin_app(manifest)
                self._intercept_server.register_app(manifest.hostname, plugin_app)
                self._plugin_manifests.append(manifest)
                logger.info("Plugin loaded: %s (%s)", manifest.name, manifest.hostname)
            except Exception as e:
                logger.warning("Failed to load plugin %s: %s", manifest.name, e)
```

In `_async_main()`, in the cleanup section after `await self._stop_event.wait()`, before `self._stop_keepalive()`, add:

```python
        # Stop intercept server
        if self._intercept_server:
            await self._intercept_server.stop()
```

- [ ] **Step 3: Change `_start_remote_exec` to register instead of create**

Replace `_start_remote_exec` with:

```python
    async def _start_remote_exec(self) -> None:
        """Register the remote exec app in the intercept server."""
        from .remote_exec import create_app as create_exec_app

        if self._intercept_server:
            exec_app = create_exec_app()
            exec_app["_plugin_reload_callback"] = self._reload_plugins
            self._intercept_server.register_app("netbridge-exec", exec_app)

        if self._remote_exec_timer:
            self._remote_exec_timer.cancel()
        loop = asyncio.get_event_loop()
        self._remote_exec_timer = loop.call_later(
            REMOTE_EXEC_TIMEOUT,
            lambda: asyncio.create_task(self._remote_exec_auto_disable()),
        )
```

- [ ] **Step 4: Change `_stop_remote_exec` to unregister instead of stop**

Replace `_stop_remote_exec` with:

```python
    async def _stop_remote_exec(self) -> None:
        """Unregister the remote exec app (server keeps running for plugins)."""
        if self._remote_exec_timer:
            self._remote_exec_timer.cancel()
            self._remote_exec_timer = None
        if self._intercept_server:
            self._intercept_server.unregister_app("netbridge-exec")
```

- [ ] **Step 5: Add `_reload_plugins` method**

Add this method to `NetBridgeApp` (after `_get_remote_exec_state`):

```python
    async def _reload_plugins(self) -> tuple[list[str], list[str]]:
        """Re-discover plugins and hot-add/remove from intercept server."""
        from .plugin_loader import discover_plugins, load_plugin_app

        plugins_dir = get_app_dir() / "plugins"
        new_manifests = discover_plugins(plugins_dir)

        current = {m.hostname for m in self._plugin_manifests}
        desired = {m.hostname: m for m in new_manifests}

        added, removed = [], []

        for m in self._plugin_manifests:
            if m.hostname not in desired:
                self._intercept_server.unregister_app(m.hostname)
                removed.append(m.hostname)
                logger.info("Plugin unloaded: %s", m.hostname)

        for hostname, m in desired.items():
            if hostname not in current:
                try:
                    app = load_plugin_app(m)
                    self._intercept_server.register_app(hostname, app)
                    added.append(hostname)
                    logger.info("Plugin loaded: %s", hostname)
                except Exception as e:
                    logger.warning("Failed to load plugin %s: %s", m.name, e)

        self._plugin_manifests = new_manifests
        return added, removed
```

- [ ] **Step 6: Run full test suite to verify no regressions**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/ -x -q`
Expected: All pass (some intercept tests that depended on auto-registered exec app may need updating — see step 7)

- [ ] **Step 7: Fix any broken tests**

The `TestEndToEndIntercept` tests in `test_intercept.py` previously relied on `InterceptServer` auto-registering the exec app in `start()`. That no longer happens. These tests were removed in Task 1's test rewrite so they should already be gone. If any other tests break, update them to explicitly register the exec app:

```python
from netbridge_agent.remote_exec import create_app
server = InterceptServer()
server.register_app("netbridge-exec", create_app())
await server.start()
```

- [ ] **Step 8: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/app.py
git commit -m "Decouple InterceptServer lifecycle from remote exec toggle"
```

---

## Task 5: Simplify agent intercept routing

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/agent.py`
- Modify: `netbridge-agent/tests/test_intercept.py`

- [ ] **Step 1: Write failing test for simplified routing**

Append to `netbridge-agent/tests/test_intercept.py`:

```python
# ---------------------------------------------------------------------------
# Agent intercept routing (simplified)
# ---------------------------------------------------------------------------


class TestAgentInterceptRouting:
    @pytest.mark.asyncio
    async def test_magic_host_routes_to_intercept_server(self):
        from netbridge_agent.agent import AgentState, handle_tcp_connect
        from netbridge_agent.remote_exec import create_app
        from unittest.mock import MagicMock, AsyncMock

        server = InterceptServer()
        server.register_app("netbridge-exec", create_app())
        await server.start()
        try:
            state = AgentState()
            state.allow_loopback = True
            state.get_intercept_server = lambda: server

            ws = MagicMock()
            ws.closed = False
            ws.send_str = AsyncMock()

            request = {
                "stream_id": "test-stream-1234",
                "host": "netbridge-exec",
                "port": 80,
            }

            await handle_tcp_connect(state, ws, request)
            for task in list(state.pending_connections.values()):
                await task

            sent = json.loads(ws.send_str.call_args_list[0][0][0])
            assert sent["type"] == "tcp_connect_result"
            assert sent["success"] is True
        finally:
            from netbridge_agent.agent import close_all_streams
            await close_all_streams(state, timeout=2.0)
            await server.stop()

    @pytest.mark.asyncio
    async def test_magic_host_rejected_when_no_server(self):
        from netbridge_agent.agent import AgentState, handle_tcp_connect
        from unittest.mock import MagicMock, AsyncMock

        state = AgentState()
        state.get_intercept_server = lambda: None

        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock()

        request = {
            "stream_id": "test-stream-5678",
            "host": "netbridge-exec",
            "port": 80,
        }

        await handle_tcp_connect(state, ws, request)
        for task in list(state.pending_connections.values()):
            await task

        sent = json.loads(ws.send_str.call_args_list[0][0][0])
        assert sent["type"] == "tcp_connect_result"
        assert sent["success"] is False
        assert "not running" in sent["error"].lower()

    @pytest.mark.asyncio
    async def test_magic_host_rejected_when_no_callback(self):
        from netbridge_agent.agent import AgentState, handle_tcp_connect
        from unittest.mock import MagicMock, AsyncMock

        state = AgentState()
        # get_intercept_server is None by default

        ws = MagicMock()
        ws.closed = False
        ws.send_str = AsyncMock()

        request = {
            "stream_id": "test-stream-9999",
            "host": "netbridge-exec",
            "port": 80,
        }

        await handle_tcp_connect(state, ws, request)
        for task in list(state.pending_connections.values()):
            await task

        sent = json.loads(ws.send_str.call_args_list[0][0][0])
        assert sent["type"] == "tcp_connect_result"
        assert sent["success"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/test_intercept.py::TestAgentInterceptRouting -v`
Expected: FAIL — `AgentState` has no `get_intercept_server`

- [ ] **Step 3: Update `AgentState` and intercept routing in `agent.py`**

In `AgentState.__init__`, replace:

```python
        self.remote_exec_enabled: bool = False
        self.intercept_server: Optional[object] = None
        self.get_remote_exec_state: Optional[Callable] = None
```

with:

```python
        self.get_intercept_server: Optional[Callable] = None
```

In `handle_tcp_connect`, replace the intercept block (lines 438-464) with:

```python
    # Intercept magic hostnames
    from .intercept import is_magic_hostname
    if is_magic_hostname(host):
        if not state.get_intercept_server:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": "Intercept server is not configured",
            })
            return
        server = state.get_intercept_server()
        if not server or not server.port:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": "Intercept server is not running",
            })
            return
        port = server.port
        host = "127.0.0.1"
        logger.info(
            "Intercept: %s -> %s:%s via 127.0.0.1:%d",
            stream_id[:8], request.get("host"), request.get("port"), port,
        )
```

In `run_agent`, replace:

```python
    state.get_remote_exec_state = get_remote_exec_state
```

with:

```python
    state.get_intercept_server = get_remote_exec_state
```

Note: The parameter name `get_remote_exec_state` in `run_agent` will be renamed to `get_intercept_server` in the signature too:

```python
async def run_agent(
    relay_url: str,
    stop_event: asyncio.Event,
    on_status_change: Optional[StatusCallback] = None,
    on_session_info: Optional[SessionInfoCallback] = None,
    on_proxy_auth_rejected: Optional[Callable[[], None]] = None,
    get_intercept_server: Optional[Callable] = None,
) -> None:
```

Update the docstring accordingly and the assignment:

```python
    state.get_intercept_server = get_intercept_server
```

- [ ] **Step 4: Update `app.py` to pass `get_intercept_server` callback**

In `NetBridgeApp._run_agent`, change the `run_agent` call from:

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

to:

```python
            await run_agent(
                relay_url=self.config.relay_url,
                stop_event=self._stop_event,
                on_status_change=self._on_agent_status,
                on_session_info=self.set_session_info,
                on_proxy_auth_rejected=self._on_proxy_auth_rejected,
                get_intercept_server=lambda: self._intercept_server,
            )
```

Remove the `_get_remote_exec_state` method from `NetBridgeApp` — it's no longer needed.

- [ ] **Step 5: Run full test suite**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/ -x -q`
Expected: All pass. The old `TestAgentIntercept` tests from `test_intercept.py` were removed in Task 1. If any test references `get_remote_exec_state`, update it to use `get_intercept_server`.

- [ ] **Step 6: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/agent.py netbridge-agent/src/netbridge_agent/app.py netbridge-agent/tests/test_intercept.py
git commit -m "Simplify agent intercept routing with get_intercept_server callback"
```

---

## Task 6: Import check and final integration

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/__main__.py`

- [ ] **Step 1: Add `plugin_loader` to import check**

In `__main__.py`, change the import check line (line 172) from:

```python
        from . import agent, app, auth, config, credstore, dialogs, installer, intercept, legacy, remote_exec, tray, tunnel, winauth, winproxy  # noqa: F401
```

to:

```python
        from . import agent, app, auth, config, credstore, dialogs, installer, intercept, legacy, plugin_loader, remote_exec, tray, tunnel, winauth, winproxy  # noqa: F401
```

- [ ] **Step 2: Run full test suites for both packages**

Run:
```bash
cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/ -x -q
```
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/__main__.py
git commit -m "Add plugin_loader to import check"
```

---

## Summary

After all tasks:

**InterceptServer** — catch-all dispatcher routing by Host header, supports hot-plug:
- `register_app(hostname, app)` / `unregister_app(hostname)` at any time
- Error isolation: crashing plugin returns 500, others unaffected
- StreamResponse: works through dispatcher
- Always runs from boot (not gated by remote exec toggle)

**Plugin lifecycle:**
- Discovered at boot from `%LOCALAPPDATA%/NetBridge/plugins/<name>/`
- Hot-reloaded via `POST /plugins/reload` (called by laptop CLI after install/uninstall)
- `manifest.json` validates: hostname prefix, reserved names, required fields

**Remote exec gating** — only `netbridge-exec` registration is toggled:
- `_start_remote_exec()` → `register_app("netbridge-exec", ...)`
- `_stop_remote_exec()` → `unregister_app("netbridge-exec")`

**Agent routing** — simplified to: "is magic hostname? → route to server. Server handles hostname-level 404."
