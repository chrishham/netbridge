# CLI Rename + Plugin System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the `netbridge-socks` CLI to `netbridge` with subcommands (`serve`, `plugin`), and add a plugin management system that installs/manages plugins on the VDI through the tunnel.

**Architecture:** The existing flat argparse CLI becomes a subcommand-based CLI: `netbridge serve` runs the proxy (backwards compat: bare `netbridge` with proxy flags also works), `netbridge plugin {list,install,uninstall,update,info,logs}` manages VDI plugins through `netbridge-exec` endpoints over the SOCKS tunnel. On the agent side, a plugin loader discovers plugins in `%LOCALAPPDATA%/NetBridge/plugins/` and registers their magic hostnames in the intercept system. Each plugin has a `manifest.json` declaring its hostname and routes, an optional `install.py`/`uninstall.py`, and its own log file.

**Tech Stack:** Python 3.14+, argparse (subparsers), aiohttp, git CLI (for cloning plugin repos)

---

## File Structure

### Socks proxy (laptop-side CLI)

| File | Responsibility |
|------|---------------|
| `socks-proxy/pyproject.toml` (modify) | Rename package, add `netbridge` entry point |
| `socks-proxy/src/socks_proxy/__main__.py` (modify) | Refactor to subcommand CLI: `serve` and `plugin` |
| `socks-proxy/src/socks_proxy/plugin_cli.py` (new) | Plugin subcommand handlers: list, install, uninstall, update, info, logs |
| `socks-proxy/src/socks_proxy/tunnel_client.py` (new) | Helper to call netbridge-exec endpoints through the tunnel |
| `socks-proxy/tests/test_plugin_cli.py` (new) | Tests for plugin CLI commands |
| `socks-proxy/tests/test_tunnel_client.py` (new) | Tests for tunnel client helper |

### Agent (VDI-side plugin loader)

| File | Responsibility |
|------|---------------|
| `netbridge-agent/src/netbridge_agent/plugin_loader.py` (new) | Discover plugins in plugins dir, validate manifests, register magic hostnames |
| `netbridge-agent/src/netbridge_agent/intercept.py` (modify) | Accept dynamic hostname→app registration from plugin loader |
| `netbridge-agent/src/netbridge_agent/remote_exec.py` (modify) | Add `/plugins` endpoint listing installed plugins |
| `netbridge-agent/src/netbridge_agent/app.py` (modify) | Start plugin loader in `_async_main`, register plugin routes |
| `netbridge-agent/tests/test_plugin_loader.py` (new) | Tests for plugin discovery and manifest validation |

### Homebrew

| File | Responsibility |
|------|---------------|
| `.github/workflows/release-socks.yml` (modify) | Update formula references from `netbridge-socks` to `netbridge` |

---

## Part A: CLI Rename

### Task 1: Rename package and add subcommand structure

**Files:**
- Modify: `socks-proxy/pyproject.toml`
- Modify: `socks-proxy/src/socks_proxy/__main__.py`
- Modify: `socks-proxy/tests/test_main.py`

- [ ] **Step 1: Write failing test for subcommand `serve`**

```python
# tests/test_main.py — add to existing file
import subprocess
import sys

def test_serve_subcommand_help():
    result = subprocess.run(
        [sys.executable, "-m", "socks_proxy", "serve", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "relay" in result.stdout.lower()

def test_plugin_subcommand_help():
    result = subprocess.run(
        [sys.executable, "-m", "socks_proxy", "plugin", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "install" in result.stdout.lower()

def test_bare_invocation_with_relay_flag_works():
    """Backwards compat: netbridge --relay ... should work like netbridge serve --relay ..."""
    result = subprocess.run(
        [sys.executable, "-m", "socks_proxy", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "serve" in result.stdout.lower()
    assert "plugin" in result.stdout.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/Projects/netbridge/socks-proxy && uv run pytest tests/test_main.py -v`
Expected: FAIL

- [ ] **Step 3: Refactor `__main__.py` to subcommand structure**

Restructure `main()`:
- Create top-level parser with subparsers
- `serve` subcommand: move all existing args and logic under `serve_main(args)`
- `plugin` subcommand: placeholder that imports from `plugin_cli.py`
- When no subcommand is given and proxy-related flags (--relay, --port, etc.) are present, default to `serve`

```python
def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        prog="netbridge",
        description="NetBridge — tunnel to your VDI",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    # --- serve ---
    serve_parser = subparsers.add_parser(
        "serve",
        help="Run the SOCKS5 & HTTP proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_serve_args(serve_parser)

    # --- plugin ---
    from .plugin_cli import add_plugin_subparser
    add_plugin_subparser(subparsers)

    args = parser.parse_args()

    if args.command == "serve" or args.command is None:
        # Default to serve when no subcommand given
        if args.command is None:
            # Re-parse with serve defaults
            args = serve_parser.parse_args(sys.argv[1:])
        serve_main(args)
    elif args.command == "plugin":
        from .plugin_cli import plugin_main
        plugin_main(args)


def _add_serve_args(parser):
    """Add all proxy-related arguments to the serve parser."""
    parser.add_argument("--host", default=DEFAULT_HOST, ...)
    parser.add_argument("--port", type=int, default=DEFAULT_SOCKS_PORT, ...)
    # ... all existing args moved here ...


def serve_main(args):
    """Run the proxy server (extracted from old main())."""
    # ... all existing main() logic after arg parsing ...
```

- [ ] **Step 4: Update `pyproject.toml`**

```toml
[project]
name = "netbridge"
version = "0.0.0"
description = "NetBridge client — SOCKS5/HTTP proxy and plugin manager for VDI tunneling"

[project.scripts]
netbridge = "socks_proxy.__main__:main"
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /data/Projects/netbridge/socks-proxy && uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add socks-proxy/
git commit -m "Rename netbridge-socks CLI to netbridge with subcommands"
```

---

### Task 2: Update CI workflow and brew formula references

**Files:**
- Modify: `.github/workflows/release-socks.yml`

- [ ] **Step 1: Update formula references in release workflow**

In `release-socks.yml`, update the sed commands that modify the formula:
- Change `Formula/netbridge-socks.rb` → `Formula/netbridge.rb`
- Update the commit message format
- Update the shebang rewrite in the formula from `netbridge-socks` to `netbridge`

```yaml
      - name: Update Homebrew formula
        env:
          TAP_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
        run: |
          git clone https://x-access-token:${TAP_TOKEN}@github.com/chrishham/homebrew-tap.git /tmp/homebrew-tap
          cd /tmp/homebrew-tap

          sed -i 's|archive/refs/tags/socks-v[^"]*\.tar\.gz|archive/refs/tags/'"${GITHUB_REF_NAME}"'.tar.gz|' Formula/netbridge.rb
          sed -i 's|version ".*"|version "${{ steps.version.outputs.version }}"|' Formula/netbridge.rb

          SHA=$(curl -sL "https://github.com/chrishham/netbridge/archive/refs/tags/${GITHUB_REF_NAME}.tar.gz" | sha256sum | cut -d' ' -f1)
          sed -i 's|sha256 ".*"|sha256 "'"${SHA}"'"|' Formula/netbridge.rb

          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add Formula/netbridge.rb
          if git diff --cached --quiet; then
            echo "Formula already up to date"
          else
            git commit -m "netbridge ${{ steps.version.outputs.version }}"
            git push
          fi
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release-socks.yml
git commit -m "Update release workflow for netbridge formula rename"
```

**Note:** The actual `homebrew-tap` repo (Formula/netbridge.rb) must be updated separately — rename the formula file from `netbridge-socks.rb` to `netbridge.rb`, update class name from `NetbridgeSocks` to `Netbridge`, update bin wrapper and service references from `netbridge-socks` to `netbridge`. This is outside the netbridge repo and should be done manually before the first tagged release.

---

## Part B: Plugin System — Agent Side

### Task 3: Plugin manifest and loader

**Files:**
- Create: `netbridge-agent/src/netbridge_agent/plugin_loader.py`
- Create: `netbridge-agent/tests/test_plugin_loader.py`

A plugin is a directory under `%LOCALAPPDATA%/NetBridge/plugins/<name>/` with:
```
manifest.json       # Required: declares hostname, description, entry point
handlers.py         # Required: Python module with create_app() -> aiohttp.web.Application
install.py          # Optional: run during plugin install
uninstall.py        # Optional: run during plugin uninstall
```

`manifest.json` schema:
```json
{
  "name": "gauth",
  "hostname": "netbridge-gauth",
  "description": "GCloud auth helper — automates SSO login on VDI",
  "version": "1.0.0",
  "entry_point": "handlers.py"
}
```

- [ ] **Step 1: Write failing tests for manifest validation**

```python
# tests/test_plugin_loader.py
import json
import pytest
from pathlib import Path
from netbridge_agent.plugin_loader import (
    load_manifest,
    discover_plugins,
    PluginManifest,
    PluginLoadError,
)


class TestLoadManifest:
    def test_valid_manifest(self, tmp_path):
        manifest_data = {
            "name": "test-plugin",
            "hostname": "netbridge-test",
            "description": "A test plugin",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(json.dumps(manifest_data))

        manifest = load_manifest(tmp_path)
        assert manifest.name == "test-plugin"
        assert manifest.hostname == "netbridge-test"
        assert manifest.version == "1.0.0"

    def test_missing_manifest(self, tmp_path):
        with pytest.raises(PluginLoadError, match="manifest.json not found"):
            load_manifest(tmp_path)

    def test_invalid_json(self, tmp_path):
        (tmp_path / "manifest.json").write_text("not json")
        with pytest.raises(PluginLoadError, match="invalid JSON"):
            load_manifest(tmp_path)

    def test_missing_required_field(self, tmp_path):
        (tmp_path / "manifest.json").write_text(json.dumps({"name": "x"}))
        with pytest.raises(PluginLoadError, match="missing required field"):
            load_manifest(tmp_path)

    def test_hostname_must_start_with_netbridge(self, tmp_path):
        manifest_data = {
            "name": "bad",
            "hostname": "not-netbridge",
            "description": "bad hostname",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))
        with pytest.raises(PluginLoadError, match="must start with 'netbridge-'"):
            load_manifest(tmp_path)

    def test_hostname_cannot_be_netbridge_exec(self, tmp_path):
        manifest_data = {
            "name": "sneaky",
            "hostname": "netbridge-exec",
            "description": "trying to hijack exec",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest_data))
        with pytest.raises(PluginLoadError, match="reserved"):
            load_manifest(tmp_path)
```

- [ ] **Step 2: Write failing tests for plugin discovery**

```python
class TestDiscoverPlugins:
    def test_discover_empty_dir(self, tmp_path):
        plugins = discover_plugins(tmp_path)
        assert plugins == []

    def test_discover_valid_plugin(self, tmp_path):
        plugin_dir = tmp_path / "my-plugin"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text(json.dumps({
            "name": "my-plugin",
            "hostname": "netbridge-myplugin",
            "description": "test",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (plugin_dir / "handlers.py").write_text(
            "from aiohttp import web\n"
            "def create_app():\n"
            "    app = web.Application()\n"
            "    return app\n"
        )

        plugins = discover_plugins(tmp_path)
        assert len(plugins) == 1
        assert plugins[0].name == "my-plugin"

    def test_skip_invalid_plugin(self, tmp_path):
        # Valid plugin
        good = tmp_path / "good"
        good.mkdir()
        (good / "manifest.json").write_text(json.dumps({
            "name": "good",
            "hostname": "netbridge-good",
            "description": "good",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (good / "handlers.py").write_text(
            "from aiohttp import web\n"
            "def create_app():\n"
            "    app = web.Application()\n"
            "    return app\n"
        )
        # Bad plugin (missing manifest)
        bad = tmp_path / "bad"
        bad.mkdir()

        plugins = discover_plugins(tmp_path)
        assert len(plugins) == 1
        assert plugins[0].name == "good"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /data/Projects/netbridge/netbridge-agent && uv run pytest tests/test_plugin_loader.py -v`
Expected: FAIL — module not found

- [ ] **Step 4: Implement `plugin_loader.py`**

```python
# netbridge-agent/src/netbridge_agent/plugin_loader.py
import importlib.util
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

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

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /data/Projects/netbridge/netbridge-agent && uv run pytest tests/test_plugin_loader.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/plugin_loader.py netbridge-agent/tests/test_plugin_loader.py
git commit -m "feat(agent): add plugin manifest loader and discovery"
```

---

### Task 4: Register plugin hostnames in intercept system

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/intercept.py`
- Modify: `netbridge-agent/src/netbridge_agent/app.py`
- Modify: `netbridge-agent/tests/test_intercept.py`

The `InterceptServer` currently only serves the `remote_exec` app. It needs to mount plugin apps under their hostnames. Since all traffic arrives as HTTP requests with a `Host` header, we can use aiohttp middleware to route by hostname.

- [ ] **Step 1: Write failing tests for multi-hostname intercept**

```python
# tests/test_intercept.py — append to existing file

class TestMultiHostnameIntercept:
    @pytest.mark.asyncio
    async def test_register_plugin_app(self):
        from netbridge_agent.intercept import InterceptServer
        from aiohttp import web

        async def hello(request):
            return web.json_response({"hello": "plugin"})

        plugin_app = web.Application()
        plugin_app.router.add_get("/hello", hello)

        server = InterceptServer()
        server.register_plugin("netbridge-test", plugin_app)
        await server.start()
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{server.port}/hello",
                    headers={"Host": "netbridge-test"},
                ) as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["hello"] == "plugin"
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_default_routes_still_work(self):
        """Remote exec routes still work without Host header."""
        from netbridge_agent.intercept import InterceptServer
        import aiohttp

        server = InterceptServer()
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{server.port}/health",
                    headers={"Host": "netbridge-exec"},
                ) as resp:
                    assert resp.status == 200
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_unknown_hostname_returns_404(self):
        from netbridge_agent.intercept import InterceptServer
        import aiohttp

        server = InterceptServer()
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{server.port}/health",
                    headers={"Host": "netbridge-unknown"},
                ) as resp:
                    assert resp.status == 404
        finally:
            await server.stop()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /data/Projects/netbridge/netbridge-agent && uv run pytest tests/test_intercept.py::TestMultiHostnameIntercept -v`
Expected: FAIL

- [ ] **Step 3: Modify `intercept.py` to support hostname-based routing**

Rewrite `InterceptServer` to use a dispatcher app that routes to sub-apps based on the `Host` header:

```python
class InterceptServer:
    def __init__(self) -> None:
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self.port: Optional[int] = None
        self._apps: dict[str, web.Application] = {}

    def register_plugin(self, hostname: str, app: web.Application) -> None:
        self._apps[hostname.lower()] = app
        MAGIC_HOSTS.add(hostname.lower())
        LOG.info("Registered plugin: %s", hostname)

    async def start(self) -> None:
        from .remote_exec import create_app as create_exec_app

        # Register the built-in remote exec app
        self._apps["netbridge-exec"] = create_exec_app()

        # Build dispatcher app that routes by Host header
        dispatcher = web.Application()

        @web.middleware
        async def route_by_host(request, handler):
            host = request.host.split(":")[0].lower()
            app = self._apps.get(host)
            if app is None:
                return web.json_response(
                    {"error": f"unknown service: {host}"}, status=404
                )
            # Match the request against the sub-app's router
            match_info = await app.router.resolve(request)
            request = request.clone(match_info=match_info)
            resp = await match_info.handler(request)
            return resp

        # For the dispatcher, we use a catch-all route
        async def dispatch(request: web.Request) -> web.Response:
            host = request.host.split(":")[0].lower()
            sub_app = self._apps.get(host)
            if sub_app is None:
                return web.json_response(
                    {"error": f"unknown service: {host}"}, status=404
                )
            # Use sub-app's router to find the handler
            resource = await sub_app.router.resolve(request)
            resp = await resource.handler(request)
            return resp

        dispatcher.router.add_route("*", "/{path_info:.*}", dispatch)

        self._runner = web.AppRunner(dispatcher)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await self._site.start()
        sockets = self._site._server.sockets  # type: ignore[union-attr]
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

Note: The exact dispatch mechanism may need adjustment — aiohttp's internal routing is fiddly. The implementer should test this carefully and may need to use `web.run_app` with `AppRunner` per sub-app, or use `request.match_info` from the sub-app's router. The key requirement is: HTTP `Host` header determines which sub-app handles the request.

- [ ] **Step 4: Update `is_magic_hostname` to check dynamic set**

The `MAGIC_HOSTS` set is already mutable. `register_plugin` adds to it. No code change needed — just verify `is_magic_hostname` still works after registration.

- [ ] **Step 5: Update `app.py` to load plugins on startup**

In `_async_main`, after the existing code, add plugin loading:

```python
# Discover and register plugins
from .plugin_loader import discover_plugins, load_plugin_app
from .config import get_app_dir

plugins_dir = get_app_dir() / "plugins"
if plugins_dir.is_dir():
    for manifest in discover_plugins(plugins_dir):
        try:
            plugin_app = load_plugin_app(manifest)
            # InterceptServer is created in _start_remote_exec
            # Store manifests for later registration
            self._plugin_manifests.append(manifest)
            logger.info(f"Plugin discovered: {manifest.name} ({manifest.hostname})")
        except Exception as e:
            logger.warning(f"Failed to load plugin {manifest.name}: {e}")
```

Add `self._plugin_manifests = []` to `__init__`.

In `_start_remote_exec`, after `await self._intercept_server.start()`, register plugin apps:

```python
for manifest in self._plugin_manifests:
    try:
        plugin_app = load_plugin_app(manifest)
        self._intercept_server.register_plugin(manifest.hostname, plugin_app)
    except Exception as e:
        logger.warning(f"Failed to register plugin {manifest.name}: {e}")
```

Actually, plugins should be always-on (not gated by the remote exec toggle). This means the InterceptServer needs to run always for plugins, and only the `netbridge-exec` hostname is gated.

Revised approach: Start the InterceptServer in `_async_main` always (for plugins). The remote exec toggle only controls whether `netbridge-exec` routes are active. Modify the intercept check in `agent.py`:

```python
if is_magic_hostname(host):
    if host.lower() == "netbridge-exec":
        # Remote exec requires the tray toggle
        if not enabled:
            return error "Remote exec is disabled"
    # All other magic hostnames (plugins) are always active
    if not server or not server.port:
        return error "Intercept server not running"
    # redirect to intercept server
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /data/Projects/netbridge/netbridge-agent && uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/intercept.py netbridge-agent/src/netbridge_agent/app.py netbridge-agent/tests/test_intercept.py
git commit -m "feat(agent): hostname-based routing for plugins in intercept server"
```

---

### Task 5: Add `/plugins` endpoint to remote_exec

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/remote_exec.py`
- Modify: `netbridge-agent/tests/test_remote_exec.py`

Add an endpoint that lists installed plugins so the laptop CLI can discover them.

- [ ] **Step 1: Write failing test**

```python
# tests/test_remote_exec.py — append
class TestPluginList:
    @pytest.mark.asyncio
    async def test_plugins_endpoint_returns_list(self, client):
        c = await client
        resp = await c.get("/plugins")
        assert resp.status == 200
        data = await resp.json()
        assert "plugins" in data
        assert isinstance(data["plugins"], list)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /data/Projects/netbridge/netbridge-agent && uv run pytest tests/test_remote_exec.py::TestPluginList -v`
Expected: FAIL — 404

- [ ] **Step 3: Implement `/plugins` endpoint**

Add to `remote_exec.py`:

```python
async def handle_plugins(request: web.Request) -> web.Response:
    """List installed plugins."""
    try:
        from .plugin_loader import discover_plugins
        from .config import get_app_dir

        plugins_dir = get_app_dir() / "plugins"
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
```

Add route in `create_app()`:
```python
app.router.add_get("/plugins", handle_plugins)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /data/Projects/netbridge/netbridge-agent && uv run pytest tests/test_remote_exec.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/remote_exec.py netbridge-agent/tests/test_remote_exec.py
git commit -m "feat(agent): add /plugins endpoint listing installed plugins"
```

---

## Part C: Plugin System — Laptop Side CLI

### Task 6: Tunnel client helper

**Files:**
- Create: `socks-proxy/src/socks_proxy/tunnel_client.py`
- Create: `socks-proxy/tests/test_tunnel_client.py`

A small helper that wraps HTTP calls through the SOCKS tunnel to `netbridge-exec` endpoints.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tunnel_client.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from socks_proxy.tunnel_client import TunnelClient


class TestTunnelClient:
    def test_default_proxy_url(self):
        client = TunnelClient()
        assert client.proxy_port == 1080

    def test_custom_proxy_port(self):
        client = TunnelClient(proxy_port=9999)
        assert client.proxy_port == 9999

    @pytest.mark.asyncio
    async def test_health_check(self):
        client = TunnelClient()
        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value={"status": "ok", "hostname": "VDI01"})
            mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_resp.__aexit__ = AsyncMock(return_value=False)

            mock_session = AsyncMock()
            mock_session.get = MagicMock(return_value=mock_resp)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_session

            result = await client.health()
            assert result["status"] == "ok"
```

- [ ] **Step 2: Implement `tunnel_client.py`**

```python
# socks-proxy/src/socks_proxy/tunnel_client.py
import aiohttp
from aiohttp_socks import ProxyConnector


class TunnelClient:
    """HTTP client that routes through the SOCKS tunnel to netbridge-exec."""

    def __init__(self, proxy_port: int = 1080):
        self.proxy_port = proxy_port
        self._base_url = "http://netbridge-exec"

    def _connector(self):
        return ProxyConnector.from_url(f"socks5://127.0.0.1:{self.proxy_port}")

    async def health(self) -> dict:
        async with aiohttp.ClientSession(connector=self._connector()) as session:
            async with session.get(f"{self._base_url}/health") as resp:
                resp.raise_for_status()
                return await resp.json()

    async def list_plugins(self) -> list[dict]:
        async with aiohttp.ClientSession(connector=self._connector()) as session:
            async with session.get(f"{self._base_url}/plugins") as resp:
                resp.raise_for_status()
                data = await resp.json()
                return data["plugins"]

    async def list_files(self, dir_path: str) -> dict:
        async with aiohttp.ClientSession(connector=self._connector()) as session:
            async with session.get(
                f"{self._base_url}/files", params={"dir": dir_path}
            ) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def upload_file(self, remote_path: str, data: bytes) -> dict:
        async with aiohttp.ClientSession(connector=self._connector()) as session:
            async with session.put(
                f"{self._base_url}/files/{remote_path}", data=data
            ) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def delete_file(self, remote_path: str) -> dict:
        async with aiohttp.ClientSession(connector=self._connector()) as session:
            async with session.delete(
                f"{self._base_url}/files/{remote_path}"
            ) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def exec(self, cmd: str, cwd: str | None = None, timeout: int = 300) -> dict:
        body = {"cmd": cmd, "timeout": timeout}
        if cwd:
            body["cwd"] = cwd
        async with aiohttp.ClientSession(connector=self._connector()) as session:
            async with session.post(
                f"{self._base_url}/exec", json=body
            ) as resp:
                resp.raise_for_status()
                return await resp.json()
```

Note: Add `aiohttp-socks` to `socks-proxy/pyproject.toml` dependencies.

- [ ] **Step 3: Run tests to verify they pass**

Run: `cd /data/Projects/netbridge/socks-proxy && uv run pytest tests/test_tunnel_client.py -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add socks-proxy/src/socks_proxy/tunnel_client.py socks-proxy/tests/test_tunnel_client.py socks-proxy/pyproject.toml
git commit -m "feat(socks): add tunnel client helper for netbridge-exec API"
```

---

### Task 7: Plugin CLI subcommand

**Files:**
- Create: `socks-proxy/src/socks_proxy/plugin_cli.py`
- Create: `socks-proxy/tests/test_plugin_cli.py`

Implements `netbridge plugin {list,install,uninstall,update,info,logs}`.

- [ ] **Step 1: Write failing tests for plugin list**

```python
# tests/test_plugin_cli.py
import pytest
from unittest.mock import AsyncMock, patch
from socks_proxy.plugin_cli import cmd_list, cmd_install, cmd_uninstall


class TestPluginList:
    @pytest.mark.asyncio
    async def test_list_plugins(self, capsys):
        mock_client = AsyncMock()
        mock_client.list_plugins = AsyncMock(return_value=[
            {"name": "gauth", "hostname": "netbridge-gauth", "version": "1.0.0", "description": "GCloud auth"},
        ])
        await cmd_list(mock_client)
        captured = capsys.readouterr()
        assert "gauth" in captured.out

    @pytest.mark.asyncio
    async def test_list_empty(self, capsys):
        mock_client = AsyncMock()
        mock_client.list_plugins = AsyncMock(return_value=[])
        await cmd_list(mock_client)
        captured = capsys.readouterr()
        assert "no plugins" in captured.out.lower()
```

- [ ] **Step 2: Write failing tests for plugin install**

```python
class TestPluginInstall:
    @pytest.mark.asyncio
    async def test_install_clones_and_pushes(self, tmp_path):
        mock_client = AsyncMock()
        mock_client.upload_file = AsyncMock(return_value={"status": "ok"})
        mock_client.exec = AsyncMock(return_value={"exit_code": 0, "stdout": "", "stderr": ""})
        mock_client.health = AsyncMock(return_value={"status": "ok", "cwd": "C:\\Users\\test"})

        with patch("socks_proxy.plugin_cli._clone_plugin") as mock_clone:
            mock_clone.return_value = tmp_path / "test-plugin"
            plugin_dir = tmp_path / "test-plugin"
            plugin_dir.mkdir()
            (plugin_dir / "manifest.json").write_text('{"name":"test","hostname":"netbridge-test","description":"t","version":"1.0.0","entry_point":"handlers.py"}')
            (plugin_dir / "handlers.py").write_text("pass")

            await cmd_install(mock_client, "https://dev.azure.com/org/repo", "test-plugin", tmp_path)

            assert mock_client.upload_file.call_count >= 2  # manifest + handlers
```

- [ ] **Step 3: Implement `plugin_cli.py`**

```python
# socks-proxy/src/socks_proxy/plugin_cli.py
import argparse
import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .tunnel_client import TunnelClient

LOG = logging.getLogger(__name__)

# Remote plugin install path on VDI
REMOTE_PLUGINS_DIR = None  # Resolved dynamically from health endpoint


async def _get_remote_plugins_dir(client: TunnelClient) -> str:
    """Get the plugins directory on the VDI."""
    health = await client.health()
    # %LOCALAPPDATA%/NetBridge/plugins
    # We derive it from the health cwd or just use a known path
    return "%LOCALAPPDATA%\\NetBridge\\plugins"


def _clone_plugin(repo_url: str, plugin_name: str, work_dir: Path) -> Path:
    """Clone a repo and return the path to the plugin subdirectory."""
    clone_dir = work_dir / "repo"
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
        check=True,
        capture_output=True,
    )
    plugin_dir = clone_dir / plugin_name
    if not plugin_dir.is_dir():
        raise FileNotFoundError(
            f"Plugin '{plugin_name}' not found in repo. "
            f"Available: {[d.name for d in clone_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]}"
        )
    return plugin_dir


async def _push_directory(client: TunnelClient, local_dir: Path, remote_dir: str) -> None:
    """Recursively push a local directory to the VDI."""
    for item in sorted(local_dir.rglob("*")):
        if item.is_file() and not item.name.startswith("."):
            relative = item.relative_to(local_dir)
            remote_path = f"{remote_dir}\\{str(relative).replace('/', chr(92))}"
            data = item.read_bytes()
            await client.upload_file(remote_path, data)
            print(f"  Pushed: {relative}")


async def cmd_list(client: TunnelClient) -> None:
    """List installed plugins on the VDI."""
    plugins = await client.list_plugins()
    if not plugins:
        print("No plugins installed.")
        return
    print(f"{'Name':<20} {'Version':<10} {'Hostname':<25} Description")
    print("-" * 80)
    for p in plugins:
        print(f"{p['name']:<20} {p['version']:<10} {p['hostname']:<25} {p['description']}")


async def cmd_install(
    client: TunnelClient,
    repo_url: str,
    plugin_name: str,
    work_dir: Path | None = None,
) -> None:
    """Install a plugin from a git repo to the VDI."""
    remote_base = await _get_remote_plugins_dir(client)

    with tempfile.TemporaryDirectory() as tmpdir:
        wd = work_dir or Path(tmpdir)
        print(f"Cloning {repo_url}...")
        plugin_dir = _clone_plugin(repo_url, plugin_name, wd)

        # Validate manifest locally
        manifest_path = plugin_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"No manifest.json in {plugin_name}/")
        manifest = json.loads(manifest_path.read_text())
        print(f"Installing plugin: {manifest['name']} v{manifest['version']}")

        # Push files to VDI
        remote_plugin_dir = f"{remote_base}\\{plugin_name}"
        print("Pushing files to VDI...")
        await _push_directory(client, plugin_dir, remote_plugin_dir)

        # Run install script if present
        install_script = f"{remote_plugin_dir}\\install.py"
        if (plugin_dir / "install.py").exists():
            print("Running install script...")
            result = await client.exec(
                f"python {install_script}",
                cwd=remote_plugin_dir,
            )
            if result["exit_code"] != 0:
                print(f"Install script failed:\n{result['stderr']}")
                return
            if result["stdout"]:
                print(result["stdout"])

        print(f"Plugin '{plugin_name}' installed successfully.")
        print(f"Access via: curl --proxy socks5h://localhost:1080 http://{manifest['hostname']}/")


async def cmd_uninstall(client: TunnelClient, plugin_name: str) -> None:
    """Uninstall a plugin from the VDI."""
    remote_base = await _get_remote_plugins_dir(client)
    remote_plugin_dir = f"{remote_base}\\{plugin_name}"

    # Check if plugin exists
    result = await client.list_files(remote_plugin_dir)
    if "error" in result:
        print(f"Plugin '{plugin_name}' not found on VDI.")
        return

    # Run uninstall script if present
    uninstall_script = f"{remote_plugin_dir}\\uninstall.py"
    entries = result.get("entries", [])
    if any(e["name"] == "uninstall.py" for e in entries):
        print("Running uninstall script...")
        r = await client.exec(f"python {uninstall_script}", cwd=remote_plugin_dir)
        if r["stdout"]:
            print(r["stdout"])

    # Delete plugin directory
    print(f"Removing {plugin_name}...")
    await client.delete_file(remote_plugin_dir)
    print(f"Plugin '{plugin_name}' uninstalled.")


async def cmd_update(client: TunnelClient, repo_url: str, plugin_name: str) -> None:
    """Update a plugin: uninstall then reinstall."""
    print(f"Updating {plugin_name}...")
    await cmd_uninstall(client, plugin_name)
    await cmd_install(client, repo_url, plugin_name)


async def cmd_info(client: TunnelClient, plugin_name: str) -> None:
    """Show details about an installed plugin."""
    plugins = await client.list_plugins()
    for p in plugins:
        if p["name"] == plugin_name:
            print(f"Name:        {p['name']}")
            print(f"Version:     {p['version']}")
            print(f"Hostname:    {p['hostname']}")
            print(f"Description: {p['description']}")
            return
    print(f"Plugin '{plugin_name}' not found.")


async def cmd_logs(client: TunnelClient, plugin_name: str) -> None:
    """View logs for a plugin."""
    remote_base = await _get_remote_plugins_dir(client)
    log_path = f"{remote_base}\\{plugin_name}\\plugin.log"
    result = await client.exec(f'type "{log_path}"')
    if result["exit_code"] != 0:
        print(f"No logs found for '{plugin_name}'.")
    else:
        print(result["stdout"])


def add_plugin_subparser(subparsers) -> None:
    """Add the 'plugin' subparser to the CLI."""
    plugin_parser = subparsers.add_parser(
        "plugin",
        help="Manage VDI plugins",
    )
    plugin_sub = plugin_parser.add_subparsers(dest="plugin_command")

    plugin_sub.add_parser("list", help="List installed plugins on VDI")

    install_p = plugin_sub.add_parser("install", help="Install a plugin from a git repo")
    install_p.add_argument("repo_url", help="Git repo URL (e.g. https://dev.azure.com/org/project/_git/repo)")
    install_p.add_argument("plugin_name", help="Plugin directory name in the repo")

    uninstall_p = plugin_sub.add_parser("uninstall", help="Uninstall a plugin from VDI")
    uninstall_p.add_argument("plugin_name", help="Plugin name to uninstall")

    update_p = plugin_sub.add_parser("update", help="Update a plugin (reinstall from repo)")
    update_p.add_argument("repo_url", help="Git repo URL")
    update_p.add_argument("plugin_name", help="Plugin name to update")

    info_p = plugin_sub.add_parser("info", help="Show plugin details")
    info_p.add_argument("plugin_name", help="Plugin name")

    logs_p = plugin_sub.add_parser("logs", help="View plugin logs")
    logs_p.add_argument("plugin_name", help="Plugin name")

    plugin_parser.add_argument(
        "--proxy-port",
        type=int,
        default=1080,
        help="Local SOCKS proxy port (default: 1080)",
    )


def plugin_main(args) -> None:
    """Entry point for plugin subcommands."""
    client = TunnelClient(proxy_port=args.proxy_port)

    if args.plugin_command == "list":
        asyncio.run(cmd_list(client))
    elif args.plugin_command == "install":
        asyncio.run(cmd_install(client, args.repo_url, args.plugin_name))
    elif args.plugin_command == "uninstall":
        asyncio.run(cmd_uninstall(client, args.plugin_name))
    elif args.plugin_command == "update":
        asyncio.run(cmd_update(client, args.repo_url, args.plugin_name))
    elif args.plugin_command == "info":
        asyncio.run(cmd_info(client, args.plugin_name))
    elif args.plugin_command == "logs":
        asyncio.run(cmd_logs(client, args.plugin_name))
    else:
        print("Usage: netbridge plugin {list,install,uninstall,update,info,logs}")
```

- [ ] **Step 4: Add `aiohttp-socks` dependency to `pyproject.toml`**

```toml
dependencies = [
    "aiohttp>=3.9.0",
    "aiohttp-socks>=0.9.0",
    "orjson>=3.11.6",
    "shared-auth",
]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /data/Projects/netbridge/socks-proxy && uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add socks-proxy/src/socks_proxy/plugin_cli.py socks-proxy/tests/test_plugin_cli.py
git commit -m "feat(socks): add plugin CLI subcommands"
```

---

### Task 8: Update `__main__.py` import check and final integration

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/__main__.py`

- [ ] **Step 1: Add `plugin_loader` to import check**

Change the import check line to include `plugin_loader`:

```python
from . import agent, app, auth, config, credstore, dialogs, installer, intercept, legacy, plugin_loader, remote_exec, tray, tunnel, winauth, winproxy  # noqa: F401
```

- [ ] **Step 2: Run full test suites**

Run both:
```bash
cd /data/Projects/netbridge/netbridge-agent && uv run pytest tests/ -x -q
cd /data/Projects/netbridge/socks-proxy && uv run pytest tests/ -x -q
```
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/__main__.py
git commit -m "Add plugin_loader to --import-check"
```

---

## Summary

After all tasks:

**Laptop side:**
```bash
netbridge serve --relay wss://relay.example.com    # proxy (same as before)
netbridge plugin list                                # list VDI plugins
netbridge plugin install <repo_url> <plugin_name>    # install from any git repo
netbridge plugin uninstall <plugin_name>             # remove plugin
netbridge plugin update <repo_url> <plugin_name>     # reinstall latest
netbridge plugin info <plugin_name>                  # show details
netbridge plugin logs <plugin_name>                  # view logs
```

**VDI agent side:**
- Plugins auto-discovered from `%LOCALAPPDATA%/NetBridge/plugins/<name>/`
- Each plugin has `manifest.json` + `handlers.py` + optional `install.py`/`uninstall.py`
- Plugin hostnames always active through tunnel (not gated by exec toggle)
- `netbridge-exec` remains gated by tray toggle
- `/plugins` endpoint lists installed plugins

**Brew:**
- Formula renamed from `netbridge-socks` to `netbridge`
- `brew install chrishham/tap/netbridge`
- Service wrapper updated for new binary name
