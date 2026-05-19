# Plan: Tray Restart + Remote Exec API

Two independent features for the netbridge-agent.

---

## Feature 1: Tray "Restart" menu item

**Goal:** Let users restart the agent from the tray to reload config or recover from errors (SSL issues, stuck connections), without needing to find/relaunch the exe manually.

### Implementation

The restart pattern already exists in `app.py:request_change_relay_url()` — it spawns a new process with `--no-install` and signals the current one to exit. Extract this into a reusable method.

**Files to change:**

#### `app.py` — add `request_restart()`
```python
def request_restart(self) -> None:
    """Restart the application (from tray menu)."""
    from .installer import get_exe_path

    target_exe = get_exe_path()
    logger.info(f"Restart requested, relaunching: {target_exe}")
    try:
        subprocess.Popen(
            [str(target_exe), "--no-install"],
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
        )
    except OSError:
        logger.exception("Failed to launch new process")
        return

    self._pending_exit.set()
    if self._async_loop and self._stop_event:
        self._async_loop.call_soon_threadsafe(self._stop_event.set)
    if self.tray:
        self.tray.stop()
```

Then refactor `request_change_relay_url()` to call `self.request_restart()` instead of duplicating the launch+exit logic.

#### `tray.py` — add menu item

Add between "View Logs" and the separator before Install/Uninstall:
```python
pystray.MenuItem(
    "Restart",
    on_restart,
),
```
With callback:
```python
def on_restart(icon, item):
    self.app.request_restart()
```

### Testing
- Click Restart → app exits, new instance starts, reconnects with fresh config
- Verify logs show clean shutdown + startup sequence
- Verify `request_change_relay_url()` still works after refactor

---

## Feature 2: Remote Exec API (opt-in)

**Goal:** Optional local HTTP API on the agent for file operations and command execution, accessible through the SOCKS tunnel. Replaces the need for a separate `vdi-remote.py` script.

### Config

#### `config.py` — add two fields to `Config`:
```python
allow_remote_exec: bool = False
remote_exec_port: int = 19877
```

Update `to_dict()`, `from_dict()` accordingly. Both fields are opt-in and only written to config.json when non-default.

### New module: `remote_api.py`

A self-contained aiohttp server. Endpoints:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Status, hostname, pid, cwd |
| GET | `/files?dir=<path>` | List directory contents |
| GET | `/files/{path}` | Read/download file |
| PUT | `/files/{path}` | Write/upload file |
| DELETE | `/files/{path}` | Delete file or directory |
| POST | `/exec` | Run command, return stdout/stderr on completion |
| POST | `/exec/stream` | Run command, stream output as chunked response |

Key design points:
- Listens on `127.0.0.1` only (loopback)
- No authentication (protected by the tunnel's Azure AD auth)
- `client_max_size = 50MB` for file uploads
- Command timeout default: 300s (configurable per-request)
- Log to the agent's existing logger

```python
# remote_api.py — skeleton

import asyncio
import logging
import os
import shutil
from aiohttp import web

LOG = logging.getLogger(__name__)

def _resolve_path(raw: str) -> str:
    if os.path.isabs(raw):
        return os.path.normpath(raw)
    return os.path.normpath(os.path.join(os.getcwd(), raw))

async def handle_health(request): ...
async def handle_file_list(request): ...
async def handle_file_read(request): ...
async def handle_file_write(request): ...
async def handle_file_delete(request): ...
async def handle_exec(request): ...
async def handle_exec_stream(request): ...

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

async def start_remote_api(port: int) -> web.AppRunner:
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    LOG.info("Remote exec API started on 127.0.0.1:%d", port)
    return runner

async def stop_remote_api(runner: web.AppRunner) -> None:
    await runner.cleanup()
    LOG.info("Remote exec API stopped")
```

The handler implementations can be lifted directly from `vdi-remote.py` (same author, same codebase context).

### Integration in `app.py`

In `_async_main()`, start the API server if enabled:

```python
async def _async_main(self) -> None:
    self._stop_event = asyncio.Event()
    self._remote_api_runner = None

    # Start remote exec API if enabled
    if self.config.allow_remote_exec:
        from .remote_api import start_remote_api
        self._remote_api_runner = await start_remote_api(
            self.config.remote_exec_port
        )

    # ... existing auto_connect / keepalive logic ...

    await self._stop_event.wait()

    # Stop remote API
    if self._remote_api_runner:
        from .remote_api import stop_remote_api
        await stop_remote_api(self._remote_api_runner)

    # ... existing cleanup ...
```

### Usage

Enable in `config.json`:
```json
{
  "relay_url": "...",
  "allow_remote_exec": true,
  "remote_exec_port": 19877
}
```

From the laptop through the tunnel:
```bash
# Health check
curl --proxy socks5://localhost:1080 http://127.0.0.1:19877/health

# Run a command
curl --proxy socks5://localhost:1080 -X POST \
  -d '{"cmd":"dir C:\\Users"}' http://127.0.0.1:19877/exec

# Push a file
curl --proxy socks5://localhost:1080 \
  -T localfile.py http://127.0.0.1:19877/files/C:/Users/me/script.py
```

### Testing
- `allow_remote_exec: false` (default) → no HTTP server started, port not bound
- `allow_remote_exec: true` → server starts on configured port
- Verify all endpoints work through SOCKS tunnel
- Verify agent restart (Feature 1) correctly stops and restarts the API server
- Verify the API server doesn't interfere with the tunnel (separate port, same event loop)

---

## Implementation order

1. **Restart** first (small, self-contained, immediately useful)
2. **Remote exec** second (new module, more testing needed)

Both can be done on a single branch since they're additive and don't conflict.

## No relay changes needed

Both features are agent-only. The relay is untouched.
