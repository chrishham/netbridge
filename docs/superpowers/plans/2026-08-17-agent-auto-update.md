# Agent Auto-Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On startup, the Windows agent checks GitHub for a newer release and offers a tray notification to update.

**Architecture:** A new `updater.py` module checks the GitHub API (`/repos/chrishham/netbridge/releases/latest`) for the latest version, compares it against `APP_VERSION`, and returns update info. The `NetBridgeApp` fires this check once on startup in the async loop. If an update is available, a tray notification tells the user; clicking "Check for Updates" in the tray menu downloads the new exe, replaces itself via the existing `Installer` flow, and restarts.

**Tech Stack:** `aiohttp` (already a dependency) for async HTTP, `packaging.version.Version` (already a dependency) for version comparison, pystray notifications.

**Spec:** N/A — feature defined in conversation.

## Global Constraints

- Python >=3.14, Windows target (PyInstaller frozen exe)
- No new dependencies — use `aiohttp` (HTTP) and `packaging` (version cmp), both already in deps
- GitHub release URL: `https://github.com/chrishham/netbridge/releases/latest/download/netbridge.exe`
- GitHub API URL: `https://api.github.com/repos/chrishham/netbridge/releases/latest`
- Version format: semver, injected from `agent-v*` git tag by CI into `__version__`
- The `latest` GitHub release always carries the newest agent exe

---

### Task 1: Update checker module (`updater.py`)

**Files:**
- Create: `netbridge-agent/src/netbridge_agent/updater.py`
- Test: `netbridge-agent/tests/test_updater.py`

**Interfaces:**
- Consumes: `config.APP_VERSION` (current version string)
- Produces:
  - `UpdateInfo` dataclass: `version: str`, `download_url: str`
  - `async check_for_update() -> UpdateInfo | None` — returns info if newer version available, None otherwise
  - `async download_update(url: str, dest: Path) -> Path` — downloads exe to `dest`, returns path
  - `GITHUB_API_URL: str` — constant for testing
  - `DOWNLOAD_URL: str` — constant for testing

- [ ] **Step 1: Write the failing tests**

```python
# netbridge-agent/tests/test_updater.py
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netbridge_agent.updater import (
    UpdateInfo,
    check_for_update,
    download_update,
)


class TestCheckForUpdate:
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        response = AsyncMock()
        response.status = 200
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=False)
        session.get.return_value = response
        return session, response

    async def test_newer_version_available(self, mock_session):
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "agent-v2.0.0",
            "assets": [{"name": "netbridge.exe", "browser_download_url": "https://example.com/netbridge.exe"}],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is not None
        assert result.version == "2.0.0"
        assert result.download_url == "https://example.com/netbridge.exe"

    async def test_same_version_returns_none(self, mock_session):
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "agent-v1.0.0",
            "assets": [{"name": "netbridge.exe", "browser_download_url": "https://example.com/netbridge.exe"}],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_older_version_returns_none(self, mock_session):
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "agent-v0.9.0",
            "assets": [{"name": "netbridge.exe", "browser_download_url": "https://example.com/netbridge.exe"}],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_dev_version_skips_check(self, mock_session):
        """Version 0.0.0 means dev/source — never prompt for update."""
        session, _ = mock_session
        with patch("netbridge_agent.updater.APP_VERSION", "0.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_http_error_returns_none(self, mock_session):
        session, response = mock_session
        response.status = 404
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_network_error_returns_none(self):
        session = AsyncMock()
        session.get.side_effect = Exception("network error")
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_non_agent_tag_skipped(self, mock_session):
        """Tags like socks-v2.0.0 should not trigger agent updates."""
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "socks-v2.0.0",
            "assets": [],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_no_exe_asset_returns_none(self, mock_session):
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "agent-v2.0.0",
            "assets": [{"name": "other.zip", "browser_download_url": "https://example.com/other.zip"}],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None


class TestDownloadUpdate:
    async def test_downloads_to_dest(self, tmp_path):
        dest = tmp_path / "netbridge.exe"
        content = b"fake exe content"

        response = AsyncMock()
        response.status = 200
        response.content = MagicMock()
        # Simulate aiohttp's async chunked read
        chunks = [content, b""]
        response.content.read = AsyncMock(side_effect=chunks)
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=False)

        session = AsyncMock()
        session.get.return_value = response

        result = await download_update(session, "https://example.com/netbridge.exe", dest)
        assert result == dest
        assert dest.read_bytes() == content

    async def test_download_failure_raises(self, tmp_path):
        dest = tmp_path / "netbridge.exe"
        response = AsyncMock()
        response.status = 404
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=False)
        session = AsyncMock()
        session.get.return_value = response

        with pytest.raises(RuntimeError, match="Download failed"):
            await download_update(session, "https://example.com/netbridge.exe", dest)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd netbridge-agent && uv run pytest tests/test_updater.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'netbridge_agent.updater'`

- [ ] **Step 3: Write the implementation**

```python
# netbridge-agent/src/netbridge_agent/updater.py
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import aiohttp
from packaging.version import Version

from .config import APP_VERSION

logger = logging.getLogger(__name__)

GITHUB_API_URL = "https://api.github.com/repos/chrishham/netbridge/releases/latest"


@dataclass
class UpdateInfo:
    version: str
    download_url: str


async def check_for_update(session: aiohttp.ClientSession) -> Optional[UpdateInfo]:
    """Check GitHub for a newer agent release.

    Returns UpdateInfo if a newer version is available, None otherwise.
    Silently returns None on any error (network, parse, etc).
    """
    if APP_VERSION == "0.0.0":
        return None

    try:
        async with session.get(
            GITHUB_API_URL,
            headers={"Accept": "application/vnd.github+json"},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
    except Exception:
        logger.debug("Update check failed", exc_info=True)
        return None

    tag = data.get("tag_name", "")
    if not tag.startswith("agent-v"):
        return None

    remote_version = tag.removeprefix("agent-v")
    try:
        if Version(remote_version) <= Version(APP_VERSION):
            return None
    except Exception:
        return None

    assets = data.get("assets", [])
    for asset in assets:
        if asset.get("name") == "netbridge.exe":
            return UpdateInfo(
                version=remote_version,
                download_url=asset["browser_download_url"],
            )

    return None


CHUNK_SIZE = 64 * 1024


async def download_update(
    session: aiohttp.ClientSession,
    url: str,
    dest: Path,
) -> Path:
    """Download the update exe to dest. Raises RuntimeError on failure."""
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=300)) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Download failed: HTTP {resp.status}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            while True:
                chunk = await resp.content.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
    return dest
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd netbridge-agent && uv run pytest tests/test_updater.py -v`
Expected: All 9 tests PASS

- [ ] **Step 5: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/updater.py netbridge-agent/tests/test_updater.py
git commit -m "feat(agent): add update checker module"
```

---

### Task 2: Integrate auto-update into app startup and tray menu

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/app.py` — add startup check + `request_update` handler
- Modify: `netbridge-agent/src/netbridge_agent/tray.py` — add "Check for Updates" menu item

**Interfaces:**
- Consumes: `updater.check_for_update()`, `updater.download_update()`, `updater.UpdateInfo`
- Consumes: `installer.Installer.terminate_running_instances()`, `installer.Installer.copy_exe()`, `installer.Installer.save_installed_version()`, `installer.Installer.launch_installed()`
- Produces: `NetBridgeApp._check_for_update()` async method, `NetBridgeApp.request_check_update()` sync method (tray callback)

- [ ] **Step 1: Add the startup update check to `app.py`**

In `NetBridgeApp.__init__`, add a field to track pending update:

```python
# In __init__, after existing fields:
self._available_update: Optional["UpdateInfo"] = None
```

Add the import at top of file:

```python
from typing import Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from .updater import UpdateInfo
```

Add the update check method to `NetBridgeApp`:

```python
async def _check_for_update(self) -> None:
    """Check GitHub for a newer version. Shows tray notification if found."""
    from .updater import check_for_update

    try:
        async with aiohttp.ClientSession() as session:
            update = await check_for_update(session)
    except Exception:
        logger.debug("Update check failed", exc_info=True)
        return

    if update:
        self._available_update = update
        logger.info(f"Update available: v{update.version}")
        if self.tray:
            self.tray.show_notification(
                "Update Available",
                f"NetBridge v{update.version} is available. Right-click tray → Check for Updates.",
            )
            self.tray.update_menu()
```

Add the `import aiohttp` at top of file.

In `_async_main`, fire the check right after auto-connect (before `await self._stop_event.wait()`):

```python
# Check for updates (non-blocking, fire-and-forget)
asyncio.create_task(self._check_for_update())
```

- [ ] **Step 2: Add the update action handler to `app.py`**

```python
def request_check_update(self) -> None:
    """Check for updates and apply if available (from tray menu)."""
    if self._async_loop:
        self._async_loop.call_soon_threadsafe(
            lambda: asyncio.ensure_future(self._do_update())
        )

async def _do_update(self) -> None:
    """Download and apply the update."""
    import aiohttp
    from .updater import check_for_update, download_update
    from .installer import Installer, get_installed_exe_path
    from .config import get_app_dir

    if self.tray:
        self.tray.show_notification("Updating", "Downloading update...")

    try:
        async with aiohttp.ClientSession() as session:
            # Re-check in case it was triggered manually
            if not self._available_update:
                update = await check_for_update(session)
                if not update:
                    if self.tray:
                        self.tray.show_notification(
                            "No Update",
                            f"You're running the latest version (v{APP_VERSION}).",
                        )
                    return
                self._available_update = update

            update = self._available_update
            dest = get_app_dir() / "netbridge-update.exe"
            await download_update(session, update.download_url, dest)
    except Exception as e:
        logger.error(f"Update download failed: {e}")
        if self.tray:
            self.tray.show_notification("Update Failed", f"Download error: {e}")
        return

    # Apply the update: terminate old, copy new, save version, relaunch
    try:
        Installer.terminate_running_instances()
        target = get_installed_exe_path()
        import shutil, os
        temp = target.with_name(f"{target.name}.tmp")
        shutil.copy2(dest, temp)
        os.replace(temp, target)
        Installer.save_installed_version(update.version)
        dest.unlink(missing_ok=True)
        logger.info(f"Updated to v{update.version}, restarting")
    except Exception as e:
        logger.error(f"Update apply failed: {e}")
        if self.tray:
            self.tray.show_notification("Update Failed", f"Install error: {e}")
        return

    # Restart
    self.request_restart()
```

- [ ] **Step 3: Add "Check for Updates" to the tray menu in `tray.py`**

In `_create_menu`, add a menu item before the separator above Install/Uninstall:

```python
def on_check_update(icon, item):
    self.app.request_check_update()

def get_update_label(item):
    if self.app._available_update:
        return f"Update to v{self.app._available_update.version}"
    return "Check for Updates"
```

Add the menu item:

```python
pystray.MenuItem(
    get_update_label,
    on_check_update,
),
```

Place it right before the separator that precedes Install/Uninstall/Exit.

- [ ] **Step 4: Add `aiohttp` import to `app.py` if not already present**

Check the imports at the top of `app.py`. Add `import aiohttp` if missing.

- [ ] **Step 5: Add the `__main__.py` import-check update**

In `__main__.py` line 172, the `--import-check` block imports all modules. Add `updater` to the import list:

```python
from . import agent, app, auth, config, credstore, dialogs, installer, intercept, legacy, plugin_loader, remote_exec, tray, tunnel, updater, winauth, winproxy  # noqa: F401
```

- [ ] **Step 6: Run all agent tests**

Run: `cd netbridge-agent && uv run pytest -x -q`
Expected: All tests pass (including updater tests from Task 1)

- [ ] **Step 7: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/app.py netbridge-agent/src/netbridge_agent/tray.py netbridge-agent/src/netbridge_agent/__main__.py
git commit -m "feat(agent): auto-update check on startup with tray notification"
```
