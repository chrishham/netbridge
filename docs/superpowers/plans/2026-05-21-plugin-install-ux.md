# Plugin Install UX & Password Detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `plugin install` set up laptop-side scripts and config automatically, and detect password failures during SSO auth instead of timing out.

**Architecture:** Two independent features. Feature 1 adds a `_install_laptop_files()` helper to `plugin_cli.py` that processes a `laptop/` directory from the cloned plugin repo using convention-based paths (`bin/` → `~/.local/bin/`, `config/.env.template` → `~/.config/<name>/.env`). Feature 2 adds error detection to `auth_flow.py` after the password submit step, returns structured `auth_failed` errors, and updates `glogin-auto` to handle them.

**Tech Stack:** Python 3.14, aiohttp, Playwright (VDI-side), bash, pytest

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `socks-proxy/src/socks_proxy/plugin_cli.py` | Modify | Add `_install_laptop_files()`, call it from `cmd_install()` |
| `socks-proxy/tests/test_plugin_cli.py` | Modify | Tests for laptop-side install logic |
| `gauth/laptop/bin/glogin-auto` | Create (in plugin repo) | The glogin-auto bash script (moved from dotfiles) |
| `gauth/laptop/config/.env.template` | Create (in plugin repo) | Credential template |
| `gauth/auth_flow.py` | Modify (in plugin repo) | Password error detection after submit |
| `gauth/handlers.py` | Modify (in plugin repo) | Return 401 for auth_failed errors |
| `~/dotfiles/glogin-auto/glogin-auto` | Modify | Handle auth_failed errors with actionable message |

---

### Task 1: Add `_install_laptop_files()` to plugin_cli.py

**Files:**
- Modify: `socks-proxy/src/socks_proxy/plugin_cli.py`
- Modify: `socks-proxy/tests/test_plugin_cli.py`

- [ ] **Step 1: Write failing tests for `_install_laptop_files`**

Add a new test class `TestInstallLaptopFiles` to `socks-proxy/tests/test_plugin_cli.py`:

```python
from socks_proxy.plugin_cli import _install_laptop_files


class TestInstallLaptopFiles:
    def test_copies_bin_files_and_makes_executable(self, tmp_path, capsys):
        plugin_dir = tmp_path / "gauth"
        (plugin_dir / "laptop" / "bin").mkdir(parents=True)
        (plugin_dir / "laptop" / "bin" / "glogin-auto").write_text("#!/bin/bash\necho hi")

        bin_dir = tmp_path / "bin"
        config_dir = tmp_path / "config"
        _install_laptop_files(plugin_dir, "gauth", bin_dir=bin_dir, config_dir=config_dir)

        installed = bin_dir / "glogin-auto"
        assert installed.exists()
        assert installed.read_text() == "#!/bin/bash\necho hi"
        assert installed.stat().st_mode & 0o111  # executable
        out = capsys.readouterr().out
        assert "glogin-auto" in out

    def test_creates_env_from_template_if_missing(self, tmp_path, capsys):
        plugin_dir = tmp_path / "gauth"
        (plugin_dir / "laptop" / "config").mkdir(parents=True)
        (plugin_dir / "laptop" / "config" / ".env.template").write_text("KEY=\n")

        bin_dir = tmp_path / "bin"
        config_dir = tmp_path / "config"
        _install_laptop_files(plugin_dir, "gauth", bin_dir=bin_dir, config_dir=config_dir)

        env_file = config_dir / "gauth" / ".env"
        assert env_file.exists()
        assert env_file.read_text() == "KEY=\n"
        out = capsys.readouterr().out
        assert "Created" in out

    def test_skips_env_if_already_exists(self, tmp_path, capsys):
        plugin_dir = tmp_path / "gauth"
        (plugin_dir / "laptop" / "config").mkdir(parents=True)
        (plugin_dir / "laptop" / "config" / ".env.template").write_text("NEW=\n")

        config_dir = tmp_path / "config"
        (config_dir / "gauth").mkdir(parents=True)
        (config_dir / "gauth" / ".env").write_text("EXISTING=secret\n")

        bin_dir = tmp_path / "bin"
        _install_laptop_files(plugin_dir, "gauth", bin_dir=bin_dir, config_dir=config_dir)

        assert (config_dir / "gauth" / ".env").read_text() == "EXISTING=secret\n"
        out = capsys.readouterr().out
        assert "Skipped" in out

    def test_no_laptop_dir_is_silent(self, tmp_path, capsys):
        plugin_dir = tmp_path / "gauth"
        plugin_dir.mkdir()

        bin_dir = tmp_path / "bin"
        config_dir = tmp_path / "config"
        _install_laptop_files(plugin_dir, "gauth", bin_dir=bin_dir, config_dir=config_dir)

        out = capsys.readouterr().out
        assert "Laptop setup" not in out

    def test_multiple_bin_files(self, tmp_path, capsys):
        plugin_dir = tmp_path / "myplugin"
        (plugin_dir / "laptop" / "bin").mkdir(parents=True)
        (plugin_dir / "laptop" / "bin" / "tool-a").write_text("#!/bin/bash\na")
        (plugin_dir / "laptop" / "bin" / "tool-b").write_text("#!/bin/bash\nb")

        bin_dir = tmp_path / "bin"
        config_dir = tmp_path / "config"
        _install_laptop_files(plugin_dir, "myplugin", bin_dir=bin_dir, config_dir=config_dir)

        assert (bin_dir / "tool-a").exists()
        assert (bin_dir / "tool-b").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /mnt/data/projects/netbridge/socks-proxy && uv run pytest tests/test_plugin_cli.py::TestInstallLaptopFiles -v`
Expected: FAIL — `ImportError: cannot import name '_install_laptop_files'`

- [ ] **Step 3: Implement `_install_laptop_files`**

Add this function to `socks-proxy/src/socks_proxy/plugin_cli.py`, above `cmd_install`:

```python
def _install_laptop_files(plugin_dir, plugin_name, bin_dir=None, config_dir=None):
    """Install laptop-side files from plugin's laptop/ directory."""
    laptop_dir = plugin_dir / "laptop"
    if not laptop_dir.is_dir():
        return

    if bin_dir is None:
        bin_dir = Path.home() / ".local" / "bin"
    if config_dir is None:
        config_dir = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))

    installed = []
    skipped = []

    laptop_bin = laptop_dir / "bin"
    if laptop_bin.is_dir():
        bin_dir.mkdir(parents=True, exist_ok=True)
        for f in sorted(laptop_bin.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                dest = bin_dir / f.name
                shutil.copy2(f, dest)
                dest.chmod(dest.stat().st_mode | 0o755)
                installed.append(f"~/.local/bin/{f.name}")

    env_template = laptop_dir / "config" / ".env.template"
    if env_template.is_file():
        env_dest_dir = config_dir / plugin_name
        env_dest = env_dest_dir / ".env"
        if env_dest.exists():
            skipped.append(f"~/.config/{plugin_name}/.env (already exists)")
        else:
            env_dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(env_template, env_dest)
            installed.append(f"~/.config/{plugin_name}/.env (fill in your credentials)")

    if installed or skipped:
        print("  Laptop setup:")
        for item in installed:
            label = "Created" if ".env" in item else "Installed"
            print(f"    {label}: {item}")
        for item in skipped:
            print(f"    Skipped: {item}")
```

Also add `import os` if not already present (it is not — check; actually `os` is not imported in plugin_cli.py currently, but `Path` is from `pathlib`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /mnt/data/projects/netbridge/socks-proxy && uv run pytest tests/test_plugin_cli.py::TestInstallLaptopFiles -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Wire `_install_laptop_files` into `cmd_install`**

In `cmd_install()`, after the "Plugin installed and loaded!" success block (line ~211), add:

```python
        _install_laptop_files(plugin_dir, plugin_name)
```

This goes inside the `try` block, before the `finally` that cleans up `repo_dir`.

- [ ] **Step 6: Update the existing install test to verify laptop files are handled**

In `TestPluginInstall.test_install_clones_and_pushes`, add a `laptop/bin/` directory to the test fixture and verify `_install_laptop_files` is called. Since the function uses real filesystem paths, mock it:

Add after the existing assertions in `test_install_clones_and_pushes`:

```python
    def test_install_calls_laptop_files(self, tmp_path):
        plugin_dir = tmp_path / "repo" / "test-plugin"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "manifest.json").write_text(json.dumps({
            "name": "test", "hostname": "netbridge-test",
            "description": "test plugin", "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (plugin_dir / "handlers.py").write_text("pass")

        exec_resp = {"exit_code": 0, "stdout": "C:\\Users\\user\\AppData\\Local"}
        ok_resp = {"status": "ok"}
        reload_resp = {"status": "ok", "added": ["netbridge-test"], "removed": []}

        with patch("socks_proxy.plugin_cli._clone_repo") as mock_clone, \
             patch("socks_proxy.plugin_cli._curl") as mock_curl, \
             patch("socks_proxy.plugin_cli._install_laptop_files") as mock_laptop:
            mock_clone.return_value = tmp_path / "repo"
            mock_curl.side_effect = [exec_resp, ok_resp, ok_resp, reload_resp]
            cmd_install(1080, "https://example.com/repo.git", "test-plugin")
            mock_laptop.assert_called_once()
```

- [ ] **Step 7: Run all plugin CLI tests**

Run: `cd /mnt/data/projects/netbridge/socks-proxy && uv run pytest tests/test_plugin_cli.py -v`
Expected: All tests PASS

- [ ] **Step 8: Commit**

```bash
git add socks-proxy/src/socks_proxy/plugin_cli.py socks-proxy/tests/test_plugin_cli.py
git commit -m "Add laptop-side file install to plugin install flow"
```

---

### Task 2: Create gauth laptop/ directory in plugin repo

**Files:**
- Create: `/tmp/netbridge-plugins/gauth/laptop/bin/glogin-auto`
- Create: `/tmp/netbridge-plugins/gauth/laptop/config/.env.template`

- [ ] **Step 1: Create the .env.template**

Create `/tmp/netbridge-plugins/gauth/laptop/config/.env.template`:

```
# glogin-auto configuration
# Fill in your credentials below.
GOOGLE_EMAIL=
NBG_USERNAME=
NBG_PASSWORD=
```

- [ ] **Step 2: Copy glogin-auto script to laptop/bin/**

Copy `~/dotfiles/glogin-auto/glogin-auto` to `/tmp/netbridge-plugins/gauth/laptop/bin/glogin-auto`.

The script should be identical to the current dotfiles version — it will be updated in Task 4 for auth_failed handling.

- [ ] **Step 3: Update manifest version**

Update `/tmp/netbridge-plugins/gauth/manifest.json` version from `1.0.1` to `1.1.0`.

- [ ] **Step 4: Commit in plugin repo**

```bash
cd /tmp/netbridge-plugins
git add gauth/laptop/ gauth/manifest.json
git commit -m "Add laptop/ directory with glogin-auto script and .env template"
```

---

### Task 3: Add password error detection to auth_flow.py

**Files:**
- Modify: `/tmp/netbridge-plugins/gauth/auth_flow.py`
- Modify: `/tmp/netbridge-plugins/gauth/handlers.py`

- [ ] **Step 1: Add error detection after password submit in auth_flow.py**

In `auth_flow.py`, after the password step (the block starting at line 141 with `if pw_visible:`), replace the password handling block with one that includes post-submit error checking:

```python
                if pw_visible:
                    try:
                        await page.locator(
                            'input[type="password"]'
                        ).first.click(timeout=5000)
                        await page.keyboard.type(password, delay=80)
                        await asyncio.sleep(1)
                        await page.keyboard.press("Enter")
                        await page.wait_for_load_state("networkidle", timeout=15000)
                        LOG.info("Password step completed")

                        # Check for authentication errors after password submit
                        await asyncio.sleep(2)
                        body_text = await page.text_content("body") or ""
                        error_patterns = [
                            "Wrong password",
                            "password is incorrect",
                            "account is locked",
                            "password expired",
                            "password has expired",
                            "Your password has changed",
                            "credentials are incorrect",
                        ]
                        for pattern in error_patterns:
                            if pattern.lower() in body_text.lower():
                                LOG.error("Auth failed: %s", pattern)
                                try:
                                    await page.screenshot(
                                        path=os.path.join(PLUGIN_DIR, "gauth_auth_failed.png")
                                    )
                                except Exception:
                                    pass
                                return json.dumps({"error": "auth_failed", "detail": pattern})
                    except Exception as e:
                        LOG.error("Step %d: password interaction FAILED: %s", step, e)
                    continue
```

Wait — the function returns a `str` (the auth code). Returning a JSON string from inside the function would break the contract. Instead, we need to use a different mechanism. The `main()` function at the bottom catches exceptions and writes JSON to stdout. Let's raise a custom exception:

Add near the top of `auth_flow.py` (after imports):

```python
class AuthFailedError(Exception):
    """Raised when SSO login fails due to wrong/expired credentials."""
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)
```

Then in the password block, instead of returning JSON, raise this exception:

```python
                        for pattern in error_patterns:
                            if pattern.lower() in body_text.lower():
                                LOG.error("Auth failed: %s", pattern)
                                try:
                                    await page.screenshot(
                                        path=os.path.join(PLUGIN_DIR, "gauth_auth_failed.png")
                                    )
                                except Exception:
                                    pass
                                raise AuthFailedError(pattern)
```

Then update `main()` to handle it:

```python
def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    body = json.loads(sys.stdin.read())
    try:
        code = asyncio.run(
            run_auth_flow(body["url"], body["email"], body["password"])
        )
        json.dump({"code": code}, sys.stdout)
    except AuthFailedError as e:
        LOG.error("Authentication failed: %s", e.detail)
        json.dump({"error": "auth_failed", "detail": e.detail}, sys.stdout)
    except Exception as e:
        LOG.exception("Auth flow failed")
        json.dump({"error": str(e)}, sys.stdout)
        sys.exit(1)
```

Note: `AuthFailedError` exits with code 0 (not 1), because it's a known failure, not a crash. This matters because `handlers.py` treats non-zero exit as a generic error.

- [ ] **Step 2: Update handlers.py to return 401 for auth_failed**

In `handlers.py`, the `handle_auth` function currently does:

```python
    if "error" in result:
        return web.json_response(result, status=500)
```

Change to:

```python
    if "error" in result:
        status = 401 if result.get("error") == "auth_failed" else 500
        return web.json_response(result, status=status)
```

- [ ] **Step 3: Commit in plugin repo**

```bash
cd /tmp/netbridge-plugins
git add gauth/auth_flow.py gauth/handlers.py
git commit -m "Detect password errors after SSO login, return structured auth_failed"
```

---

### Task 4: Update glogin-auto to handle auth_failed errors

**Files:**
- Modify: `/tmp/netbridge-plugins/gauth/laptop/bin/glogin-auto`
- Modify: `~/dotfiles/glogin-auto/glogin-auto`

- [ ] **Step 1: Add auth_failed handling to glogin-auto**

In both copies of glogin-auto, find the error handling block after the curl to `/auth` (the section that checks `$ERROR`):

```bash
if [[ -n "$ERROR" ]]; then
    echo "Error from VDI auth helper: $ERROR"
```

Replace with:

```bash
if [[ -n "$ERROR" ]]; then
    if [[ "$ERROR" == "auth_failed" ]]; then
        DETAIL=$(echo "$RESPONSE" | jq -r '.detail // "unknown reason"' 2>/dev/null)
        echo "Authentication failed: $DETAIL"
        echo ""
        echo "Your password may be expired or incorrect."
        echo "Update it in: ~/.config/glogin-auto/.env"
        exit 1
    fi
    echo "Error from VDI auth helper: $ERROR"
```

The rest of the existing error block (debug HTML save, exit 1) stays as-is for non-auth errors.

- [ ] **Step 2: Also update the .env search path to include the new config location**

In the glogin-auto script, the `.env` search already includes `$XDG_CONFIG_HOME/glogin-auto/.env` which will match `~/.config/glogin-auto/.env`. But note the plugin name is `gauth`, not `glogin-auto`. The convention uses the plugin name, so the `.env` will land at `~/.config/gauth/.env`.

Update the `.env` search candidates in glogin-auto to also check `~/.config/gauth/.env`:

```bash
    for _candidate in \
        "$_config_dir/.env" \
        "${XDG_CONFIG_HOME:-$HOME/.config}/gauth/.env" \
        "$HOME/Projects/556-devops-mcp-servers/config/.env" \
        "/mnt/data/projects/556-devops-mcp-servers/config/.env"; do
```

And update the auth_failed message to reference the correct path:

```bash
        echo "Update it in: ${ENV_FILE:-~/.config/gauth/.env}"
```

- [ ] **Step 3: Commit both copies**

```bash
cd /tmp/netbridge-plugins
git add gauth/laptop/bin/glogin-auto
git commit -m "Handle auth_failed errors with actionable password message"
```

```bash
cd ~/dotfiles
git add glogin-auto/glogin-auto
git commit -m "Handle auth_failed errors, add ~/.config/gauth/.env to search path"
```

---

### Task 5: Run all tests and verify

- [ ] **Step 1: Run socks-proxy tests**

Run: `cd /mnt/data/projects/netbridge/socks-proxy && uv run pytest tests/ -x -q`
Expected: All tests PASS

- [ ] **Step 2: Run agent tests**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run pytest tests/ -x -q`
Expected: All tests PASS (no agent-side changes, but verify nothing is broken)

- [ ] **Step 3: Final commit if any fixups needed**

Only if test failures require adjustments.
