# Plugin Install UX & Password Detection

**Date:** 2026-05-21
**Scope:** Two features for the gauth plugin and socks-proxy CLI

---

## Feature 1: Laptop-Side Plugin Install

### Problem

`cmd_install` uploads plugin files to the VDI but does nothing on the laptop. Users must manually copy scripts (like `glogin-auto`) and create config files. This should be automated.

### Design

After successful VDI-side install, `cmd_install` checks for a `laptop/` directory in the cloned plugin repo. Convention-based structure:

```
gauth/
  laptop/
    bin/
      glogin-auto          # → ~/.local/bin/glogin-auto (chmod +x)
    config/
      .env.template        # → ~/.config/gauth/.env (only if .env doesn't exist)
```

**Rules:**
- `laptop/bin/*` — each file copied to `~/.local/bin/`, made executable. Existing files are overwritten (updates should refresh scripts).
- `laptop/config/.env.template` — copied to `~/.config/<plugin_name>/.env` only if the `.env` does not already exist. Never overwrite user credentials.
- After copying, print a summary: what was installed, what env vars need filling in `.env`.
- If `laptop/` doesn't exist in the plugin, skip silently (backward compatible).

**Changes required:**

1. **`socks-proxy/src/socks_proxy/plugin_cli.py`** — `cmd_install()`: after VDI install succeeds, call a new `_install_laptop_files(plugin_dir, plugin_name)` function.
2. **`gauth` plugin repo** — add `laptop/bin/glogin-auto` (move from `~/dotfiles/glogin-auto/glogin-auto`) and `laptop/config/.env.template`.

### .env.template contents

```
# glogin-auto configuration
# Fill in your credentials and source this file, or set these as environment variables.
GOOGLE_EMAIL=
NBG_USERNAME=
NBG_PASSWORD=
```

### Output example

```
  Laptop setup:
    Installed: ~/.local/bin/glogin-auto
    Created:   ~/.config/gauth/.env (fill in your credentials)
```

If `.env` already exists:

```
  Laptop setup:
    Installed: ~/.local/bin/glogin-auto
    Skipped:   ~/.config/gauth/.env (already exists)
```

---

## Feature 2: Password Expiry Detection

### Problem

When the NBG password is wrong or expired, `auth_flow.py` loops through 20 steps trying to find UI elements, eventually times out, and returns a generic error. Users get no indication that the password is the issue.

### Design

After the password submit step in `auth_flow.py`, add a detection check:

1. After typing the password and pressing Enter, wait for page load.
2. Check for known error strings on the page: `"Wrong password"`, `"password is incorrect"`, `"account is locked"`, `"password expired"`, `"password has expired"`, `"Your password has changed"`.
3. If any match is found, return immediately with: `{"error": "auth_failed", "detail": "<matched text>"}`.
4. Also save a debug screenshot before returning.

**Changes required:**

1. **`gauth/auth_flow.py`** — after the password step's `wait_for_load_state`, scan `page.text_content("body")` for error patterns. If found, output `{"error": "auth_failed", "detail": "..."}` to stdout and exit 0 (not exit 1 — this is a known failure, not a crash).
2. **`gauth/handlers.py`** — already handles `"error" in result` and returns it as HTTP 500. Change to return HTTP 401 when `result.get("error") == "auth_failed"` for better semantics.
3. **`~/dotfiles/glogin-auto/glogin-auto`** — after the curl to `/auth`, check if the error field equals `auth_failed`. If so, print: `"Authentication failed: <detail>"` and `"Update your password in ~/.config/glogin-auto/.env"`, then exit 1.

---

## Out of Scope

- Plugin `update` laptop-side handling (update already calls uninstall + install, so laptop files get refreshed automatically).
- Plugin `uninstall` laptop-side cleanup (would need a convention for what to remove — defer to a future iteration).
- Interactive password re-prompt in `glogin-auto` (decided: print and exit).
