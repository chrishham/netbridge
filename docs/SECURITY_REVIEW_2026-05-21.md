# NetBridge Full Codebase Security Review

**Date:** 2026-05-21
**Reviewers:** Codex CLI (gpt-5.4) + Claude Opus 4.6
**Scope:** All source files across netbridge-agent, socks-proxy, socks-proxy-win, relay, shared

---

## Executive Summary

Full security and correctness review of the NetBridge codebase — a token-authenticated TCP tunneling system (agent ↔ relay ↔ SOCKS proxy). The review identified **9 High**, **22 Medium**, and **12 Low** severity findings.

The most critical themes:

1. **remote_exec provides essentially unrestricted RCE** (H1–H5) — shell exec, file I/O, and deletion with no sandboxing, gated only by a UI toggle with auto-timeout. Plugin routes bypass the gate (M1).
2. **HTTP request smuggling** in the socks-proxy HTTP CONNECT handler (H6).
3. **JWT validation ordering** in the relay (H7) — authorization decisions made on unverified claims before signature verification.
4. **CRLF/header injection** in tunnel CONNECT requests (M21).
5. **DNS TOCTOU** enabling SSRF bypass via DNS rebinding (M3).

---

## High Severity

### H1 — Shell command injection via `create_subprocess_shell`

- **File:** `netbridge-agent/src/netbridge_agent/remote_exec.py:179-224, 232-283`
- **Issue:** `handle_exec` and `handle_exec_stream` pass user-supplied `cmd` directly to `asyncio.create_subprocess_shell()` with zero validation — no allowlisting, no command structure checks.
- **Impact:** Full remote code execution on the agent machine for any authenticated relay user when exec is toggled on.
- **Fix:** Use `create_subprocess_exec` with argument lists. Add configurable command allowlisting. Log all executed commands with authenticated identity.

### H2 — Arbitrary file write with no path restriction

- **File:** `netbridge-agent/src/netbridge_agent/remote_exec.py:133-150`
- **Issue:** `handle_file_write` accepts any path via `{path:.+}`, resolves it with `_resolve_path`, creates parent directories, and writes arbitrary content up to 50 MB. No sandboxing, no path allowlist.
- **Impact:** An authenticated tunnel user can overwrite config files, executables, the agent binary, or plant malicious content anywhere on the filesystem.
- **Fix:** Restrict writes to a configurable sandbox directory. Validate resolved path with `Path.is_relative_to()`.

### H3 — Arbitrary file/directory deletion

- **File:** `netbridge-agent/src/netbridge_agent/remote_exec.py:153-171`
- **Issue:** `handle_file_delete` can recursively delete any directory the agent user can write to via `shutil.rmtree`.
- **Impact:** Destructive attack — an authenticated user can wipe entire directory trees.
- **Fix:** Same sandbox restriction as H2.

### H4 — Arbitrary filesystem read

- **File:** `netbridge-agent/src/netbridge_agent/remote_exec.py:81-113`
- **Issue:** `handle_file_read` and `handle_file_list` allow reading any file and listing any directory with no path restrictions.
- **Impact:** Information disclosure — SSH keys, DPAPI credential store, config files, browser profiles, etc.
- **Fix:** Restrict to a configurable sandbox directory.

### H5 — Plugin uninstall runs arbitrary Python

- **File:** `netbridge-agent/src/netbridge_agent/remote_exec.py:344-417`
- **Issue:** `handle_plugin_uninstall` executes `uninstall.py` from the plugin directory without integrity checks. A malicious plugin can place any code there.
- **Impact:** Code execution at uninstall time. Combined with M1 (plugin routes bypass exec gate), this is reachable even when remote-exec is disabled.
- **Fix:** Validate `uninstall_script.resolve()` is within the plugin directory. Consider removing auto-execution of uninstall.py.

### H6 — HTTP request smuggling in socks-proxy

- **File:** `socks-proxy/src/socks_proxy/http_proxy.py:374-427`
- **Issue:** Forwards both `Content-Length` and `Transfer-Encoding: chunked` headers unchanged. The proxy switches to chunked handling when `Transfer-Encoding: chunked` is present, but a client sending both headers creates a framing disagreement with the upstream server.
- **Impact:** Classic request-smuggling/desync condition against internal HTTP services reached through the tunnel.
- **Fix:** Strip `Transfer-Encoding` when `Content-Length` is present, or reject requests with both headers. Normalize hop-by-hop headers.

### H7 — JWT claims checked before signature verification

- **File:** `shared/src/shared_auth/validate.py:155-280`
- **Issue:** `validate_arm_token` decodes the JWT unverified, reads `tid`/`iss`/`aud`/`exp` from the unverified payload, uses `tid` to construct the JWKS URL, and only calls `_verify_signature` near the end (line 239). All authorization decisions (user/group allowlists, expiration) are made on unverified data.
- **Impact:** An attacker controls which JWKS endpoint is queried. If signature verification is bypassed or fails open (see H8), all auth checks are meaningless.
- **Fix:** Move signature verification to immediately after JWKS key lookup, before checking any claims. Consider using a well-tested JWT library (PyJWT).

### H8 — Catch-all exception masks verification failures

- **File:** `shared/src/shared_auth/validate.py:277-280`
- **Issue:** `except Exception as e` catches any exception from the entire validation flow and converts it to `TokenValidationError`. Programming errors or unexpected exceptions before signature verification could be silently swallowed.
- **Impact:** Masked security-relevant errors; fragile to restructuring.
- **Fix:** Narrow the `except Exception` to only cover JWKS fetch and signature verification. Let programming errors propagate as 500s.

### H9 — Allowed-users cache sentinel confusion

- **File:** `shared/src/shared_auth/validate.py:63-71`
- **Issue:** `_allowed_users_cache` starts as `None`. `_get_allowed_users()` checks `if _allowed_users_cache is None` to decide whether to load. But `_load_comma_set` also returns `None` when the env var is empty — so the cache never takes effect when no allowlist is configured.
- **Impact:** Repeated env var reads on every request (performance). Pattern is fragile for similar sentinel uses elsewhere.
- **Fix:** Use a distinct sentinel (e.g., `_UNSET = object()`) to distinguish "not yet loaded" from "env var is empty".

---

## Medium Severity

### M1 — Exec gate bypass via plugin routes

- **File:** `netbridge-agent/src/netbridge_agent/remote_exec.py:420-430`
- **Issue:** `exec_gate_middleware` only checks path prefixes (`/files`, `/exec`, `/health`). Plugin management routes (`/plugins/reload`, `/plugins/uninstall`) are always available. Combined with H5, an attacker can trigger code execution without remote-exec being enabled.
- **Fix:** Gate plugin reload/uninstall behind the same approval control, or add a separate plugin management permission.

### M2 — Plugin directory permanently added to `sys.path`

- **File:** `netbridge-agent/src/netbridge_agent/plugin_loader.py:107-108`
- **Issue:** Each loaded plugin's directory is inserted at `sys.path[0]` and never removed. A malicious plugin can shadow standard library modules (e.g., `json.py`, `os.py`).
- **Fix:** Remove the plugin directory from `sys.path` after loading, or use an isolated import mechanism.

### M3 — DNS TOCTOU in `validate_destination`

- **File:** `netbridge-agent/src/netbridge_agent/agent.py:90-182`
- **Issue:** Resolves hostnames to check against SSRF blocklists, but the actual TCP connection resolves the hostname again. An attacker controlling DNS could return a safe IP during validation and loopback during connection.
- **Fix:** Resolve once, then connect to the resolved IP directly.

### M4 — Racy file permissions on credential store

- **File:** `netbridge-agent/src/netbridge_agent/credstore.py:97-116`
- **Issue:** File created with default permissions, then `chmod(0o600)` called afterward. Brief window where plaintext creds are world-readable on non-Windows.
- **Fix:** Use `os.open()` with `O_CREAT | O_WRONLY` and mode `0o600`, then `os.fdopen()`.

### M5 — Client-controlled subprocess timeout

- **File:** `netbridge-agent/src/netbridge_agent/remote_exec.py:190-195`
- **Issue:** The `timeout` field from the request body is used directly in `asyncio.wait_for` with no upper bound.
- **Fix:** Clamp to a configurable maximum: `min(body.get("timeout", 300), MAX_EXEC_TIMEOUT)`.

### M6 — `_resolve_path` has no confinement

- **File:** `netbridge-agent/src/netbridge_agent/remote_exec.py:38-47`
- **Issue:** `os.path.normpath` collapses `..` but the function freely resolves to any absolute path.
- **Fix:** Enforce resolved paths fall within a defined sandbox directory.

### M7 — Batch script injection in installer

- **File:** `netbridge-agent/src/netbridge_agent/installer.py:387-401`
- **Issue:** Path variable interpolated directly into batch script. Special batch characters (`&`, `|`, `%`) in path could execute unintended commands.
- **Fix:** Sanitize path for batch-safe characters, or use PowerShell with proper escaping.

### M8 — Config directory controlled by environment variable

- **File:** `netbridge-agent/src/netbridge_agent/config.py:43-44`
- **Issue:** `get_app_dir()` reads `LOCALAPPDATA` from environment. Tampered env var redirects credential storage.
- **Fix:** Use `SHGetKnownFolderPath` via ctypes on Windows, or validate the path.

### M9 — Missing type/presence validation on relay messages

- **File:** `netbridge-agent/src/netbridge_agent/agent.py:566-594`
- **Issue:** `stream_id`, `host`, `port` extracted from relay messages with `.get()` but no type or presence validation.
- **Fix:** Add explicit type and presence validation; return error to relay if fields are missing.

### M10 — No hop-by-hop header normalization

- **File:** `socks-proxy/src/socks_proxy/http_proxy.py:390-441`
- **Issue:** Doesn't normalize hop-by-hop headers or parse HTTP response framing. Keep-alive responses hang indefinitely.
- **Fix:** Strip hop-by-hop headers; handle keep-alive framing.

### M11 — Slowloris-style stream exhaustion

- **File:** `socks-proxy/src/socks_proxy/http_proxy.py:353-372`
- **Issue:** Opens tunnel connection before reading/validating client headers. A client only needs a valid request line to consume a stream, then can stall for 30 seconds.
- **Fix:** Read and validate headers before opening the upstream connection.

### M12 — Duplicate SOCKS5 failure responses

- **File:** `socks-proxy/src/socks_proxy/socks5.py:109-196`
- **Issue:** `_handle_greeting()` writes failure bytes then raises `Socks5Error`; outer handler catches it and sends a second reply. Protocol violation.
- **Fix:** Let the outer handler be the sole response writer, or don't re-raise after writing.

### M13 — Shutdown race in socks-proxy-win

- **File:** `socks-proxy-win/src/socks_proxy_win/app.py:149-299`
- **Issue:** `_async_main()` creates `self._stop_event`, but `_run_proxy()` overwrites it. Exit paths signal only the newer event; background thread blocks on the original.
- **Fix:** Use a single stop event created in `__init__` and never overwrite it.

### M14 — Unvalidated `stream_id` in relay

- **File:** `relay/src/relay/__main__.py:669`
- **Issue:** `stream_id` accepted as-is with no type check, length limit, or format validation. Enables memory abuse via long IDs and log injection via control characters.
- **Fix:** Validate string type, enforce max length (64 chars), reject non-alphanumeric characters.

### M15 — Stale `agent_ws` reference outside lock

- **File:** `relay/src/relay/__main__.py:783-784`
- **Issue:** `agent_ws` read inside `_state_lock`, then used outside it. Agent could reconnect between, making the reference stale. Message goes to closed socket.
- **Fix:** Re-check after send failure; re-send to new agent or fail the stream.

### M16 — Tenant ID not validated for path traversal

- **File:** `shared/src/shared_auth/validate.py:86-88`
- **Issue:** `tid` from unverified JWT used directly in JWKS URL construction. A `tid` like `../../some/path` could redirect the fetch.
- **Fix:** Validate `tid` matches UUID format (GUID regex) before use.

### M17 — TOCTOU in stale stream cleanup

- **File:** `relay/src/relay/__main__.py:436-456`
- **Issue:** Reads stale streams under lock, releases lock, re-acquires to pop. Between acquisitions, a stream could be reactivated.
- **Fix:** Re-check `last_activity` inside the second lock acquisition.

### M18 — Orphaned subprocess on client disconnect

- **File:** `netbridge-agent/src/netbridge_agent/remote_exec.py:249-283`
- **Issue:** `handle_exec_stream` doesn't guarantee child cleanup if `resp.write()` or `resp.prepare()` fails after subprocess starts.
- **Fix:** Wrap subprocess in `try/finally`; terminate/kill if `proc.returncode is None`.

### M19 — Symlink/junction attacks on install paths

- **File:** `netbridge-agent/src/netbridge_agent/installer.py:215-224, 363-400`
- **Issue:** Install/update/uninstall operate on `%LOCALAPPDATA%` and `%TEMP%` without checking for symlinks/junctions. Fixed `%TEMP%\netbridge_uninstall.bat` filename is raceable.
- **Fix:** Reject reparse points; use securely created random temp filename.

### M20 — Proxy resolution failure silently goes DIRECT

- **File:** `netbridge-agent/src/netbridge_agent/winproxy.py:270-288`
- **Issue:** `get_proxy_for_url_safe()` converts every proxy-resolution failure into `None`, treated as "no proxy".
- **Fix:** Distinguish "no proxy configured" from "resolution failed"; log failures and make direct fallback configurable.

### M21 — CRLF injection in CONNECT request

- **File:** `netbridge-agent/src/netbridge_agent/tunnel.py:76-79`
- **Issue:** `target_host` interpolated directly into CONNECT request line and `Host` header without rejecting control characters.
- **Impact:** Malicious relay-supplied hostname can inject headers into the corporate proxy request.
- **Fix:** Reject `\r`, `\n`, and other control characters. Bracket IPv6 literals.

### M22 — Missing `CompleteAuthToken` call

- **File:** `netbridge-agent/src/netbridge_agent/winauth.py:270-271`
- **Issue:** `SEC_I_COMPLETE_NEEDED` and `SEC_I_COMPLETE_AND_CONTINUE` accepted as success, but `CompleteAuthToken` is never called.
- **Fix:** Bind and invoke `CompleteAuthToken` when either status is returned.

---

## Low Severity

### L1 — Crash on `stream_id[:8]` when None

- **File:** `netbridge-agent/src/netbridge_agent/agent.py:601`
- **Fix:** Guard with `if not stream_id: return`.

### L2 — Plaintext password storage on non-Windows

- **File:** `netbridge-agent/src/netbridge_agent/credstore.py:107-108`
- **Fix:** Consider system keyring (`keyring` library) on non-Windows.

### L3 — `os._exit(0)` bypasses cleanup

- **File:** `netbridge-agent/src/netbridge_agent/app.py:335`
- **Fix:** Use `sys.exit(0)` or document why hard exit is necessary.

### L4 — Unbounded chunked transfer body drain

- **File:** `netbridge-agent/src/netbridge_agent/tunnel.py:97-134`
- **Fix:** Add maximum body size limit to `_drain_body`.

### L5 — SSPI output buffer not freed

- **File:** `netbridge-agent/src/netbridge_agent/winauth.py:280-282`
- **Fix:** Remove `ISC_REQ_ALLOCATE_MEMORY` flag or free with `FreeContextBuffer`.

### L6 — Race between tray thread toggle and async loop

- **File:** `netbridge-agent/src/netbridge_agent/app.py:400-428`
- **Fix:** Use `asyncio.Event` or `call_soon_threadsafe`.

### L7 — Pending connects don't fail fast on relay disconnect

- **File:** `socks-proxy/src/socks_proxy/tunnel.py:451-598`
- **Fix:** Resolve or fault `handler.connect_future` in `_receive_loop`.

### L8 — Raw repo URL with credentials printed to terminal

- **File:** `socks-proxy/src/socks_proxy/plugin_cli.py:196, 228-243`
- **Fix:** Sanitize URL before printing.

### L9 — `_is_loopback` doesn't cover all loopback representations

- **File:** `relay/src/relay/__main__.py:39-41`
- **Fix:** Use `ipaddress.ip_address(host).is_loopback`.

### L10 — Rate limit values with no upper bound

- **File:** `relay/src/relay/__main__.py:107-127`
- **Fix:** Add upper-bound validation with warnings.

### L11 — Algorithm handling (correct defense)

- **File:** `shared/src/shared_auth/validate.py:310-313`
- **Note:** JWK's `alg` used over header's — correct defense against algorithm confusion. No fix needed; add a comment.

### L12 — WinHTTP string pointers never freed

- **File:** `netbridge-agent/src/netbridge_agent/winproxy.py:124-267`
- **Fix:** Free non-null strings with `GlobalFree` after use.

---

## Superseded Reviews

This review supersedes:
- `gemini-2.0-flash-security-review.md` (2026-02-14)
- `SECURITY_REVIEW_GPT-5.2.md` (2026-02-14)
- `security-hardening-plan.md` (2026-02-15)
