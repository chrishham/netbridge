# Error paths, plugin load and agent gap-fill (sub-project D)

Date: 2026-10-03
Status: autonomous design (user: "προχώρα τα"); decisions logged below
Depends on: A (#20), B (#22), C (#23), all merged. Branch `error-paths-gapfill`.

## Context

The journey proves the happy path, faults and auth. It still proves almost
nothing about what a user sees when a connection **fails**, nothing about
plugins (a shipped feature, v1.7.0), and the agent is the least-tested
component (floor 37 %; `app.py`, `credstore.py`, `keepalive.py` at 0-23 %).
Reading the relay for this design also turned up a robustness bug (see
"Findings", F4).

Measured today (2026-10-03, `uv run pytest --cov` per component): agent
37.66 % (floor 37), relay 73.41 % (73), socks-proxy 50.95 % (50), e2e
77.40 % (77), shared floor 91, socks-proxy-win floor 33.

## Findings (current behaviour, verified in code)

### F1. Every connect failure collapses to SOCKS5 0x04 / HTTP 502

Chain for a failed destination:

1. Agent `handle_tcp_connect` (`netbridge-agent/.../agent.py:409`):
   - destination validation failure -> `tcp_connect_result{success:false,
     error:"Destination H:P is not allowed"}` (`agent.py:481-490`). Loopback
     (unless `allow_loopback`) and link-local (`169.254/16`, `fe80::/10`, always)
     are denied here (`agent.py:78-95, 138-150`);
   - magic hostname without a registered app -> `Service H is not available`
     (`agent.py:463-466`);
   - any exception from `open_tcp_connection` -> `error: str(e)`
     (`agent.py:542-557`). Refused port: `[Errno 111] Connect call failed
     (...)` (Windows: `[WinError 1225]`/`10061` text); unresolvable name:
     `[Errno -2] Name or service not known` (Windows `[Errno 11001]
     getaddrinfo failed`). The text is OS- and locale-dependent.
   - DNS failure inside `validate_destination` is swallowed
     (`agent.py:130-134`) and the connect proceeds, so the name is resolved
     twice (validation, then connect). Harmless, noted.
2. Relay forwards the agent's result verbatim; relay-side rejections (blocked
   port `relay/__main__.py:723`, invalid params, rate limit, no agent) use the
   same message shape.
3. Proxy `TunnelManager.connect` (`socks-proxy/.../tunnel.py:742-753`) turns
   `success:false` into `TunnelConnectError(error)`, a `ConnectionError`
   subclass (`tunnel.py:108`). Only `classify_connect_error` looks at the text,
   and only to decide agent health (`tunnel.py:136-154`).
4. SOCKS5 front end (`socks5.py:88-101`): `asyncio.TimeoutError` -> **0x06**;
   `ConnectionError` -> **0x04**; anything else -> 0x01. HTTP front end
   (`http_proxy.py:215-229, 280-297, 350-362`): `TimeoutError` -> **504**;
   `ConnectionError` -> **502**.

Result today: refused port, NXDOMAIN, agent-side denial, relay port block, "no
agent" and "stream limit" all give **0x04 / 502**; 0x05 (refused) and 0x03/0x04
distinctions are never produced; 0x06/504 appear only when the proxy's own 30 s
connect wait expires. The error text never reaches the client.

Assessment: lossy, not wrong. 0x04 and 502 are valid replies, every client
treats them as "failed". A proper mapping needs a structured error code in
`tcp_connect_result` across agent, relay and proxy (protocol change), because
mapping by OS error text is locale- and platform-dependent. **Not fixed in D;
pinned** (Decision 1).

### F2. Existing coverage of failure replies

`relay_filter` (`journey.py:305-319`) covers only SOCKS5 to a relay-blocked
port (asserts a `ProxyError`, logs "Blocked port", any reply code). Missing:
refused port, DNS failure, agent-side denial, and the HTTP CONNECT / HTTP
forward front ends for any failure. Unit tests pin 0x04/0x06/502/504 mapping
only partially (`socks-proxy/tests/test_socks5.py`, `test_http_proxy.py`).

### F3. Plugins

- Plugins are drop-in directories `<app dir>/plugins/<name>/` with
  `manifest.json` (`name, hostname, description, version, entry_point`;
  hostname must start with `netbridge-`, `netbridge-exec` reserved) and a module
  exporting `create_app()` (`plugin_loader.py:41-141`). App dir =
  `%LOCALAPPDATA%/NetBridge` (`config.py:42-45`); `SourceAgent` already sets
  `LOCALAPPDATA` to `<work>/localappdata` (`stack.py:172`).
- No toggle: `NetBridgeApp._async_main` (`app.py:722-739`) always starts the
  `InterceptServer`, registers `netbridge-exec` and calls `_reload_plugins()`
  **before** the agent connects. Each plugin gets its own loopback runner;
  success logs `Plugin loaded: <hostname>` (`app.py:512`), a bad plugin logs
  `Skipping plugin <dir>: ...` (`plugin_loader.py:137`) or `Failed to load
  plugin` (`app.py:523`) and does not stop the others.
- Clients reach a plugin as `http://<hostname>/` through the proxy: the agent
  treats it as a magic hostname and rewrites the destination to the plugin's
  loopback port (`agent.py:438-471`, `intercept.py`). The always-on route
  `GET http://netbridge-exec/plugins` lists discovered plugins without needing
  remote exec enabled (`remote_exec.py:289-312, 417-448`); this is also what the
  `netbridge-socks plugin list` CLI calls (`plugin_cli.py:154`).
- There is no plugin in the socks proxy itself; its `plugin` subcommand is a
  client of the agent endpoints above.

### F4. Relay dies on non-object JSON (product bug)

Both message loops do `data = json.loads(msg.data); data.get("type")` inside
`try/except json.JSONDecodeError` only:

- tunnel handler `relay/__main__.py:934-935`;
- agent `/ws` handler `relay/__main__.py:613-614`.

`[1]`, `"x"`, `null`, `42` parse fine, then `.get` raises `AttributeError`; the
exception leaves the `async for`, aiohttp logs "Error handling request" with a
traceback, and the connection (and for a tunnel client all its streams) is
torn down by one malformed frame. A related crash: a **non-hashable**
`stream_id` in an object (`{"type":"tcp_data","stream_id":[1]}`) makes
`tcp_streams.get(stream_id)` raise `TypeError` (`__main__.py:623, 817, 853,
688` then `tcp_streams[stream_id] = ...`). Tunnel clients are authenticated, so
this is a robustness/availability issue for the user's own session, not an
auth bypass; the same input from the agent side is equivalent.

The same pattern exists on the receiving side of the relay's messages and is
equally fragile: agent `agent.py:610-611` (`handle_message`) and
`agent.py:731, 769` (registration and loop), proxy `tunnel.py:867` -> `895`
(`data.get`; the generic `except` at `tunnel.py:870+` logs and ends the receive
loop, dropping the tunnel). The relay is a trusted peer, so these are
defence-in-depth, fixed with the same one-line guard.

### F5. `NotAppKeyWarning`

`relay/__main__.py:487,492` use `app["cleanup_task"]`; the lifecycle tests carry
a `filterwarnings("ignore::NotAppKeyWarning")` to hide it
(`test_relay_lifecycle.py:18`). The agent has the same pattern in
`remote_exec.py:323,402,425`, `app.py:449,466,734` and its tests.

### F6. Agent unit-test gaps

| File | Stmts | Cov today | Nature |
|---|---|---|---|
| `app.py` | 456 | 0 % | `NetBridgeApp`: no Tk. Tray is `pystray` (guarded import, `TRAY_AVAILABLE`); console mode needs none. Mostly plain methods around `self.tray`, asyncio events, `Config`, subprocess |
| `credstore.py` | 85 | 23 % | JSON file store; DPAPI via `ctypes.windll` only on `win32`; non-Windows branch is base64 |
| `keepalive.py` | 54 | 0 % | loop + two `ctypes.windll` calls that are no-ops off Windows |
| `auth.py` | 71 | n/a | pure re-export of `shared_auth` (imports only; no logic) |
| `__main__.py`, `tray.py`, `dialogs.py` | 190, 156, 274 | 0 % | CLI wiring, pystray menu, Win32/Tk dialogs: need a display |
| `legacy.py` | 502 | 21 % | deprecated path |

## Goals

1. Journey steps that pin the user-visible result of each failure kind on all
   three front ends, fast and deterministic, in source and exe modes.
2. A journey step proving plugins load, are routable through the tunnel, and
   that one bad plugin does not break the rest.
3. Fix F4 test-first in relay, agent and proxy.
4. Agent unit tests for `app.py` (headless part), `credstore.py`,
   `keepalive.py`, `auth.py` re-exports; relay tests for the agent message loop.
5. Migrate to `web.AppKey` (relay, agent), drop the warning filter.
6. Ratchet floors from measured values.

## Non-goals

- A structured connect-error code / correct SOCKS5 reply mapping (F1): a
  protocol change; recorded as a follow-up.
- Testing `tray.py`, `dialogs.py`, `__main__.py`, `legacy.py`, Windows DPAPI /
  `SendInput` internals (need a display or real Win32; the Windows e2e journey
  already starts the exe).
- Plugin install/uninstall/hot-reload through `netbridge-socks plugin ...`
  (needs git/clone and exec; `test_plugin_cli.py` / `test_remote_exec.py` own it).
- Changing reconnect, rate-limit or timeout behaviour.

## Design

### 1. Error-path journey steps (new `Journey._errors`, after `_filter`)

Targets gains a **refused port**: `Targets.refused_port`, a TCP socket bound to
an ephemeral port on the target IP and never `listen()`ed, held open for the run
so the port cannot be reused by anything else. Connecting to a bound,
non-listening port is refused immediately on Linux and within about 2 s on
Windows (SYN retries). The target IP is the host's non-loopback address (as for
all other targets), so the agent's loopback block does not apply.

Clients: `clients.socks5_connect` already raises `ProxyError(code)`;
`clients.http_connect` raises `ProxyError(status)` on non-200;
`clients.http_forward_get` returns `(status, body)`. No new client code except
a helper `attempt(fn, budget)` in the journey returning
`(outcome, seconds)`, where outcome is the reply code/status, `"ok"`, or
`"hang"` (budget exhausted).

| Step | Action | Expect | Budget |
|---|---|---|---|
| `refused_socks5` | SOCKS5 CONNECT `ip:refused_port` | reply **0x04**; agent log `Failed: ... Connect call failed`/OS refusal text | 10 s |
| `refused_http_connect` | HTTP CONNECT `ip:refused_port` | **502** | 10 s |
| `refused_http_forward` | `GET http://ip:refused_port/` | **502** | 10 s |
| `dns_failure_socks5` | SOCKS5 CONNECT domain `netbridge-e2e-nxdomain.invalid:80` (ATYP=0x03; `.invalid` is reserved and never resolves) | **0x04**; agent log shows the resolver error | 20 s |
| `dns_failure_http_connect` | HTTP CONNECT same name | **502** | 20 s |
| `agent_denies_link_local` | SOCKS5 CONNECT `169.254.169.254:80` (literal, no network I/O; agent always blocks it) | **0x04**; agent log `Destination denied`; relay log has **no** `Blocked port` | 10 s |
| `blocked_port_http_connect` / `blocked_port_http_forward` | the relay-blocked port over the two HTTP front ends | **502**; relay logs `Blocked port` | 10 s |
| `missing_service` | SOCKS5 CONNECT `netbridge-e2e-missing:80` | **0x04**; agent log `Service ... is not available` | 10 s |
| `errors_leave_tunnel_healthy` | after all of the above: `socks5_http` round trip succeeds; relay `/status` `active_streams` is back to its pre-error baseline within 5 s | both | 15 s |

Each step also records elapsed seconds in its detail and fails on `"hang"`.
"Pinned current behaviour" is stated in the step detail
(`0x04 (host unreachable; the product maps all connect failures to it)`), so a
future structured-error change updates exactly these assertions.
Steps use `Journey.check` so one failure does not hide the rest; the log
evidence is read from `agent.logs` and `relay.logs` with `wait_for(..., 5)`
since file logs lag slightly.

`relay_filter` is kept as is (it already pins the SOCKS5 relay block); the
HTTP variants are the new `blocked_port_*` steps.

### 2. Plugin steps (new `Journey._plugins`, after `az_called`)

Fixtures are written by the driver, not shipped: `e2e/src/netbridge_e2e/plugin_fixtures/`
holds a template `probe` plugin (`manifest.json` with hostname
`netbridge-e2e-probe`; `plugin.py` whose `create_app()` returns an
`aiohttp.web` app answering `GET /` with `netbridge-e2e-plugin <nonce>`) and a
`broken` plugin (manifest missing `entry_point`). Only `aiohttp.web` is
imported, which the agent (and the PyInstaller exe) already bundles.

`Agent.install()` (both `SourceAgent` and `ExeComponent`) accepts `plugins:
list[Path]` and copies them into `<app dir>/plugins/` before `start()`
(plugins load at agent start, F3). The nonce is a per-run random token
substituted into the copy, so a stale directory from an earlier run cannot
satisfy the check. Cleanup removes only the two fixture directories (an
`--allow-existing-install` machine keeps its own plugins).

Steps, all through the real proxy -> relay -> agent path:

- `plugin_loaded_log`: agent log contains `Plugin loaded: netbridge-e2e-probe`
  since the start mark, and `Skipping plugin broken` (the broken plugin is
  skipped, not fatal).
- `plugin_routable`: SOCKS5 domain CONNECT `netbridge-e2e-probe:80` then
  `GET /` -> 200 and body equals `netbridge-e2e-plugin <nonce>`; the same over
  HTTP CONNECT and over HTTP forward (`http://netbridge-e2e-probe/`).
- `plugins_listed`: `GET http://netbridge-exec/plugins` over SOCKS5 returns
  JSON whose `plugins` names contain the probe plugin and not `broken`
  (always-on route, no remote exec needed; this is the same endpoint
  `netbridge-socks plugin list` uses).
- `plugin_isolation`: `netbridge-e2e-missing:80` is the `missing_service` step
  above; ordering guarantees plugins loaded before errors are asserted.

**Which journeys:** both. The steps only use the proxy front ends and files in
the agent's app dir. Source mode: `<work>/localappdata/NetBridge/plugins`. Exe
mode: `%LOCALAPPDATA%\NetBridge\plugins` (`ExeComponent.install_dir`, deleted on
uninstall anyway). The logs are the same files `LogWatch` already reads. Risk:
the frozen exe must import the plugin module via `importlib` and bundle
`aiohttp.web` (it already does for the intercept server); first Windows run
decides, and the step's detail carries the agent log tail on failure.

### 3. Relay: non-object JSON (F4)

Introduce in `relay/__main__.py`:

```python
def _parse_message(raw: str, who: str) -> dict | None:
    """json.loads that only returns JSON objects; warns and returns None otherwise."""
```

Used at the two loops (`__main__.py:613`, `:934`). Behaviour: invalid JSON
keeps today's "Invalid JSON from ..." warning; a valid non-object logs
`Ignoring non-object JSON message from <who>` (warning, no traceback) and the
loop continues. The `stream_id` handled by `_handle_tcp_connect`,
`_handle_tcp_data`, `_handle_tcp_close`, and the agent branch must be a
`str` of at most 128 characters: anything else is treated as a missing
`stream_id` (tcp_connect answers `tcp_connect_result success:false` with
`stream_id: null` and `error: "Invalid stream_id"`; data/close are dropped with
a warning), never used as a dict key. Same for `host`/`port` types, already
covered by `validate_tcp_connect_params`.

Agent (`agent.py:610, 731, 769`) and proxy (`tunnel.py:867`) get the same
guard (`isinstance(data, dict)` else warn and skip); no shared helper, so
`shared_auth` (a non-editable path dependency) is untouched.

### 4. `web.AppKey` migration (F5)

Relay: module constant `CLEANUP_TASK = web.AppKey("cleanup_task", asyncio.Task)`
used at `__main__.py:487,492`; remove the `filterwarnings` line from
`test_relay_lifecycle.py`. Agent: `PLUGIN_RELOAD_CALLBACK` and
`REMOTE_EXEC_ENABLED` keys defined in `remote_exec.py`, used there, in
`app.py` and in `test_remote_exec.py`. Both pytest configs get
`filterwarnings = ["error::aiohttp.web_exceptions.NotAppKeyWarning"]` so the
warning cannot return.

### 5. Agent unit tests

All use the existing agent test conventions (loopback only; the pytest-socket
guard stays on). Nothing here needs a display: `Status`/`TRAY_AVAILABLE` come
from `tray.py` with a guarded import, and tests never create a `TrayIcon`.

**Headless-testable and in scope**

- `tests/test_app.py` (`NetBridgeApp(console=True)`, `LOCALAPPDATA` -> tmp,
  `Config.load` real on a tmp dir; `setup_logging` handlers removed after each
  test): `set_status` (transition, tray notifications for CONNECTED /
  DISCONNECTED-from-CONNECTED / AUTH_REQUIRED with a fake tray, no notification
  when `notify=False` or unchanged); `_on_agent_status` mapping
  (auth_required -> AUTH_REQUIRED, connected -> CONNECTED, else CONNECTING vs
  DISCONNECTED by `_agent_task`); `_check_pending_requests` (connect starts a
  task once, not twice; disconnect sets the stop event) with a fake `run_agent`;
  `_run_agent` success, exception (logged, status DISCONNECTED) and status
  sequence CONNECTING -> DISCONNECTED; `_on_proxy_auth_rejected` notification;
  `request_toggle_keepalive` / `_start_keepalive` / `_stop_keepalive` with the
  loop patched; remote exec: `request_toggle_remote_exec`, `_start_remote_exec`
  / `_stop_remote_exec` flag handling on a fake exec app, `_remote_exec_auto_disable`
  (patched timeout); `_reload_plugins_locked` with `discover_plugins` /
  `load_plugin_app` patched and a fake `InterceptServer`: added, reloaded,
  removed, load failure unregisters nothing it didn't register, duplicate
  hostname shadowing, lock serialises concurrent reloads; `_async_main`
  start-up order (intercept server, exec app, plugins before the agent task)
  and shutdown (agent task cancelled, server stopped) with a fake `run_agent`
  and an immediate stop; `request_exit`; `_run_tray` returning 1 when
  `TRAY_AVAILABLE` is false; `request_login` on non-Windows (Popen patched, error
  path notifies); `request_restart` no-op off Windows;
  `_check_for_update` / `_do_update` decision logic with `updater` patched
  (no network); `_launch_update_script` writes the expected script (Windows-only
  parts skipped via `pytest.mark.skipif`).
- `tests/test_credstore.py`: non-Windows branch for real (tmp app dir): save ->
  load round trip, file mode/location, `clear`, `has_proxy_credentials`,
  corrupt JSON and missing keys return None. Windows branch: `_dpapi_*`
  tests marked `skipif(sys.platform != "win32")` (run on the Windows runner in
  `ci.yml`'s agent job if present; otherwise they document intent). A
  parametrised test patches `sys.platform` to cover the `password_b64` /
  plaintext fork in `load_proxy_credentials` with `_dpapi_*` mocked.
- `tests/test_keepalive.py`: `_set_execution_state` and `_jiggle_mouse` return /
  no-op off Windows; with `sys.platform` patched and `ctypes.windll` replaced
  by a fake, flags (`ES_CONTINUOUS|...`, clear) and the 2-input `SendInput`
  call are asserted; `session_keepalive_loop` with `KEEPALIVE_INTERVAL`
  patched to 0.01 s: sets state on start, jiggles, warns when `SendInput`
  fails, clears state and stops on `stop_event`, clears state when cancelled.
- `tests/test_auth_reexports.py`: every name in `netbridge_agent.auth.__all__`
  is the same object as in `shared_auth` and `__all__` has no duplicates (the
  module has no logic; this catches a rename in `shared_auth`).

**Excluded (documented in `[tool.coverage.report] exclude_also` is NOT used;
files stay in the denominator, honestly low):** `tray.py`, `dialogs.py`,
`__main__.py`, `legacy.py`, the `win32`-only branches of `app.py`
(`request_restart`, `_launch_update_script` Windows script, `request_install`
/ `request_uninstall` which call the installer and dialogs), and the DPAPI /
`SendInput` calls themselves. They are exercised by the Windows exe journey
(start, connect, traffic, uninstall), not by unit tests.

### 6. Relay tests

`relay/tests/test_relay_malformed.py` (same fixtures as the lifecycle tests):
for each of `[1]`, `"x"`, `null`, `42`, `true`, `{"type": []}`,
`{"type":"tcp_data","stream_id":[1]}`, `{"type":"tcp_connect","stream_id":{},
"host":"h","port":1}` sent on **/tunnel** and on **/ws**: the websocket stays
open, a following valid message is processed (tunnel: a `tcp_connect` for an
unknown agent still answers `tcp_connect_result`; agent: a `heartbeat` is
acked), no `ERROR`/traceback record from `aiohttp.server` or `relay` (caplog),
and `Ignoring non-object JSON` / `Invalid stream_id` warnings appear. A
state-level test asserts `tcp_streams` is unchanged.

`relay/tests/test_relay_agent_loop.py`: the uncovered agent message loop
(`__main__.py:603-666`): result/data/close forwarded to the owning tunnel
client; ownership denied (stream of another user or another agent socket) is
dropped with the warning; `tcp_close` removes the stream; oversized message
dropped; unknown type warns; invalid JSON warns; bandwidth limiter acquired
for `tcp_data` only (limiter faked).

Proxy and agent guards: `socks-proxy/tests/test_tunnel_malformed.py`
(`_receive_loop` fed non-objects keeps running and still delivers a later
`tcp_connect_result`), `netbridge-agent/tests/test_agent_malformed.py`
(`handle_message` ignores non-objects; the loop in `connect_and_run` does not
raise). Reply mapping pins: `socks-proxy/tests/test_socks5.py` gains explicit
`TunnelConnectError -> 0x04`, `TimeoutError -> 0x06`, other `Exception -> 0x01`
cases and `test_http_proxy.py` the 502/504 equivalents for CONNECT and forward
(if not already pinned, per F2).

### 7. E2E driver unit tests

`e2e/tests/test_targets.py`: `refused_port` really refuses a connect and stays
held until `close()`. `test_journey_errors.py` (like `test_journey_faults.py`,
using the existing fake proxy): the `attempt` helper classifies reply code,
`ok`, `hang`; each new step passes against a scripted fake and fails when the
fake answers 0x05, succeeds, or hangs. `test_stack.py`: `install(plugins=...)`
copies fixtures, substitutes the nonce, and cleanup removes only those
directories. `test_plugin_fixtures.py`: the probe plugin is loaded with the
agent's real `discover_plugins` + `load_plugin_app` and answers with the nonce;
the broken plugin is skipped. (Source mode only: the e2e venv gets the agent
as a path dev-dependency for this test, or the test is skipped when
`netbridge_agent` is not importable.)

## Coverage floors

Rule: new floor = floor(measured after D) minus 1, never lowered. Estimates
before measuring:

| Component | Now (floor) | After D (estimate) | New floor |
|---|---|---|---|
| netbridge-agent | 37.66 (37) | ~47 (`app.py` ~60 % of 456 stmts, `credstore` ~85 %, `keepalive` ~90 %, guards) | **45** |
| relay | 73.41 (73) | ~81 (agent loop 603-666, malformed paths) | **79** |
| socks-proxy | 50.95 (50) | ~52 (guards, mapping pins) | **51** |
| e2e | 77.40 (77) | ~78 (new targets/steps/fixtures) | **77** unless measured higher |
| shared, socks-proxy-win | unchanged | unchanged | unchanged |

Floors are set from the actual numbers in the final commit of D, not from
this table. The `diff-cover >= 80 %` gate stays as is and applies to all new
lines (it forces the guards and `AppKey` lines to be tested).

## Success criteria

- Journey (source, image-relay, Windows exe): all new steps pass; the
  `errors` group adds roughly 15-25 s, the plugin group about 3 s.
- Sending `[1]`, `"x"`, `null`, `42` on `/ws` or `/tunnel` leaves the
  connection up and logs no traceback.
- `NotAppKeyWarning` is an error in relay and agent pytest runs and none fires.
- All component floors raised as above; `scripts/coverage.sh` green.

## Error handling

- Error steps never fail from a different cause than they assert: they print
  reply code, elapsed time and the relevant agent/relay log lines; a hang is
  reported as such, not as a timeout exception.
- Plugin steps attach the agent log tail on failure (missing `Plugin loaded`
  line is the usual cause: wrong app dir, frozen import error).

## Risks

- **DNS in CI.** `.invalid` should resolve instantly to NXDOMAIN, but a
  runner with a blackholed resolver could take the full resolver timeout. The
  20 s budget and a clear "hang" report keep it bounded; if flaky it is
  switched to a hosts-file-free alternative (a name containing a character the
  relay's hostname pattern accepts but no resolver answers, same `.invalid`).
- **Windows refused-connect latency** (~2 s per attempt, three attempts):
  within budget.
- **Frozen exe plugin import** (see section 2): first Windows run will confirm.
- **Pinning 0x04/502** makes a later correct mapping a deliberate test change;
  intended.
- **Message-limiter interaction:** the new steps add about 12 connects; the
  e2e relay already raises per-user/IP limits (B), and stream-rate limiting is
  far above this.
- **App tests and logging:** `NetBridgeApp.__init__` calls `setup_logging`;
  tests must remove the handlers it adds or later tests see duplicate logs.

## Decisions

| # | Decision | Alternatives | Why |
|---|---|---|---|
| 1 | Pin 0x04 / 502 for all connect failures; do not fix mapping in D | map refused -> 0x05, NXDOMAIN -> 0x04, denied -> 0x02 by parsing error text | The proxy only has free text from the agent; OS/locale-dependent strings make a text-based mapping fragile (Windows messages differ). A correct fix is a structured `error_code` in `tcp_connect_result` (agent+relay+proxy, version skew with older agents). Out of scope, logged as follow-up |
| 2 | Fix F4 (relay) in D | pin | Clear bug: one malformed frame kills the session and logs a traceback |
| 3 | Apply the same `isinstance(dict)` guard to agent and proxy | relay only | Same one-liner; the relay is a trusted peer but a bug there should not cascade |
| 4 | No shared helper for the guard | add to `shared_auth` | `shared_auth` is a non-editable path dependency; a change there forces re-syncs and is unrelated to auth |
| 5 | Refused port = bound, never-listened socket held by `Targets` | closed ephemeral port | Closed ports can be reused between pick and use; a held bound socket is deterministic and refuses on both OSes |
| 6 | DNS failure name `*.invalid` | random subdomain of a real domain | RFC 6761: guaranteed NXDOMAIN, no external query semantics |
| 7 | Agent-side denial tested with `169.254.169.254` | allowed/denied destination config | Always blocked, no config seam, no network I/O, works in source and exe |
| 8 | Plugin proof = log line + routing through the tunnel + `/plugins` list | log only | Routing proves the real chain (magic hostname -> intercept -> plugin app); the log alone would pass with a dead runner. `/plugins` is always-on and is what the CLI uses |
| 9 | Fixture plugins copied by the driver with a per-run nonce | ship a plugin in the repo's agent package | No product change; a stale dir cannot give a false pass |
| 10 | Plugin steps run in both source and exe journeys | source only | Pure file drop + proxy traffic; exe mode is where frozen imports could break, so it is the more valuable run |
| 11 | Plugin hot-reload, install CLI not in e2e | include | Needs git/exec/remote-exec toggle; unit-tested already |
| 12 | Test `app.py` headless logic, exclude tray/dialogs/`__main__`/`legacy`/Win32 branches | exclude `app.py` entirely, or omit files from coverage | `app.py` has no Tk and most logic is plain asyncio/state; excluding untestable files from the denominator would hide the gap, so they stay in and are covered by the Windows journey |
| 13 | `auth.py` gets only an identity test | mock-heavy tests | It is a pure re-export; behaviour belongs to `shared_auth` tests |
| 14 | `AppKey` migration includes the agent's `remote_exec` keys, and the warning becomes an error | relay only | Same warning, same fix, prevents regressions |
| 15 | Floors = measured minus 1, set at the end of D | fixed targets now | Avoids a red CI from estimate error; ratchet never lowers |
| 16 | `stream_id` must be `str` <= 128 chars in the relay | accept any hashable | Closes the `TypeError` crash and bounds memory; proxy stream ids are `token_urlsafe(16)` |
| 17 | Error steps use `Journey.check` (continue after failure) | stop at first failure | One run reports every divergence |
