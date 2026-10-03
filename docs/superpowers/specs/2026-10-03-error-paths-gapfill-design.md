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
     (`agent.py:130-134`) and the connect proceeds; the name is then resolved
     a **second** time by `open_connection` (`agent.py:279`). This is not
     harmless, see F8.
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

### F6a. Failed connects leak the relay stream (product bug)

`_handle_tcp_connect` registers the stream in `tcp_streams` before the agent
answers (`relay/__main__.py:792`). On `tcp_connect_result{success:false}` the
agent-result branch only forwards the message (`__main__.py:621`) and removes
the stream solely for `tcp_close`. The proxy drops its own handler
(`tunnel.py:742`) and never learns a `stream_id` to close
(`socks5.py:90`), so the relay keeps the entry until the idle sweep
(`STREAM_TIMEOUT` 120 s, `__main__.py:108, 430`). Every refused port, DNS
failure or denial therefore leaves a phantom stream in `active_streams` for two
minutes (and counts against `/status`). Relay-side failures that return before
registration (blocked port, invalid params) do not leak.

### F6b. DNS rebinding gap in the agent (product bug)

`validate_destination` resolves the name (`agent.py:126`) and checks the
answers; `open_tcp_connection` then calls `asyncio.open_connection(host, port)`
(`agent.py:279`), which resolves again. A name whose answer changes between the
two lookups (short TTL / rebinding server) passes validation with an allowed
address and connects to loopback or link-local, defeating the "always blocked"
boundary (`agent.py:78-95`). The validation lookup is also unbounded
(`agent.py:127`), so a blackholed resolver stalls the stream for the OS
resolver timeout; the driver cannot cancel that.

### F6c. Other unguarded JSON consumers

Beyond F4: `legacy.py:493, 557, 595` (the shipped `--legacy` mode) parse then
call `.get` the same way; `remote_exec` `/exec` and `/exec/stream` call
`await request.json()` then `.get` (`remote_exec.py:183, 236`), so a valid
scalar/array body yields a logged traceback and HTTP 500.

### F6d. Shutdown race in `NetBridgeApp` (product bug)

`_async_main` creates `self._stop_event` and waits on it (`app.py:722, 751`).
`_run_agent` then **replaces** `self._stop_event` with a new `asyncio.Event`
for each connection (`app.py:671`), and `request_exit()` sets whatever
`self._stop_event` is at that moment (`app.py:540`). After the agent task has
started, Exit signals the replacement, `_async_main` keeps waiting on the
original, and the application does not shut down (the same applies to
`_check_pending_requests` disconnect, which stops the connection, not the app).

### F6. Agent unit-test gaps

| File | Stmts | Cov today | Nature |
|---|---|---|---|
| `app.py` | 456 | 0 % | `NetBridgeApp`: no Tk. Tray is `pystray` (guarded import, `TRAY_AVAILABLE`); console mode needs none. Mostly plain methods around `self.tray`, asyncio events, `Config`, subprocess |
| `credstore.py` | 85 | 23 % | JSON file store; DPAPI via `ctypes.windll` only on `win32`; the non-Windows branch stores the password as **plaintext** JSON (`credstore.py:102, 145`) |
| `keepalive.py` | 54 | 0 % | loop + two `ctypes.windll` calls that are no-ops off Windows |
| `auth.py` | 71 | n/a | pure re-export of `shared_auth` (imports only; no logic) |
| `__main__.py`, `tray.py`, `dialogs.py` | 190, 156, 274 | 0 % | CLI wiring, pystray menu, Win32/Tk dialogs: need a display |
| `legacy.py` | 502 | 21 % | deprecated path |

## Goals

1. Journey steps that pin the user-visible result of each failure kind on all
   three front ends, fast and deterministic, in source and exe modes.
2. A journey step proving plugins load, are routable through the tunnel, and
   that one bad plugin does not break the rest.
3. Fix test-first: F4/F6c (non-object JSON: relay, agent, proxy, legacy,
   remote_exec), F6a (failed connect leaks the relay stream), F6b (single,
   bounded DNS resolution in the agent), F6d (app shutdown race).
4. Agent unit tests for `app.py` (headless part), `credstore.py`,
   `keepalive.py`, `auth.py` re-exports; relay tests for the agent message loop.
5. Migrate to `web.AppKey` (relay, agent), drop the warning filter.
6. Ratchet floors from measured values.

## Non-goals

- A structured connect-error code / correct SOCKS5 reply mapping (F1): a
  protocol change; recorded as a follow-up.
- Testing `tray.py`, `dialogs.py`, `__main__.py`, Windows DPAPI /
  `SendInput` internals (need a display or real Win32). Nothing in CI exercises
  them (the Windows workflow runs the e2e driver tests and the exe journey, whose
  config enables neither keep-alive nor stored credentials): honest follow-up,
  see section 5.
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
`clients.http_forward_get` returns `(status, body)`. A journey helper
`_fail_case(front_end, dest, expect, budget)` runs one failure over one front
end and returns `(outcome, seconds)`, outcome being the reply code/status,
`"ok"`, or `"hang"` (budget exhausted, via the existing thread-based
`_attempt`; this is only a backstop, the agent bounds DNS itself, section 3).
The matrix is parametrised over failure kind x front end, one step each:

| Failure | Destination | SOCKS5 | HTTP CONNECT | HTTP forward | Budget |
|---|---|---|---|---|---|
| refused | `ip:refused_port` | `refused_socks5` 0x04 | `refused_http_connect` 502 | `refused_http_forward` 502 | 10 s |
| DNS failure | `netbridge-e2e-nxdomain.invalid:80` (ATYP=0x03 on SOCKS5) | `dns_failure_socks5` 0x04 | `dns_failure_http_connect` 502 | `dns_failure_http_forward` 502 | 20 s |
| agent denial | `169.254.169.254:80` (literal, no network I/O, always blocked) | `agent_denies_socks5` 0x04 | `agent_denies_http_connect` 502 | `agent_denies_http_forward` 502 | 10 s |
| relay port block | relay-blocked port | `relay_filter` (updated, below) | `blocked_port_http_connect` 502 | `blocked_port_http_forward` 502 | 10 s |

Evidence rules: **before every action** the step takes `agent.logs.mark()` and
`relay.logs.mark()`, and every log assertion uses `wait_for(..., 5,
since=mark)`, so earlier lines (e.g. `relay_filter`'s `Blocked port`) can neither
satisfy nor break a later step. Refused: agent log `Failed:` line with the OS
refusal text; DNS: agent log `Failed:` with the resolver error; agent denial:
agent log `Destination denied` and **no** relay `Blocked port` since the mark;
port block: relay `Blocked port` since the mark.

`errors_leave_tunnel_healthy` runs last: a `socks5_http` round trip succeeds
and relay `/status` `active_streams` returns to the baseline taken before the
group within 5 s. It depends on the relay fix F6a (without it the phantom
streams stay for 120 s); that is the point of the step.

Every step prints reply, seconds and evidence, and fails on `"hang"`. The step
detail says `0x04 (host unreachable; the product maps all connect failures to
it)`, so a future structured-error change updates exactly these assertions.
Steps use the journey's normal `check`, which fails fast like the rest of the
journey: a failing case ends the run.

The agent's `Service H is not available` branch (`agent.py:438-459`, a registered
magic hostname whose app has no port) is **not** a journey step: `netbridge-e2e-missing`
is not a magic hostname (`intercept.py:22-28`), so it would go to plain DNS. It
is covered by an agent unit test (section 5).

`relay_filter` (`journey.py:305`) is **updated**: it takes fresh `LogWatch`
marks on the relay and agent logs before the action, asserts `Blocked port`
with `wait_for(since=mark)`, and requires SOCKS reply **0x04 exactly** (not
any `ProxyError`). The new `blocked_port_http_*` steps cover the HTTP front ends.

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
satisfy the check. Source mode cleanup removes the two fixture directories; in exe mode the whole
install dir is removed by `uninstall` (nothing is preserved, as for all other
exe state).

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
- `plugin_isolation`: covered by `plugin_loaded_log` (the broken plugin is
  skipped while the probe plugin loads) and `plugin_routable`; plugin steps run
  before the error group.

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
loop continues. `validate_tcp_connect_params` (`__main__.py:72`) accepts `True`/`False` as a port because `bool` is an `int`; it now requires `type(port) is int` (tests: `true`, `false`, plus existing out-of-range cases). The `stream_id` handled by `_handle_tcp_connect`,
`_handle_tcp_data`, `_handle_tcp_close`, and the agent branch must be a
`str` of at most 128 characters: anything else is treated as a missing
`stream_id` (tcp_connect answers `tcp_connect_result success:false` with
`stream_id: null` and `error: "Invalid stream_id"`; data/close are dropped with
a warning), never used as a dict key. Same for `host`/`port` types, already
covered by `validate_tcp_connect_params`.

Agent (`agent.py:610, 731, 769`) and proxy (`tunnel.py:867`) get the same
guard (`isinstance(data, dict)` else warn and skip); no shared helper, so
`shared_auth` (a non-editable path dependency) is untouched.

Also guarded (F6c): `legacy.py:493, 557, 595` get the same `isinstance(dict)`
check (guard only, plus one small unit test of `handle_message` ignoring
non-objects if the module's existing test fixtures allow it, otherwise guard
only; the test is not required for legacy). `remote_exec` `/exec` and
`/exec/stream` answer a non-object body with `400 {"error": "JSON object
required"}` and no traceback, with unit tests for both routes (`[1]`, `"x"`,
`null`, `42`).

### 3c. App shutdown race (F6d)

`NetBridgeApp` gets a separate app-lifetime event, `self._shutdown_event`,
created once in `_async_main` and awaited there instead of `_stop_event`.
`request_exit()` sets `_shutdown_event` (via `call_soon_threadsafe` as today)
**and** the current per-connection `_stop_event` so an active agent stops;
`_run_agent` keeps creating a fresh per-connection `_stop_event`. Disconnect
from the tray keeps signalling only the per-connection event. Test
(`test_app.py`): start `_async_main` with a fake `run_agent` that blocks on its
stop event; after the agent has started (event replaced), `request_exit()` ends
`_async_main` within a short timeout, the fake agent is stopped, and the
intercept server is stopped; disconnect still leaves the app running.

### 3-bis. Field-type validation at every receiver

Beyond "top-level is an object" and `stream_id` being a bounded `str`, each
receiver validates the fields it uses. A bad message is warned and dropped
(the stream is closed when that is the natural reaction, e.g. undecodable data
for a live stream); the receive loop never dies.

- **`stream_id` everywhere:** every receiver (relay both loops, agent
  `handle_tcp_data`/`handle_tcp_close`/`handle_tcp_connect` at `agent.py:570`
  etc., proxy `_handle_message` at `tunnel.py:893`) requires a non-empty `str`
  of at most 128 characters; anything else (null, list, overlong, empty) is
  warned and dropped before it is used as a key.
- **Relay** (both loops): `tcp_data.data` must be `str`, else dropped and not
  forwarded (`__main__.py:623, 817`); `tcp_connect_result.success` must be
  `bool` and `error` `str | None`, else the result is dropped with a warning
  (the tunnel client then times out on its own side; an agent that sends garbage
  results is misbehaving). `success:false` with `error` null or non-str is
  valid and forwarded; the relay does not interpret `error`.
- **Agent** (`handle_tcp_data`, `agent.py:570`): `data` must be `str`
  (`len(None)` crashes before any size guard today); otherwise warn, close the
  stream, return. Invalid base64 is handled the same way.
- **Proxy** (`tunnel.py:891`): `tcp_data.data` must be a `str` and decode as
  base64 (`validate=True`), else warn and close that stream
  (`handler.close()`, release the semaphore); an uncaught `b64decode` error
  no longer ends the receive loop. `tcp_connect_result` is checked the same
  way as in the relay (`success` bool, `error` str or None); an invalid result
  fails that connect with `ConnectionError("Invalid connect result")`. For
  `success:false` the proxy normalises a missing/None/non-str `error` to
  `"Unknown error"` before `classify_connect_error` (which calls `.lower()`,
  `tunnel.py:136`) and `TunnelConnectError` (`tunnel.py:742`), so the front
  ends still answer the pinned 0x04 / 502.
- **Invalid JSON syntax:** the proxy's receive loop (`tunnel.py:867`) calls
  `_json_loads` unguarded, so one malformed frame (`orjson` or `json` decode
  error, a `ValueError`) ends the loop. It now catches `ValueError` per frame,
  warns and continues. Checked the others: relay loops (`__main__.py:613,
  934`) and the agent (`agent.py:610, 731, 769`) already catch
  `json.JSONDecodeError` per frame and continue, so they need no change for
  syntax errors (only for non-objects, above).

Tests, bidirectional (every case also covers `stream_id` null, a list and a 129-character value, and `success:false` with `error: null`; proxy additionally malformed JSON syntax followed by a valid message that is still processed): relay `test_relay_malformed.py` (tcp_data with
`None`/int/list data both directions, results with non-bool `success`,
non-str `error`: dropped, connection stays up, next valid message works);
`netbridge-agent/tests/test_agent_malformed.py` (`tcp_data` with
`None`/int/non-base64 data); `socks-proxy/tests/test_tunnel_malformed.py`
(bad base64, non-str data, bad result fields: receive loop survives, stream
closed, later valid traffic still delivered).

### 3a. Relay: release failed streams (F6a)

In the agent loop, after forwarding a `tcp_connect_result` whose `success` is
not `true`, the relay removes `tcp_streams[stream_id]` (under `_state_lock`,
only if the entry still belongs to this agent and user, same ownership check
as today). A successful result keeps the stream. The stream limiter is a
rate limiter, not a counter, so there is no per-user count to decrement; the
removal makes `/status` `active_streams` accurate immediately. Late
`tcp_data`/`tcp_close` for the removed id are already dropped as unknown.

Tests: relay unit test (`test_relay_agent_loop.py`): a failed result is
forwarded and the stream removed; a successful result keeps it; a failed
result for another user's stream does not remove it. Journey:
`errors_leave_tunnel_healthy`.

### 3b. Agent: resolve once, bounded, connect to validated IPs (F6b)

`validate_destination` is split so one resolution serves both purposes. Today
validation runs inline in `handle_tcp_connect` (`agent.py:478`) and the
message loop awaits it (`agent.py:767`), so one slow lookup stalls heartbeats
and every other stream. D moves **resolution, validation and connect all inside
the tracked pending connection task** (`state.pending_connections`, created at
the end of `handle_tcp_connect`); the receive loop never awaits DNS. Intercepted
(magic) hosts still skip validation.

Resolution details:

- `resolve_destination(host, port, timeout=10.0)` runs `loop.getaddrinfo`
  under `asyncio.wait_for` with `type=socket.SOCK_STREAM`; addresses are deduplicated preserving resolver order; on timeout raises an error whose text is `DNS
  resolution timed out for <host>`; a resolver error keeps its own text. IP
  literals skip DNS.
- Validation applies all existing rules (link-local always, loopback unless
  allowed, private if disabled, denied/allowed lists) to **every** resolved
  address, and rejects if any one is blocked.
- `open_tcp_connection` receives the validated addresses and tries them in
  order (`asyncio.open_connection(ip, port)` each, remaining time of the 30 s
  budget), raising the last error if all fail. The original hostname is kept
  for logs, the `Destination H:P` message and `StreamInfo.host`. With a
  corporate upstream proxy (`connect_via_proxy`) the name is passed to the proxy
  as today (the proxy resolves it); the agent still validates its own
  resolution first.
- Unaffected: magic hostnames and plugin hosts return before any resolution
  (`agent.py:438-471`, intercepted streams skip validation and connect to
  `127.0.0.1:<plugin port>`); IP-literal destinations behave as before.

Unit tests (`netbridge-agent/tests/test_agent_dns.py`, resolver mocked, no
network): rebinding prevented (a fake `getaddrinfo` that answers `1.2.3.4` first
and `127.0.0.1` afterwards: exactly one lookup happens and the connect uses
`1.2.3.4`; a name resolving to a blocked address is rejected, as is a name with
one blocked among several answers); timeout (a never-completing resolver yields
`DNS resolution timed out` within the patched small timeout and the failure
reaches the relay as `success:false`); multi-address fallback (first address
refuses, second accepted, order preserved; all fail -> last error); hostname
preserved in log/`StreamInfo`; **non-blocking** (a fake `getaddrinfo` blocked on an `asyncio.Event` for stream A: heartbeat, `tcp_data` and `tcp_close` for stream B are processed meanwhile; releasing the event lets A complete; the pending task is cancelled cleanly on shutdown); duplicates collapsed in order; magic hostname and intercepted plugin path make
no resolver call.

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
- `tests/test_credstore.py`: non-Windows branch for real (tmp app dir; the password is stored in plaintext
  there, the test pins that): save -> load round trip, file location, `clear`, `has_proxy_credentials`,
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
- `tests/test_agent.py` addition: `handle_tcp_connect` for the permanently magic
  host `netbridge-exec` with an intercept server whose `port_for` returns None
  answers `Service netbridge-exec is not available` (a dynamic plugin host stops
  being magic once unregistered, `intercept.py:73`, so it cannot be used; or
  `is_magic_hostname` is mocked explicitly);
  not configured / not running branches (`agent.py:438-459`).
- `tests/test_remote_exec.py` additions: non-object bodies on `/exec` and
  `/exec/stream` give 400 JSON, no traceback.
- `tests/test_auth_reexports.py`: every name in `netbridge_agent.auth.__all__`
  is the same object as in `shared_auth` and `__all__` has no duplicates (the
  module has no logic; this catches a rename in `shared_auth`).

**Excluded and honestly uncovered:** `tray.py`, `dialogs.py`, `__main__.py`,
`legacy.py` (apart from the new guard), the `win32`-only branches of
`app.py` (`request_restart`, `_launch_update_script` Windows script,
`request_install` / `request_uninstall`), and the DPAPI / `SendInput` calls
themselves. They stay in the coverage denominator. They are **not** exercised by
the Windows journey (its exe config enables neither keep-alive nor stored
credentials) nor by CI (the Windows workflow runs only the e2e driver tests).
Non-goal for D; follow-up: a Windows unit-test job for `credstore` DPAPI and
`keepalive` `SendInput`.

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

`relay/tests/test_relay_agent_loop.py` (also the F6a tests above): the uncovered agent message loop
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

Rule: new floor = `floor(measured after D)`, matching the hint printed by
`scripts/coverage_report.py:41`; never lowered. Estimates before measuring (the
resulting floors are the integer parts):

| Component | Now (floor) | After D (estimate) | New floor |
|---|---|---|---|
| netbridge-agent | 37.66 (37) | ~46 (`app.py` ~60 % of 456 stmts, `credstore` ~85 %, `keepalive` ~90 %, DNS/guards) | **46** |
| relay | 73.41 (73) | ~80.5 (agent loop 603-666, malformed paths, stream release) | **80** |
| socks-proxy | 50.95 (50) | ~52.3 (guards, mapping pins) | **52** |
| e2e | 77.40 (77) | ~78.2 (new targets/steps/fixtures) | **78** |
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

- Error steps never fail from a different cause than they assert (log evidence only since the per-action mark): they print
  reply code, elapsed time and the relevant agent/relay log lines; a hang is
  reported as such, not as a timeout exception.
- Plugin steps attach the agent log tail on failure (missing `Plugin loaded`
  line is the usual cause: wrong app dir, frozen import error).

## Risks

- **DNS in CI.** `.invalid` should answer NXDOMAIN instantly. If the resolver
  is blackholed the agent now gives up after 10 s with `DNS resolution timed
  out` (F6b), so the stream ends deterministically; the driver's 20 s budget is
  only a backstop. Residual flake risk: a resolver slower than 10 s fails the
  step with that explicit message.
- **Windows refused-connect latency** (~2 s per attempt, three attempts):
  within budget.
- **Frozen exe plugin import** (see section 2): first Windows run will confirm.
- **Pinning 0x04/502** makes a later correct mapping a deliberate test change;
  intended.
- **Message-limiter interaction:** the new steps add about 18 connects; the
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
| 12 | Test `app.py` headless logic, exclude tray/dialogs/`__main__`/`legacy`/Win32 branches | exclude `app.py` entirely, or omit files from coverage | `app.py` has no Tk and most logic is plain asyncio/state; excluding untestable files from the denominator would hide the gap, so they stay in; they are not covered by the Windows journey or CI (see section 5) |
| 13 | `auth.py` gets only an identity test | mock-heavy tests | It is a pure re-export; behaviour belongs to `shared_auth` tests |
| 14 | `AppKey` migration includes the agent's `remote_exec` keys, and the warning becomes an error | relay only | Same warning, same fix, prevents regressions |
| 15 | Floors set from measured values at the end of D (see 23) | fixed targets now | Avoids a red CI from estimate error; ratchet never lowers |
| 16 | `stream_id` must be `str` <= 128 chars in the relay | accept any hashable | Closes the `TypeError` crash and bounds memory; proxy stream ids are `token_urlsafe(16)` |
| 17 | Error cases are separate steps and fail fast like the rest of the journey | add a non-raising recorder | `check`/`step` raise `StepFailed` today; consistency over a new mechanism |
| 18 | Fix F6a in the relay: drop the stream on `tcp_connect_result success:false` | weaken the `active_streams` assertion | Real leak: 120 s phantom streams after every failed connect; fix is a few lines and makes `/status` honest |
| 19 | Fix F6b in the agent: one bounded (10 s) resolution, validate all answers, connect to the validated IPs in order, keep hostname for logs | keep validate-then-resolve | Closes a DNS-rebinding bypass of the always-blocked ranges and makes DNS failures deterministic; magic/plugin hosts never resolve so are unaffected |
| 20 | Matrix covers each failure on all three front ends, parametrised by a helper | narrow Goal 1 | Goal 1 stays true; helper keeps the code compact |
| 21 | Guard legacy and `remote_exec` JSON parsing too; legacy test optional | relay/agent/proxy only | Shipped code paths with the same crash; remote_exec gets 400 instead of 500 |
| 22 | `missing_service` is a unit test, not a journey step | journey step | The name is not magic, so the journey would test plain DNS |
| 23 | Floors use `floor(measured)` | measured minus 1 | Matches `coverage_report.py:41` |
| 25 | Fix F6d: separate app-shutdown event from the per-connection stop event | stop replacing `_stop_event` | Exit after the agent started is silently ignored today; a dedicated event keeps disconnect semantics intact |
| 26 | `stream_id` (non-empty str, <= 128) and field types validated at every receiver; proxy normalises `error` and survives bad JSON syntax | relay-only checks | One bad frame must never end a receive loop or change the pinned 0x04/502 |
| 27 | `validate_tcp_connect_params` uses `type(port) is int` | `isinstance` | `bool` is an `int` subclass |
| 24 | Windows-only internals (DPAPI, `SendInput`, legacy) listed as uncovered | claim journey coverage | Nothing in CI exercises them; follow-up Windows unit job |
