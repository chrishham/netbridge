# WebSocket close diagnostics (Βήμα 0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every WebSocket leg (relay↔agent, relay↔proxy) logs *who* ended it, with close code, reason, duration and exception, and the agent logs when its own event loop stalls, so the disconnects observed 2026-10-20..24 can be attributed to Cloudflare / corporate proxy / relay / agent.

**Architecture:** Pure logging changes at the three places where a WebSocket loop ends (relay `handle_websocket`/`handle_tunnel`, proxy `_receive_loop`, agent `connect_and_run`), plus a small `LoopWatchdog` daemon thread in the agent that pings the asyncio loop and logs a stack dump when it does not answer within 60 s. No protocol, config or behaviour change.

**Tech Stack:** Python 3.12+, aiohttp (WS `close_code`, `exception()`, `WSMessage.extra`), stdlib `threading`/`sys._current_frames`, pytest + pytest-asyncio + `caplog`.

**Spec:** No separate design doc. The approved description is the "Βήμα 0" item in `docs/ROADMAP.md` (section "Εκκρεμότητες Claude", 2026-10-24) and the investigation findings above it. Summary of the agreed scope:
1. Relay: INFO log on agent/tunnel connect (user, client IP) and on disconnect (close code, duration, exception, streams closed).
2. Proxy: log close code and session duration when the relay connection ends.
3. Agent: log close code, close reason, duration when the relay connection ends (CLOSE/CLOSED/ERROR/liveness).
4. Agent: event-loop watchdog thread; WARNING with stack of the loop thread after 60 s without response, INFO when it recovers.
Out of scope: fixing head-of-line blocking, quieting the "Proxy authentication required" noise, auto-update, deployment.

## Global Constraints

- Work on branch `ws-close-diagnostics` off `main`; commit per task; human-style commit messages, no AI attribution lines.
- `docs/` is gitignored: `git add -f docs/...` for roadmap/plan changes.
- Use `uv run pytest` in each component dir; never plain `python`/`pytest`.
- No new runtime dependencies. No Windows-only APIs in `watchdog.py` (tests run on Linux CI).
- Log format stays plain f-strings through each component's existing `logger`; new lines are `key=value` pairs so they can be grepped: `close_code=`, `reason=`, `duration=`, `exc=`.
- Do not change heartbeat intervals, timeouts, reconnect behaviour or message handling.
- Test commands (all must stay green):
  - `cd relay && uv run pytest -q`
  - `cd socks-proxy && uv run pytest -q`
  - `cd netbridge-agent && uv sync --group dev && uv run pytest -q`

## Review Focus

1. **Clean close must not print `exc=None`** — summary strings include `exc=` only when `ws.exception()` is not None (relay Task 1 test `test_agent_disconnect_logs_close_summary` asserts `"exc=" not in message`).
2. **Relay disconnect line must fire on every exit path** — it lives in the `finally:` of both handlers, so a handler exception or cancellation still logs it (Task 1 Step 3 placement).
3. **Agent CLOSE frame without a reason** — `msg.extra` is `''`; the line must still print `reason=''` and the right code (Task 3 test uses `extra=""` in one case).
4. **Watchdog must not false-alarm at shutdown or keep the process alive** — daemon thread; `stop()` is called before `loop.close()`; a closed loop (`call_soon_threadsafe` raising `RuntimeError`) ends the thread silently (Task 4 test `test_watchdog_exits_quietly_when_loop_closed`).
5. **Proxy duration when `_connected_at` was never set** — `_receive_loop` can run with `_connected_at == 0.0` in tests/edge cases; duration must then be reported as `0s`, not a monotonic-clock-sized number (Task 2 test asserts `duration=0s`).

---

### Task 1: Relay connection lifecycle logs

**Files:**
- Modify: `relay/src/relay/__main__.py` (helper near `_agent_alive` ~line 812; `handle_websocket` ~693-808; `handle_tunnel` ~1035-1140)
- Test: `relay/tests/test_relay_lifecycle.py`

**Interfaces:**
- Produces: `_ws_close_summary(ws: web.WebSocketResponse, connected_at: float) -> str` returning `f"close_code={ws.close_code} duration={int(time.monotonic() - connected_at)}s"` plus `f" exc={type(e).__name__}: {e}"` only when `e = ws.exception()` is not None.
- Log lines (exact prefixes, grep targets):
  - `Agent connected: {user_email} from {client_ip}`
  - `Agent disconnected: {user_email} {summary}`
  - `Tunnel connected: {tunnel_key} from {client_ip}`
  - `Tunnel disconnected: {tunnel_key} {summary} streams_closed={n}`
  All at INFO. `client_ip` comes from the existing `_client_ip(request)` (line ~398).

- [ ] **Step 1: Write the failing tests** (append to `relay/tests/test_relay_lifecycle.py`, reuse `client`, `Peer`, `USER`, `WAIT`; use the `caplog` fixture at `logging.INFO` for logger `"relay.__main__"` — check `mod.logger.name` and pass that name to `caplog.set_level(logging.INFO, logger=...)`)

```python
async def test_agent_connect_and_disconnect_are_logged(client, caplog):
    caplog.set_level(logging.INFO, logger=mod.logger.name)
    agent = Peer(await client.ws_connect("/ws"))
    await agent.expect("registered")
    await agent.ws.close(code=1001, message=b"going away")
    await _wait_for_log(caplog, "Agent disconnected:")
    msgs = [r.getMessage() for r in caplog.records]
    assert any(m.startswith(f"Agent connected: {USER} from ") for m in msgs)
    disc = next(m for m in msgs if m.startswith("Agent disconnected:"))
    assert f"Agent disconnected: {USER} close_code=1001 duration=" in disc
    assert "exc=" not in disc

async def test_tunnel_disconnect_logs_summary_and_stream_count(client, caplog):
    caplog.set_level(logging.INFO, logger=mod.logger.name)
    agent = Peer(await client.ws_connect("/ws")); await agent.expect("registered")
    tunnel = Peer(await client.ws_connect("/tunnel"))
    await tunnel.send(type="tcp_connect", stream_id="s1", host="10.0.0.1", port=80)
    await agent.expect("tcp_connect", stream_id="s1")
    await tunnel.ws.close(code=1000)
    await _wait_for_log(caplog, "Tunnel disconnected:")
    msgs = [r.getMessage() for r in caplog.records]
    assert any(m.startswith(f"Tunnel connected: {USER}:") for m in msgs)
    disc = next(m for m in msgs if m.startswith("Tunnel disconnected:"))
    assert "close_code=1000" in disc and "streams_closed=1" in disc
```

Add a module-level helper in the test file:
```python
async def _wait_for_log(caplog, prefix, timeout=WAIT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(r.getMessage().startswith(prefix) for r in caplog.records):
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"no log line starting with {prefix!r}")
```
(If the existing tests already use a destination that passes the relay's filters in no-auth mode, copy that host/port instead of `10.0.0.1:80`; `test_tunnel_disconnect_notifies_agent` at line ~154 shows the working pattern.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd relay && uv run pytest -q tests/test_relay_lifecycle.py -k "logged or logs_summary"`
Expected: FAIL (no log line starting with "Agent disconnected:" / "Tunnel disconnected:").

- [ ] **Step 3: Implement**

- Add `_ws_close_summary` per Interfaces, next to `_agent_alive`.
- `handle_websocket`: capture `client_ip = _client_ip(request)` and `connected_at = time.monotonic()` right after `ws.prepare`; log `Agent connected: …` immediately after `bridge_agents[user_email] = ws` (outside the lock); in the existing `finally:` log `Agent disconnected: …` **before** `await _cleanup_agent(ws, user_email)`.
- `handle_tunnel`: same pattern; log `Tunnel connected: …` after `tunnel_clients[tunnel_key] = ws`; in the `finally:` log `Tunnel disconnected: … streams_closed={len(streams_to_remove)}` after the lock block that computes `streams_to_remove` (so the count is available) and before notifying agents.
- Do not touch the "Replacing existing …" warnings.

- [ ] **Step 4: Run the relay suite**

Run: `cd relay && uv run pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add relay/src/relay/__main__.py relay/tests/test_relay_lifecycle.py
git commit -m "Log relay WebSocket connect/disconnect with close code and duration"
```

---

### Task 2: Proxy close summary

**Files:**
- Modify: `socks-proxy/src/socks_proxy/tunnel.py` (`__init__` state; `_connect` ~348-388; `_receive_loop` ~883-920)
- Test: `socks-proxy/tests/test_tunnel_reconnect.py`

**Interfaces:**
- Produces: attribute `TunnelManager._connected_at: float` (0.0 until `_connect` succeeds; set to `time.monotonic()` next to `self._connected.set()`).
- Log lines in `_receive_loop`, after the `async for` ends normally (peer closed): WARNING `Relay connection ended: close_code={ws.close_code} duration={d}s`; in the `WSMsgType.ERROR` branch: ERROR `WebSocket error: {exc} (close_code={ws.close_code} duration={d}s)` replacing the current message; where `d = int(time.monotonic() - self._connected_at) if self._connected_at else 0`. The `"Connection lost"` CLOSED branch is dead code under aiohttp's `__anext__` (it stops iteration on CLOSE/CLOSING/CLOSED) — leave it.

- [ ] **Step 1: Write the failing tests** (append to `test_tunnel_reconnect.py`)

```python
@pytest.mark.asyncio
async def test_receive_loop_logs_close_code_and_duration(caplog):
    caplog.set_level(logging.WARNING, logger="socks_proxy.tunnel")
    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")
    tm._connected.set()
    tm._connected_at = time.monotonic() - 12
    fake_ws = AsyncMock()
    fake_ws.closed = False
    fake_ws.close_code = 1006
    fake_ws.__aiter__ = lambda self: self
    fake_ws.__anext__ = AsyncMock(side_effect=StopAsyncIteration())
    tm.ws = fake_ws

    await tm._receive_loop()

    msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(m.startswith("Relay connection ended: close_code=1006 duration=1") for m in msgs)

@pytest.mark.asyncio
async def test_receive_loop_duration_is_zero_without_connect_timestamp(caplog):
    caplog.set_level(logging.WARNING, logger="socks_proxy.tunnel")
    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")
    fake_ws = AsyncMock(); fake_ws.closed = False; fake_ws.close_code = 1000
    fake_ws.__aiter__ = lambda self: self
    fake_ws.__anext__ = AsyncMock(side_effect=StopAsyncIteration())
    tm.ws = fake_ws
    await tm._receive_loop()
    assert any("close_code=1000 duration=0s" in r.getMessage() for r in caplog.records)
```
Add `import logging, time` to the test module. Confirm the logger name with `grep -n getLogger socks-proxy/src/socks_proxy/tunnel.py` and adjust the `logger=` argument.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd socks-proxy && uv run pytest -q tests/test_tunnel_reconnect.py -k receive_loop_logs or duration_is_zero`
Expected: FAIL (no matching log line).

- [ ] **Step 3: Implement** per Interfaces. Initialise `self._connected_at = 0.0` in `__init__`; set it in `_connect` on success; add the summary WARNING right after the `async for` block inside the `try` (so it does not fire on `CancelledError` or on exceptions, which have their own log lines).

- [ ] **Step 4: Run the proxy suite**

Run: `cd socks-proxy && uv run pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add socks-proxy/src/socks_proxy/tunnel.py socks-proxy/tests/test_tunnel_reconnect.py
git commit -m "Log close code and session duration when the relay connection ends"
```

---

### Task 3: Agent close summary

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/agent.py` (`connect_and_run` message loop ~1010-1040)
- Test: `netbridge-agent/tests/test_agent_reconnect.py`

**Interfaces:**
- Replace the three loop-exit log lines in `connect_and_run` (keep the `break`s and return values unchanged). With `d = int(time.monotonic() - connected_at)`:
  - liveness: WARNING `No messages for {int(idle_time)}s, assuming dead (duration={d}s)` — the existing test asserts `"assuming dead"` is still present.
  - `WSMsgType.ERROR`: ERROR `WebSocket error: {ws.exception()} (close_code={ws.close_code} duration={d}s)`
  - `WSMsgType.CLOSE`: WARNING `Connection closed by server: close_code={msg.data} reason={msg.extra!r} duration={d}s`
  - `WSMsgType.CLOSED`: WARNING `Connection closed by server: close_code={ws.close_code} reason='' duration={d}s`
  Both close variants start with `Connection closed by server: close_code=`.

- [ ] **Step 1: Write the failing tests** (new class in `test_agent_reconnect.py`, using the existing `_make_fake_websocket`; the fake `ws` is a `MagicMock`, so set `fake_client_session.ws_connect.return_value.__aenter__.return_value.close_code = 1006` where needed)

```python
class TestCloseSummaryLogging:
    @pytest.mark.asyncio
    async def test_close_frame_logs_code_and_reason(self, caplog):
        caplog.set_level(logging.WARNING)
        stop = asyncio.Event(); state = AgentState()
        messages = [
            MagicMock(type=aiohttp.WSMsgType.TEXT, data='{"type": "registered"}'),
            MagicMock(type=aiohttp.WSMsgType.CLOSE, data=1001, extra="going away"),
        ]
        fake = _make_fake_websocket(messages)
        with patch("netbridge_agent.agent.aiohttp.ClientSession", return_value=fake), \
             patch("netbridge_agent.agent.close_all_streams", new_callable=AsyncMock):
            intentional, _ = await connect_and_run(state, "ws://relay.com", None, None, "token", stop, None, None)
        assert intentional is False
        line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("Connection closed by server:"))
        assert "close_code=1001" in line and "reason='going away'" in line and "duration=" in line

    @pytest.mark.asyncio
    async def test_closed_without_frame_logs_ws_close_code(self, caplog):
        caplog.set_level(logging.WARNING)
        stop = asyncio.Event(); state = AgentState()
        messages = [
            MagicMock(type=aiohttp.WSMsgType.TEXT, data='{"type": "registered"}'),
            MagicMock(type=aiohttp.WSMsgType.CLOSED, data=None, extra=None),
        ]
        fake = _make_fake_websocket(messages)
        fake.ws_connect.return_value.__aenter__.return_value.close_code = 1006
        with patch("netbridge_agent.agent.aiohttp.ClientSession", return_value=fake), \
             patch("netbridge_agent.agent.close_all_streams", new_callable=AsyncMock):
            await connect_and_run(state, "ws://relay.com", None, None, "token", stop, None, None)
        line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("Connection closed by server:"))
        assert "close_code=1006" in line and "reason=''" in line
```
Add `import logging` at the top of the test module.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd netbridge-agent && uv run pytest -q tests/test_agent_reconnect.py -k CloseSummary`
Expected: FAIL (`StopIteration` from `next(...)`, since the old message is at INFO without `close_code=`).

- [ ] **Step 3: Implement** per Interfaces. Split the combined `(CLOSED, CLOSE)` branch into two `elif`s.

- [ ] **Step 4: Run the agent suite**

Run: `cd netbridge-agent && uv sync --group dev && uv run pytest -q`
Expected: all pass (including `test_liveness_timeout_ends_session` and `test_disconnect_closes_all_streams`).

- [ ] **Step 5: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/agent.py netbridge-agent/tests/test_agent_reconnect.py
git commit -m "Log close code, reason and duration when the agent's relay connection ends"
```

---

### Task 4: Agent event-loop watchdog

**Files:**
- Create: `netbridge-agent/src/netbridge_agent/watchdog.py`
- Modify: `netbridge-agent/src/netbridge_agent/app.py` (`_run_async_loop` ~791-799)
- Test: `netbridge-agent/tests/test_watchdog.py` (new)

**Interfaces:**
- Produces:
```python
class LoopWatchdog:
    def __init__(self, loop: asyncio.AbstractEventLoop, loop_thread_id: int,
                 interval: float = 30.0, stall_threshold: float = 60.0) -> None
    def start(self) -> None   # starts a daemon thread named "netbridge-loop-watchdog"
    def stop(self) -> None    # signals the thread and joins it (timeout = interval)
```
- Behaviour of the thread, each `interval` seconds while not stopped: schedule `loop.call_soon_threadsafe(event.set)` and wait up to `stall_threshold` for `event`. If it is not set in time, log WARNING `Event loop unresponsive for {n}s` followed by a newline and the formatted stack of `sys._current_frames()[loop_thread_id]` (via `traceback.format_stack`), then keep waiting in `interval` chunks, repeating the WARNING with the cumulative `n` on each chunk. When the event is finally set after a stall, log INFO `Event loop responsive again after {n}s`. If `call_soon_threadsafe` raises `RuntimeError` (loop closed) or `stop()` was called, exit the thread without logging. Logger: `logging.getLogger(__name__)` of the module.
- `app.py` `_run_async_loop`: after `asyncio.set_event_loop(...)`, create `LoopWatchdog(self._async_loop, threading.get_ident())`, `start()` it, and `stop()` it in the `finally:` before `self._async_loop.close()`. Keep it as `self._watchdog`.

- [ ] **Step 1: Write the failing tests** (`tests/test_watchdog.py`; these use a real loop in a real thread, no asyncio marker)

```python
import asyncio, logging, threading, time
import pytest
from netbridge_agent.watchdog import LoopWatchdog

def _loop_in_thread():
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    ident = []
    def run():
        asyncio.set_event_loop(loop); ident.append(threading.get_ident()); ready.set(); loop.run_forever()
    t = threading.Thread(target=run, daemon=True); t.start(); ready.wait(1)
    return loop, t, ident[0]

def _stop(loop, t):
    loop.call_soon_threadsafe(loop.stop); t.join(2); loop.close()

def test_healthy_loop_logs_nothing(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent.watchdog")
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident, interval=0.05, stall_threshold=0.2); wd.start()
    time.sleep(0.4); wd.stop(); _stop(loop, t)
    assert caplog.records == []

def test_stalled_loop_logs_warning_with_stack_and_recovery(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent.watchdog")
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident, interval=0.05, stall_threshold=0.1); wd.start()
    loop.call_soon_threadsafe(time.sleep, 0.6)   # block the loop thread
    time.sleep(1.0); wd.stop(); _stop(loop, t)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings and warnings[0].getMessage().startswith("Event loop unresponsive for ")
    assert "File \"" in warnings[0].getMessage()          # stack dump attached
    assert any(r.getMessage().startswith("Event loop responsive again after ") for r in caplog.records)

def test_watchdog_exits_quietly_when_loop_closed(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent.watchdog")
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident, interval=0.05, stall_threshold=0.1); wd.start()
    _stop(loop, t)                                     # loop closed while watchdog runs
    time.sleep(0.3)
    assert not wd._thread.is_alive()
    assert caplog.records == []

def test_thread_is_daemon():
    loop, t, ident = _loop_in_thread()
    wd = LoopWatchdog(loop, ident); wd.start()
    assert wd._thread.daemon and wd._thread.name == "netbridge-loop-watchdog"
    wd.stop(); _stop(loop, t)
```
If the test suite runs with `pytest-socket` disabling sockets, `asyncio.new_event_loop()` still works (selector self-pipe uses `socket.socketpair`); if it raises, add `@pytest.mark.enable_socket` to these tests.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd netbridge-agent && uv run pytest -q tests/test_watchdog.py`
Expected: FAIL with `ModuleNotFoundError: netbridge_agent.watchdog`.

- [ ] **Step 3: Implement `watchdog.py`** per Interfaces (thread body is the algorithm given in Interfaces; `stop()` sets a `threading.Event` that the waits also observe so stop is prompt).

- [ ] **Step 4: Run the watchdog tests**

Run: `cd netbridge-agent && uv run pytest -q tests/test_watchdog.py`
Expected: PASS.

- [ ] **Step 5: Wire into `app.py` `_run_async_loop`** per Interfaces (import `threading` is already present in app.py — verify with grep; add if not).

- [ ] **Step 6: Run the agent suite**

Run: `cd netbridge-agent && uv run pytest -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/watchdog.py netbridge-agent/src/netbridge_agent/app.py netbridge-agent/tests/test_watchdog.py
git commit -m "Add an event-loop watchdog to the agent that logs stalls with a stack dump"
```

---

### Task 5: Roadmap bookkeeping

**Files:**
- Modify: `docs/ROADMAP.md` ("Εκκρεμότητες Claude" → Βήμα 0 line; "Ιστορικό")

- [ ] **Step 1: Update the roadmap**: mark the Βήμα 0 sub-item as done (`[x]`, "υλοποιήθηκε 2026-10-24, branch ws-close-diagnostics"), add a one-line "how to read" note under it: grep `close_code=` in the three logs and `Event loop unresponsive` in the agent log; add a dated history line.

- [ ] **Step 2: Commit**

```bash
git add -f docs/ROADMAP.md docs/superpowers/plans/2026-10-24-ws-close-diagnostics.md
git commit -m "Mark the disconnect diagnostics step done in the roadmap"
```
