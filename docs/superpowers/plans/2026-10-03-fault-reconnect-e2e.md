# Fault and Reconnect E2E Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Inject realistic link faults between each client and the relay in the e2e journey, assert recovery and fail-fast promises, fix the three product bugs the design review found, and cover reconnect/cleanup logic with deterministic unit tests.

**Architecture:** A threaded in-process `FaultProxy` sits between agent→relay and proxy→relay. New journey steps cut, blackhole and refuse those links and restart the agent, measuring every deadline from one fault time `t0`. Product fixes: pending SOCKS connects fail on disconnect (socks-proxy); relay streams remember their owning agent websocket for their whole life; the stale sweep re-checks activity before closing.

**Tech Stack:** Python 3.14, uv, pytest, pytest-asyncio, aiohttp (`aiohttp.test_utils`), stdlib `socket`/`select`/`threading`.

**Spec:** `docs/superpowers/specs/2026-10-03-fault-reconnect-e2e-design.md`

## Global Constraints

- Always use `uv`; Python `>=3.14`. Run component tests with `cd <component> && uv run pytest -q` (add `--cov` to check floors).
- Unit tests stay network-free: pytest-socket (`--allow-hosts=127.0.0.1,::1,localhost`) is on in relay, netbridge-agent, socks-proxy; only loopback servers are allowed.
- No real waiting in unit tests: patch delays/constants (`asyncio.sleep`, `RECONNECT_DELAY`, `CONNECTION_LIVENESS_TIMEOUT`, `STREAM_CLEANUP_INTERVAL`, `STREAM_TIMEOUT`), keep every test < 2 s.
- Product fixes are test-first, each in its own commit, smallest change.
- e2e env for fault tests: `RELAY_HEARTBEAT_INTERVAL=10`, `NETBRIDGE_CLIENT_HEARTBEAT_INTERVAL=10`, `RELAY_RATE_CONNECTIONS_PER_MIN=600`, `RELAY_RATE_IP_CONNECTIONS_PER_MIN=600`.
- Fault step deadlines (all measured from the fault's `t0`): agent cut — stream end 15 s, recovery 45 s; proxy cut — stream end 5 s, recovery 45 s; agent blackhole — stream end 45 s, CONNECT error 30 s, recovery 75 s; relay unreachable — `0x04` within 20 s (each attempt ≤ 10 s), recovery 90 s after un-refuse; agent down — `0x04` within 15 s (each attempt ≤ 10 s) with relay agents == 0 and proxy link active, recovery 60 s after restart, `/status` agents == 1.
- Before agent-disconnecting faults (cut, blackhole, unreachable) wait until the agent's session is ≥ 65 s old.
- Every fault step asserts `link.active() >= 1` before and injection count `>= 1`.
- Coverage floors (`[tool.coverage.report] fail_under`) may only go up; raise them to floor(measured) at the end.
- Commit messages: plain, no Claude attribution / Co-Authored-By lines.
- Match the surrounding style: compact code, sparse comments explaining *why*.

## Review Focus

- A blocked `recv` that `cut()` must interrupt (POSIX does not wake on close) — pinned in Task 1 `test_cut_ends_both_legs_promptly` (≤ 1 s).
- Large transfers through the fault proxy must not be killed by socket timeouts on `sendall` (the 5 MiB `bulk_payload` step) — pinned in Task 1 `test_large_transfer_passes`.
- A CONNECT pending at the moment of a relay `tcp_close` or websocket loss must get `0x04` at once, not `0x06` after 30 s — Task 2 tests.
- During agent replacement an old stream's tunnel bytes must never reach the new agent — Task 3 `test_old_stream_data_not_forwarded_to_replacement`.
- The journey must not pass vacuously when a fault hits zero connections — Task 5 asserts counts.

---

### Task 1: `FaultProxy`

**Files:**
- Create: `e2e/src/netbridge_e2e/faultproxy.py`
- Create: `e2e/tests/test_faultproxy.py`

**Interfaces:**
- Produces: `class FaultProxy(upstream: tuple[str, int], name: str)` with `port: int`, `url: str` (`"ws://127.0.0.1:<port>"`), `start()`, `close()`, `active() -> int`, `cut() -> int`, `blackhole() -> int`, `refuse(on: bool) -> None`.

- [ ] **Step 1: Write the failing tests** — `e2e/tests/test_faultproxy.py`:

```python
import socket
import threading
import time

import pytest

from netbridge_e2e.faultproxy import FaultProxy


@pytest.fixture
def echo_server():
    srv = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=_echo, args=(c,), daemon=True).start()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()
    stop.set()
    srv.close()
    t.join(2)


def _echo(c):
    with c:
        try:
            while data := c.recv(65536):
                c.sendall(data)
        except OSError:
            pass


@pytest.fixture
def fp(echo_server):
    p = FaultProxy(echo_server, "test")
    p.start()
    yield p
    p.close()


def connect(fp):
    s = socket.create_connection(("127.0.0.1", fp.port), timeout=5)
    s.sendall(b"ping")
    assert s.recv(4) == b"ping"
    return s


def wait_until(pred, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def ended(s, timeout=1.0) -> bool:
    s.settimeout(timeout)
    try:
        return s.recv(1) == b""
    except socket.timeout:
        return False
    except OSError:
        return True


def test_url_and_pass_through(fp):
    assert fp.url == f"ws://127.0.0.1:{fp.port}"
    with connect(fp):
        assert wait_until(lambda: fp.active() == 1)


def test_large_transfer_passes(fp):
    data = bytes(range(256)) * 20480  # 5 MiB
    with connect(fp) as s:
        got = bytearray()
        sender = threading.Thread(target=s.sendall, args=(data,))
        sender.start()
        s.settimeout(10)
        while len(got) < len(data):
            got += s.recv(1 << 16)
        sender.join(10)
    assert bytes(got) == data


def test_cut_ends_both_legs_promptly(fp):
    s1, s2 = connect(fp), connect(fp)
    start = time.monotonic()
    assert fp.cut() == 2
    assert ended(s1) and ended(s2)
    assert time.monotonic() - start < 1.5
    assert wait_until(lambda: fp.active() == 0)
    with connect(fp):  # new connections still pass
        pass


def test_blackhole_keeps_sockets_open_but_drops_bytes(fp):
    s = connect(fp)
    assert fp.blackhole() == 1
    s.sendall(b"lost")
    s.settimeout(0.5)
    with pytest.raises(socket.timeout):
        s.recv(4)
    assert fp.active() == 1
    with connect(fp):  # a fresh connection is unaffected
        pass
    s.close()
    assert wait_until(lambda: fp.active() == 0)


def test_refuse_closes_new_connections_until_lifted(fp):
    old = connect(fp)
    fp.refuse(True)
    s = socket.create_connection(("127.0.0.1", fp.port), timeout=5)
    assert ended(s)
    old.sendall(b"ok")  # existing connections unaffected
    assert old.recv(2) == b"ok"
    fp.refuse(False)
    with connect(fp):
        pass
    old.close()


def test_upstream_down_closes_client():
    dead = socket.create_server(("127.0.0.1", 0))
    addr = dead.getsockname()
    dead.close()
    p = FaultProxy(addr, "dead")
    p.start()
    try:
        s = socket.create_connection(("127.0.0.1", p.port), timeout=5)
        assert ended(s, timeout=3)
    finally:
        p.close()


def test_close_is_idempotent_and_stops_threads(echo_server):
    before = threading.active_count()
    p = FaultProxy(echo_server, "t")
    p.start()
    connect(p)
    p.close()
    p.close()
    assert wait_until(lambda: threading.active_count() <= before, timeout=3)
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd e2e && uv run pytest tests/test_faultproxy.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'netbridge_e2e.faultproxy'`.

- [ ] **Step 3: Implement** — `e2e/src/netbridge_e2e/faultproxy.py`:

```python
"""In-process TCP fault injector between a client and the relay.

Runs in the driver (Linux and the Windows runner, no root, no binaries).
Pumps wait with select() so they notice a state change within one tick;
cut() shuts sockets down, which also wakes a blocked sendall().
"""
import select
import socket
import threading

TICK = 0.2


def _close(s: socket.socket) -> None:
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


class _Conn:
    def __init__(self, client: socket.socket, upstream: socket.socket):
        self.client = client
        self.upstream = upstream
        self.state = "open"  # open | blackholed | closed
        self.lock = threading.Lock()
        self.threads: list[threading.Thread] = []

    def kill(self) -> bool:
        with self.lock:
            if self.state == "closed":
                return False
            self.state = "closed"
        _close(self.client)
        _close(self.upstream)
        return True


class FaultProxy:
    def __init__(self, upstream: tuple[str, int], name: str):
        self.upstream = upstream
        self.name = name
        self._lsock = socket.create_server(("127.0.0.1", 0))
        self.port = self._lsock.getsockname()[1]
        self.url = f"ws://127.0.0.1:{self.port}"
        self._lock = threading.Lock()
        self._conns: set[_Conn] = set()
        self._refuse = False
        self._closed = False
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._spawn(self._accept_loop, f"fault-{self.name}-accept", self._threads)

    def _spawn(self, target, name, into, *args) -> None:
        t = threading.Thread(target=target, args=args, name=name, daemon=True)
        t.start()
        into.append(t)

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                ready, _, _ = select.select([self._lsock], [], [], TICK)
                if not ready:
                    continue
                client, _ = self._lsock.accept()
            except OSError:
                break
            if self._refuse:  # relay unreachable: the TCP handshake works, then nothing
                _close(client)
                continue
            try:
                up = socket.create_connection(self.upstream, timeout=5)
            except OSError:  # relay down: fail the client at once, like a refused connect
                _close(client)
                continue
            up.settimeout(None)
            conn = _Conn(client, up)
            with self._lock:
                if self._closed:
                    conn.kill()
                    break
                self._conns.add(conn)
            for src, dst in ((client, up), (up, client)):
                self._spawn(self._pump, f"fault-{self.name}-pump", conn.threads, conn, src, dst)

    def _pump(self, conn: _Conn, src: socket.socket, dst: socket.socket) -> None:
        try:
            while conn.state != "closed":
                ready, _, _ = select.select([src], [], [], TICK)
                if not ready:
                    continue
                data = src.recv(65536)
                if not data:
                    break
                if conn.state == "open":  # blackholed: keep draining, forward nothing
                    dst.sendall(data)
        except (OSError, ValueError):  # ValueError: select on a socket closed by cut()
            pass
        finally:
            conn.kill()
            with self._lock:
                self._conns.discard(conn)

    def _live(self) -> list[_Conn]:
        with self._lock:
            return [c for c in self._conns if c.state != "closed"]

    def active(self) -> int:
        return len(self._live())

    def cut(self) -> int:
        return sum(c.kill() for c in self._live())

    def blackhole(self) -> int:
        n = 0
        for c in self._live():
            with c.lock:
                if c.state == "open":
                    c.state = "blackholed"
                    n += 1
        return n

    def refuse(self, on: bool) -> None:
        self._refuse = on

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        _close(self._lsock)
        conns = self._live()
        for c in conns:
            c.kill()
        for t in self._threads + [t for c in conns for t in c.threads]:
            t.join(2)
```

- [ ] **Step 4: Run tests**

Run: `cd e2e && uv run pytest tests/test_faultproxy.py -q` → all pass. Then `cd e2e && uv run pytest -q` → all pass. If `test_close_is_idempotent_and_stops_threads` is flaky because pump threads of connections that ended on their own are not joined, keep their `Thread` objects reachable (e.g. collect into a list under `_lock` when spawned) and join them in `close()`.

- [ ] **Step 5: Commit**

```bash
git add e2e/src/netbridge_e2e/faultproxy.py e2e/tests/test_faultproxy.py
git commit -m "Add an in-process TCP fault proxy to the e2e driver"
```

---

### Task 2: socks-proxy — fail pending connects on close (bug 1) + reconnect/teardown tests

**Files:**
- Modify: `socks-proxy/src/socks_proxy/stream.py` (`StreamHandler.close`)
- Modify: `socks-proxy/src/socks_proxy/tunnel.py` (`connect`: clean up on a `ConnectionError` from the future)
- Create: `socks-proxy/tests/test_tunnel_reconnect.py`

**Interfaces:**
- Produces: `StreamHandler.close()` fails a not-yet-done `connect_future` with `ConnectionError("stream closed before connect completed")`; `TunnelManager.connect()` (tunnel.py) raises `ConnectionError` promptly when that happens and releases the stream slot. `socks5.py` already maps `ConnectionError` → reply `0x04`.

Read first: `stream.py` (whole), `tunnel.py` `connect` (≈ lines 670–760), `_receive_loop` and `_handle_message` (≈ 845–915), `_connection_loop` / reconnect (≈ 376–448), and the existing `tests/test_tunnel.py` fixtures (reuse its fake websocket helpers rather than inventing new ones).

- [ ] **Step 1: Failing tests** in `socks-proxy/tests/test_tunnel_reconnect.py` (async tests marked `@pytest.mark.asyncio` like the existing ones):
  1. `test_close_fails_pending_connect` — create `StreamHandler(stream_id="s", connect_future=loop.create_future())`, `await handler.close()`, assert `handler.connect_future.done()` and its exception is a `ConnectionError`; closing an already-resolved future must not raise.
  2. `test_ws_loss_fails_pending_connect_fast` — a tunnel client wired to a fake websocket that accepts `send_str` but never answers; start `connect("10.0.0.1", 80, timeout=30)` as a task, wait until the stream is registered, then end the fake websocket's message iteration (so `_receive_loop` runs its cleanup). The task must raise `ConnectionError` within 1 s (assert with `asyncio.wait_for(task, 1)`), `streams` must be empty and the semaphore slot released (the next 1 connect can acquire immediately).
  3. `test_relay_tcp_close_fails_pending_connect` — same setup, but deliver `{"type": "tcp_close", "stream_id": <id>, "reason": "agent_disconnected"}` through `_handle_message`; `connect` raises `ConnectionError` within 1 s.
  4. `test_socks_reply_is_host_unreachable_on_pending_close` — drive `socks5.handle_socks5_client` with a fake tunnel whose `connect` raises `ConnectionError`; the reply byte is `0x04`. (If an existing socks5 test already proves the mapping, reference it in the report and skip this one.)
  5. `test_receive_loop_end_closes_established_streams` — two established handlers; after the loop ends both are `closed` and `read()` returns `None`.
  6. `test_reconnect_after_failed_handshakes` — patch the websocket factory to fail `N=3` times (raise `aiohttp.ClientError`) then succeed; patch the reconnect sleep to record delays instead of sleeping; assert 3 retries happened and each recorded delay is within `[base, base * 1.3]` for the documented backoff (read the constants in `tunnel.py`/`shared_auth.session`).
- [ ] **Step 2:** `cd socks-proxy && uv run pytest tests/test_tunnel_reconnect.py -q` — tests 1–3 FAIL (connect hangs / future not failed); record RED.
- [ ] **Step 3: Fix (smallest change).** In `StreamHandler.close()`, before/after marking closed: `if not self.connect_future.done(): self.connect_future.set_exception(ConnectionError("stream closed before connect completed"))`. In `TunnelManager.connect()`, catch `ConnectionError` from awaiting the future alongside the `TimeoutError` path: pop the stream, release its semaphore slot (idempotent helper already exists), re-raise. Make sure no "Future exception was never retrieved" warning appears when a handler is closed without anyone awaiting its future (e.g. established streams: their future is already done, so nothing is set).
- [ ] **Step 4:** `cd socks-proxy && uv run pytest -q --cov` — all pass, output free of new warnings.
- [ ] **Step 5: Commit** (two commits): tests+fix for bug 1 — "Fail pending SOCKS connects at once when their stream closes"; remaining reconnect/teardown tests — "Cover socks-proxy reconnect and stream teardown".

---

### Task 3: relay — stream owner for the whole life (bug 2), stale-sweep recheck (bug 3), lifecycle tests

**Files:**
- Modify: `relay/src/relay/__main__.py` (`StreamInfo`, `_handle_tcp_connect`, agent handler `handle_websocket` message forwarding and `finally`, `_handle_tcp_data`, `_handle_tcp_close`, `handle_tunnel` `finally`, `cleanup_stale_streams`)
- Create: `relay/tests/test_relay_lifecycle.py`

**Interfaces:**
- Produces: `StreamInfo` gains `agent_ws: web.WebSocketResponse`. All tunnel→agent forwarding for a stream uses `stream["agent_ws"]`; agent→tunnel messages for a stream are accepted only when the sending websocket is that `agent_ws`. A closing agent handler pops/notifies only streams with `agent_ws is ws`. `cleanup_stale_streams` re-checks `now - last_activity > STREAM_TIMEOUT` under the lock immediately before popping each stream.

Read first: `__main__.py` lines ≈ 380–480 (state, sweep), 520–660 (agent handler), 660–845 (tcp handlers), 844–962 (tunnel handler), `create_app()`; and `relay/tests/test_relay.py` for how state is reset between tests (module dicts `bridge_agents`, `tunnel_clients`, `tcp_streams`, limiters).

- [ ] **Step 1: Failing/coverage tests** in `relay/tests/test_relay_lifecycle.py`, driving the real app with `aiohttp.test_utils.TestServer`/`TestClient` (loopback only) in no-auth mode (set the module's no-auth flag/env exactly as `test_relay.py` does), resetting module state in a fixture:
  1. `test_agent_disconnect_closes_its_streams` — connect agent (`/ws`, read `registered`), tunnel (`/tunnel`); tunnel sends `tcp_connect` (agent receives it); agent closes → tunnel receives `tcp_close` with `reason == "agent_disconnected"` for that stream; `/status` shows 0 agents.
  2. `test_tunnel_disconnect_notifies_agent` — tunnel with an open stream closes → agent receives `tunnel_client_disconnected`.
  3. `test_replacement_keeps_new_agent_and_its_streams` (bug 2) — agent A registers; tunnel opens stream S1 (routed to A); agent B (same user) connects → A is closed by the relay; tunnel opens S2 (routed to B); after A's handler finished: B is still in `bridge_agents`, S2 still in `tcp_streams`, S1 is gone and the tunnel received `tcp_close`/`agent_disconnected` for S1 only.
  4. `test_old_stream_data_not_forwarded_to_replacement` (bug 2) — hold A's cleanup open (or send before A's handler exits) and have the tunnel send `tcp_data` for S1 after B registered: B must never receive a message with `stream_id == S1`.
  5. `test_stale_sweep_closes_idle_streams_only` — patch `STREAM_CLEANUP_INTERVAL` to ~0.01 and `STREAM_TIMEOUT` small; one idle stream, one with fresh `last_activity`; run the sweep task briefly: idle one gets `tcp_close reason=idle_timeout` on both sides and is removed; fresh one stays.
  6. `test_stale_sweep_rechecks_before_closing` (bug 3) — force the interleaving: make the sweep's scan see the stream as stale, then refresh `last_activity` before the removal (e.g. wrap `_state_lock` or patch `time.monotonic`/`safe_ws_send` so the refresh happens between scan and pop); the stream must survive and no `tcp_close` is sent for it.
- [ ] **Step 2:** `cd relay && uv run pytest tests/test_relay_lifecycle.py -q` — 3, 4, 6 FAIL; record RED (1, 2, 5 may pass: they are coverage for untested paths).
- [ ] **Step 3: Fix (smallest change)** as described in Interfaces. Where an `agent_ws` recorded for a stream is closed or no longer registered when the tunnel sends data/close for it, drop the message and send the tunnel `tcp_close` with reason `agent_disconnected` (the stream cannot continue). Keep the existing user-ownership check as well.
- [ ] **Step 4:** `cd relay && uv run pytest -q --cov` — all pass.
- [ ] **Step 5: Commit** (three commits): bug 2 — "Route relay streams through the agent that opened them"; bug 3 — "Recheck stream activity before the stale sweep closes it"; remaining lifecycle tests — "Cover relay connection lifecycle cleanup".

---

### Task 4: agent — reconnect backoff, liveness and disconnect cleanup tests

**Files:**
- Create: `netbridge-agent/tests/test_agent_reconnect.py`
- Modify (only if a test exposes a bug — then stop and report): `netbridge-agent/src/netbridge_agent/agent.py`

**Interfaces:**
- Consumes: `agent.run_agent(...)`, `agent.connect_and_run(...)`, `agent.close_all_streams(state)`, `agent.heartbeat_sender(...)`, constants `RECONNECT_DELAY`/`RECONNECT_DELAY_MAX`/`RECONNECT_BACKOFF_FACTOR` (from `shared_auth.session`), `HEALTHY_CONNECTION_THRESHOLD`, `CONNECTION_LIVENESS_TIMEOUT`, `APP_HEARTBEAT_INTERVAL`.

Read first: `agent.py` ≈ 640–1000 and the existing `tests/test_agent.py::TestReconnectDelayReset` (reuse its patching approach for `connect_and_run`).

- [ ] **Step 1: Tests:**
  1. `test_backoff_escalates_for_short_sessions` — patch `connect_and_run` to return `(False, 1.0)` (a 1 s session) six times then set `stop_event`; capture the reconnect waits (patch the `asyncio.wait_for(stop_event.wait(), timeout=...)` call site or record `timeout` values); assert `[5, 10, 20, 40, 60, 60]`.
  2. `test_backoff_resets_after_healthy_session` — sessions `(False, 1.0)`, `(False, 1.0)`, `(False, 61.0)`, `(False, 1.0)` → waits `[5, 10, 5, 10]`.
  3. `test_handshake_failures_escalate` — `connect_and_run` raises `aiohttp.ClientError` 3 times → waits `[5, 10, 20]` (a `FlakyConnector`-style fake with `fail_times`).
  4. `test_liveness_timeout_ends_session` — run `connect_and_run` against a fake `aiohttp.ClientSession.ws_connect` whose websocket sends `registered` then nothing; patch `CONNECTION_LIVENESS_TIMEOUT` to 0.05 and the 1 s receive poll so the test is fast; it returns `(False, duration)` and the log contains `assuming dead`.
  5. `test_disconnect_closes_all_streams` — same fake, websocket sends `registered` then CLOSED; assert `close_all_streams` was awaited (patch it with an `AsyncMock`) and the heartbeat task was cancelled.
  6. `test_close_all_streams_closes_targets_and_cancels_pending` — build an `AgentState` with one open fake target writer and one pending connect task; after `close_all_streams(state)` the writer is closed and the task cancelled, state emptied.
- [ ] **Step 2:** `cd netbridge-agent && uv run pytest tests/test_agent_reconnect.py -q` — all pass (no product change expected). If one fails because of a product defect, do NOT fix it: report status DONE_WITH_CONCERNS with the evidence.
- [ ] **Step 3:** `cd netbridge-agent && uv run pytest -q --cov` — all pass.
- [ ] **Step 4: Commit** — "Cover agent reconnect backoff, liveness and disconnect cleanup".

---

### Task 5: journey fault steps

**Files:**
- Modify: `e2e/src/netbridge_e2e/clients.py` (add `wait_closed`)
- Modify: `e2e/src/netbridge_e2e/stack.py` (`Relay`: fault tuning env incl. docker `-e`)
- Modify: `e2e/src/netbridge_e2e/journey.py` (fault links, env, `_wait_traffic`, agent session tracking, `_faults`)
- Modify: `e2e/tests/test_clients.py`, `e2e/tests/test_stack.py`
- Modify: `e2e/README.md` (steps list)

**Interfaces:**
- Consumes: `FaultProxy` (Task 1); fixed product behaviour (Tasks 2–3).
- Produces: steps `fault_links_up`, `agent_cut_ends_streams`, `agent_cut_recovers`, `proxy_cut_ends_streams`, `proxy_cut_recovers`, `agent_blackhole_detected`, `relay_unreachable_fails_fast`, `relay_reachable_recovers`, `agent_down_fails_fast`, `agent_restarted`.

- [ ] **Step 1: `clients.wait_closed` (TDD).** Test in `e2e/tests/test_clients.py`: a loopback socket pair where the server side closes after 0.2 s → `wait_closed(sock, 2)` is True in < 1 s; server stays open → False after ~0.3 s with `timeout=0.3`; server resets → True. Implement:

```python
def wait_closed(sock: socket.socket, timeout: float) -> bool:
    """True once the peer ends the connection (EOF or error) within timeout; data is discarded."""
    deadline = time.monotonic() + timeout
    while (left := deadline - time.monotonic()) > 0:
        sock.settimeout(min(left, 1.0))
        try:
            if sock.recv(65536) == b"":
                return True
        except socket.timeout:
            continue
        except OSError:
            return True
    return False
```

- [ ] **Step 2: Relay tuning env (TDD).** In `stack.py` add

```python
# fault steps: detect a half-open link in ~15 s, and never throttle fault-driven reconnects from 127.0.0.1
FAULT_TUNING = {"RELAY_HEARTBEAT_INTERVAL": "10", "RELAY_RATE_CONNECTIONS_PER_MIN": "600",
                "RELAY_RATE_IP_CONNECTIONS_PER_MIN": "600"}
CLIENT_TUNING = {"NETBRIDGE_CLIENT_HEARTBEAT_INTERVAL": "10"}
```

and merge `FAULT_TUNING` into `Relay._relay_env` (so the docker `-e` list gets it too). Test in `test_stack.py`: the image-mode argv contains `-e RELAY_HEARTBEAT_INTERVAL=10` (use the existing `captured_argv` helper) and source-mode `Proc` env contains all three keys.

- [ ] **Step 3: Journey wiring.**
  - In `_journey`, after `relay_up`: create `agent_link = FaultProxy(("127.0.0.1", relay.port), "agent")` and `proxy_link = FaultProxy(..., "proxy")`, `start()` both, register `close` in `self.cleanups`, then `self.step("fault_links_up", True, f"agent via :{agent_link.port}, proxy via :{proxy_link.port}")`.
  - `env.update(CLIENT_TUNING)` where the client env is built (before components are created).
  - `_components(agent_url, proxy_url, ip, targets, env)` — the agent gets `agent_link.url`, the proxy `proxy_link.url` (source and exe variants).
  - Track the agent session start: `self._agent_up = time.monotonic()` when `agent_connected` passes and whenever a step observes the agent recovered (relay restart recovery, each agent fault recovery, agent restart).
  - Extract the polling loop of `_reconnect` into `_wait_traffic(self, ip, targets, relay, deadline: float) -> tuple[bool, str]` (absolute monotonic deadline; same body), and use it in `_reconnect` (behaviour unchanged).
  - Call `self._faults(relay, agent, proxy, ip, targets, agent_link, proxy_link)` right after `self._reconnect(...)`.

- [ ] **Step 4: `_faults`** — implement in `journey.py` (helpers are methods):

```python
    def _await_agent_session(self, min_age: float = 65.0) -> None:
        # the agent resets its reconnect delay only after a 60 s session
        wait = self._agent_up + min_age - time.monotonic()
        if wait > 0:
            time.sleep(wait)

    def _open_echo(self, ip: str, targets: Targets):
        s = clients.socks5_connect(self.socks, ip, targets.echo_port, timeout=15)
        if clients.echo_roundtrip(s, b"fault-probe\n") != b"fault-probe\n":
            s.close()
            raise RuntimeError("echo round trip failed before the fault")
        return s

    def _connect_refused(self, ip: str, targets: Targets, timeout: float) -> tuple[str, str]:
        """'refused' (SOCKS 0x04), 'other' (another reply or error), 'ok' (connected) or 'hang'."""
        start = time.monotonic()
        try:
            s = clients.socks5_connect(self.socks, ip, targets.echo_port, timeout=timeout)
        except clients.ProxyError as e:
            took = time.monotonic() - start
            return ("refused" if e.code == 0x04 else "other"), f"SOCKS reply {e.code:#04x} after {took:.1f}s"
        except socket.timeout:
            return "hang", f"no SOCKS reply within {timeout:.0f}s"
        except OSError as e:
            return "other", f"{type(e).__name__}: {e}"
        s.close()
        return "ok", "connected"

    def _fails_fast(self, ip, targets, deadline: float, per_attempt: float = 10.0) -> tuple[bool, str]:
        last = "no attempt"
        while time.monotonic() < deadline:
            kind, last = self._connect_refused(ip, targets, per_attempt)
            if kind == "refused":
                return True, last
            if kind in ("hang", "other"):
                return False, last
            time.sleep(1)  # still connected through a link that has not noticed yet
        return False, f"never refused before the deadline (last: {last})"

    def _inject(self, link: FaultProxy, how: str) -> tuple[float, int]:
        before = link.active()
        n = link.cut() if how == "cut" else link.blackhole()
        if before < 1 or n < 1:
            raise RuntimeError(f"{link.name} link: {before} active, {how} affected {n} (nothing to fault)")
        return time.monotonic(), n

    def _faults(self, relay, agent, proxy, ip, targets, agent_link, proxy_link) -> None:
        def recovered(t0, budget, comp=None, marker=None, mark=None):
            ok, detail = self._wait_traffic(ip, targets, relay, t0 + budget)
            if ok and comp is not None:
                m = comp.logs.wait_for(marker, max(1.0, t0 + budget - time.monotonic()), since=mark)
                ok, detail = m is not None, (f"{detail}; {m.group(0)}" if m else f"{detail}; no new '{marker}' log line")
            return ok, f"{detail} ({time.monotonic() - t0:.0f}s after the fault)"

        # 1-2: agent link cut
        self._await_agent_session()
        mark = agent.logs.mark()
        echo = self._open_echo(ip, targets)
        t0, n = self._inject(agent_link, "cut")
        ended = clients.wait_closed(echo, 15)
        echo.close()
        self.step("agent_cut_ends_streams", ended, f"{n} link(s) cut; open stream ended: {ended} "
                  f"after {time.monotonic() - t0:.1f}s")
        self.check("agent_cut_recovers", lambda: recovered(t0, 45, agent, CONNECTED, mark))
        self._agent_up = time.monotonic()

        # 3-4: proxy link cut (the agent is unaffected)
        mark = proxy.logs.mark()
        echo = self._open_echo(ip, targets)
        t0, n = self._inject(proxy_link, "cut")
        ended = clients.wait_closed(echo, 5)
        echo.close()
        self.step("proxy_cut_ends_streams", ended, f"{n} link(s) cut; open stream ended: {ended} "
                  f"after {time.monotonic() - t0:.1f}s")
        self.check("proxy_cut_recovers", lambda: recovered(t0, 45, proxy, RELAY_SESSION, mark))

        # 5: agent link blackholed (half-open)
        self._await_agent_session()
        echo = self._open_echo(ip, targets)
        t0, n = self._inject(agent_link, "blackhole")
        probe: dict = {}
        worker = threading.Thread(target=lambda: probe.update(r=self._connect_refused(ip, targets, 28)))
        worker.start()
        ended = clients.wait_closed(echo, 45)
        echo.close()
        worker.join(max(0.0, t0 + 30 - time.monotonic()))
        kind, how = probe.get("r", ("hang", "no SOCKS reply within 30s"))
        ok, traffic = recovered(t0, 75)
        self.step("agent_blackhole_detected", ended and kind in ("refused", "other") and ok,
                  f"stream ended: {ended}; CONNECT during blackhole: {how}; {traffic}")
        self._agent_up = time.monotonic()

        # 6: relay unreachable for both clients
        self._await_agent_session()
        for link in (agent_link, proxy_link):
            link.refuse(True)
        t0 = time.monotonic()
        counts = [link.cut() for link in (agent_link, proxy_link)]
        if min(counts) < 1:
            raise RuntimeError(f"relay_unreachable: cut affected {counts} (nothing to fault)")
        self.check("relay_unreachable_fails_fast", lambda: self._fails_fast(ip, targets, t0 + 20))
        for link in (agent_link, proxy_link):
            link.refuse(False)
        t1 = time.monotonic()
        self.check("relay_reachable_recovers", lambda: recovered(t1, 90))
        self._agent_up = time.monotonic()

        # 7: agent process down, then restarted
        agent.stop()
        t0 = time.monotonic()
        def agent_down():
            ok, detail = self._fails_fast(ip, targets, t0 + 15)
            agents, linked = (relay.status() or {}).get("agents"), proxy_link.active()
            # the refusal must come from "no agent", not from a proxy that lost the relay
            return ok and agents == 0 and linked >= 1, f"{detail}; relay sees {agents} agent(s); proxy link {linked}"

        self.check("agent_down_fails_fast", agent_down)
        mark = agent.logs.mark()
        agent.start()
        t1 = time.monotonic()

        def restarted():
            ok, detail = recovered(t1, 60, agent, CONNECTED, mark)
            agents = (relay.status() or {}).get("agents")
            return ok and agents == 1, f"{detail}; relay sees {agents} agent(s)"

        self.check("agent_restarted", restarted)
        self._agent_up = time.monotonic()
```

  Notes: `CONNECTED` and `RELAY_SESSION` already exist in `stack.py`; import `threading`, `socket` and `FaultProxy` in `journey.py` as needed. Blackhole: the CONNECT may get `0x04` or another error reply depending on which side notices first — the promise is "no hang", so both `refused` and `other` pass, `ok` (connected through the dead agent) and `hang` fail. If the real run shows a deadline is not met, first check whether it is a product defect (report it); do not silently widen deadlines — any change to a deadline must be justified in the report with measured numbers.

- [ ] **Step 5: README** — append the new steps after `*_reconnected` in the `## Steps` sequence of `e2e/README.md`, and one sentence: "Both clients reach the relay through in-process fault proxies, so the fault steps can cut, blackhole or refuse each link; heartbeats are shortened to 10 s for the run."
- [ ] **Step 6: Driver tests** — `cd e2e && uv run pytest -q` all pass.
- [ ] **Step 7: Real journey** (Linux, source mode, with coverage):

```bash
for p in relay netbridge-agent socks-proxy e2e; do (cd "$p" && uv sync -q); done
uv run --project e2e python -m netbridge_e2e --mode source --work /tmp/nb-e2e-faults --coverage /tmp/nb-e2e-faults/coverage
```

  All steps PASS; record each fault step's detail (measured times) and `coverage/summary.md` in the report. Run twice to check stability. If docker is available also run `--relay-image` mode with a locally built image (`docker build -f deploy/Dockerfile.netbridge -t nb-relay-e2e .`).
- [ ] **Step 8: Commit** — "Inject link faults between the clients and the relay in the e2e journey".

---

### Task 6: Raise floors

- [ ] Run `scripts/coverage.sh`; for each component whose report row shows a "raise fail_under to N" hint, set `fail_under = N` in its `pyproject.toml`. Re-run `scripts/coverage.sh` → exit 0. Commit "Raise coverage floors after the reconnect tests".

## Final verification

- `scripts/coverage.sh` exit 0.
- Source journey with `--coverage` passes twice; e2e coverage of relay/netbridge_agent/socks_proxy higher than 54.25/20.95/36.46 %.
