# Connection Stability Improvements

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix connection stability issues causing frequent disconnects and slow reconnects, and improve throughput.

**Architecture:** Five targeted fixes across the three components (shared, socks-proxy, netbridge-agent). Each fix addresses a specific observed failure mode from production logs: missing backoff in proxy reconnect loop, stale backoff delay in agent after server-initiated close, aggressive PONG timeout, small TCP buffer in agent, and token refresh spinning.

**Tech Stack:** Python 3.14, asyncio, aiohttp, pytest, pytest-asyncio

**Spec:** Investigation findings from production logs showing 1,196 reconnects, 126 PONG timeouts, 531 unreachable-relay events, and 26,735 "no bridge agent" warnings.

## Global Constraints

- All components use `uv run --native-tls` for running and testing
- Tests: `cd <component> && uv run --native-tls pytest`
- Shared constants in `shared/src/shared_auth/session.py` are imported by both proxy and agent
- No new dependencies allowed — only changes to existing code
- Run proxy tests: `cd socks-proxy && uv run --native-tls pytest`
- Run agent tests: `cd netbridge-agent && uv run --native-tls pytest`
- Run shared tests: `cd shared && uv run --native-tls pytest`

---

### Task 1: Add exponential backoff + jitter to proxy reconnect loop

The proxy's `_connection_loop()` always reconnects at a fixed 5-second interval. When the relay is down, this hammers it with attempts indefinitely. Add exponential backoff with jitter, matching the pattern already used in `start()` and the agent's `run_agent()`.

**Files:**
- Modify: `socks-proxy/src/socks_proxy/tunnel.py:155-217` (TunnelManager.__init__) and `socks-proxy/src/socks_proxy/tunnel.py:374-439` (_connection_loop)
- Test: `socks-proxy/tests/test_tunnel.py`

**Interfaces:**
- Consumes: `RECONNECT_DELAY`, `RECONNECT_DELAY_MAX`, `RECONNECT_BACKOFF_FACTOR` from shared auth
- Produces: No new public API — internal behavior change only

**Why jitter:** Without jitter, if the relay restarts and N clients disconnect simultaneously, they all reconnect at 5s, 10s, 20s, etc. — thundering herd. Adding `random.uniform(0, delay * 0.3)` spreads them out.

- [ ] **Step 1: Write the failing test**

Add to `socks-proxy/tests/test_tunnel.py`:

```python
class TestConnectionLoopBackoff:
    """Tests for exponential backoff in _connection_loop reconnection."""

    @pytest.mark.asyncio
    async def test_reconnect_uses_backoff(self):
        """Reconnect delay increases after each failure."""
        from socks_proxy.tunnel import RECONNECT_DELAY, RECONNECT_DELAY_MAX, RECONNECT_BACKOFF_FACTOR

        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm._connected.set()

        delays = []
        original_sleep = asyncio.sleep

        async def capture_sleep(duration):
            delays.append(duration)
            tm._stopping = True  # stop after capturing

        connect_calls = 0

        async def fake_receive_loop():
            raise ConnectionError("lost")

        async def fake_connect():
            nonlocal connect_calls
            connect_calls += 1
            raise ConnectionError("Cannot reach relay")

        tm._receive_loop = fake_receive_loop
        tm._connect = fake_connect

        with patch("socks_proxy.tunnel.asyncio.sleep", side_effect=capture_sleep):
            await tm._connection_loop()

        assert len(delays) >= 1
        assert delays[0] >= RECONNECT_DELAY
        # The delay should include jitter, so it may be slightly above base
        assert delays[0] <= RECONNECT_DELAY * 1.5

    @pytest.mark.asyncio
    async def test_backoff_resets_on_success(self):
        """Delay resets to initial value after successful reconnection."""
        with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
            tm = TunnelManager("relay.com")
        tm._connected.set()

        call_count = 0
        delays = []

        async def fake_receive_loop():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                tm._stopping = True
            raise ConnectionError("lost")

        async def fake_connect():
            pass  # success

        async def capture_sleep(duration):
            delays.append(duration)

        tm._receive_loop = fake_receive_loop
        tm._connect = fake_connect

        with patch("socks_proxy.tunnel.asyncio.sleep", side_effect=capture_sleep):
            await tm._connection_loop()

        # Both delays should be near RECONNECT_DELAY (reset after successful connect)
        from socks_proxy.tunnel import RECONNECT_DELAY
        for d in delays:
            assert d <= RECONNECT_DELAY * 1.5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /mnt/data/projects/netbridge/socks-proxy && uv run --native-tls pytest tests/test_tunnel.py::TestConnectionLoopBackoff -v`
Expected: FAIL — `_connection_loop` uses fixed `RECONNECT_DELAY`

- [ ] **Step 3: Implement backoff with jitter in _connection_loop**

In `socks-proxy/src/socks_proxy/tunnel.py`, add `import random` at the top, then modify `_connection_loop`:

```python
async def _connection_loop(self) -> None:
    """Manage connection lifecycle with automatic reconnection."""
    current_delay = RECONNECT_DELAY
    while not self._stopping and not self._permanent_failure:
        try:
            # Run receive loop until disconnected
            await self._receive_loop()
            # Connection was healthy — reset backoff
            current_delay = RECONNECT_DELAY
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Connection error: {type(e).__name__}: {e}")

        if self._stopping or self._permanent_failure:
            break

        # Connection lost - clean up and reconnect
        self._connected.clear()
        self._notify_status(connected=False)
        if self.ws and not self.ws.closed:
            await self.ws.close()
        self.ws = None

        jitter = random.uniform(0, current_delay * 0.3)
        sleep_time = current_delay + jitter
        logger.info(f"Reconnecting in {sleep_time:.0f}s...")
        await asyncio.sleep(sleep_time)

        try:
            await self._connect()
            self._notify_status(connected=True)
            self._probe_now.set()
            # Successful connect — reset backoff
            current_delay = RECONNECT_DELAY
        except ConnectionError as e:
            error_str = str(e)
            logger.error(f"Reconnection failed: {e}")
            # Increase backoff for next attempt
            current_delay = min(current_delay * RECONNECT_BACKOFF_FACTOR, RECONNECT_DELAY_MAX)

            # Handle auth errors (401)
            if "(401)" in error_str or "Token invalid" in error_str:
                self._auth_failure_count += 1
                self._notify_status(connected=False, auth_required=True)
                if self._auth_failure_count >= MAX_AUTH_FAILURES:
                    logger.error(f"{MAX_AUTH_FAILURES} consecutive auth failures. Giving up.")
                    logger.error("Run 'az login' to re-authenticate, then restart.")
                    self._permanent_failure = True
                    break

                if self._token_refresh_callback:
                    try:
                        logger.info("Refreshing auth token...")
                        new_token = self._token_refresh_callback()
                        if new_token:
                            self.auth_token = new_token
                            logger.info("Token refreshed successfully")
                    except RuntimeError as refresh_err:
                        logger.error(f"Token refresh failed: {refresh_err}")
                else:
                    logger.error("Cannot refresh token. Restart with fresh credentials.")
                    self._permanent_failure = True
                    break

            elif "(403)" in error_str:
                logger.error("Access forbidden. Your account may not have permission.")
                self._permanent_failure = True
                self._notify_status(connected=False, permanent_failure=True)
                break
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /mnt/data/projects/netbridge/socks-proxy && uv run --native-tls pytest tests/test_tunnel.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add socks-proxy/src/socks_proxy/tunnel.py socks-proxy/tests/test_tunnel.py
git commit -m "fix(proxy): add exponential backoff + jitter to reconnect loop"
```

---

### Task 2: Reset agent reconnect delay after healthy connection

The agent's `connect_and_run()` returns `stop_event.is_set()` — which is `False` for server-initiated disconnects ("Connection closed by server"). This means `success` is `False`, the delay is not reset, and the agent waits 60s before reconnecting even though it had a healthy multi-hour connection. Fix: track connection start time and return a richer signal.

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/agent.py:697-953` (connect_and_run return value + run_agent delay logic)
- Test: `netbridge-agent/tests/test_agent.py`

**Interfaces:**
- Consumes: `RECONNECT_DELAY` from shared auth
- Produces: No new public API — `connect_and_run` return type changes from `bool` to include connection duration info

- [ ] **Step 1: Write the failing test**

Add to `netbridge-agent/tests/test_agent.py`:

```python
class TestReconnectDelayReset:
    """Agent should reset backoff delay after a healthy connection."""

    @pytest.mark.asyncio
    async def test_delay_resets_after_long_connection(self):
        """When a connection lasts > HEALTHY_THRESHOLD, delay resets to initial."""
        from netbridge_agent.agent import run_agent, RECONNECT_DELAY

        delays = []
        call_count = 0
        stop = asyncio.Event()

        async def fake_connect_and_run(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                stop.set()
                return True
            # Simulate a connection that was alive for 120 seconds
            return False

        original_sleep = asyncio.sleep

        async def capture_wait(coro, timeout):
            delays.append(timeout)
            if stop.is_set():
                return
            raise asyncio.TimeoutError

        with patch("netbridge_agent.agent.connect_and_run", side_effect=fake_connect_and_run), \
             patch("netbridge_agent.agent.check_az_login", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_arm_token", return_value="tok"), \
             patch("netbridge_agent.agent.check_token_expiration", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_user_identity", return_value="user@test"), \
             patch("netbridge_agent.agent.cleanup_idle_streams", new_callable=AsyncMock), \
             patch("netbridge_agent.agent.token_refresh_loop", new_callable=AsyncMock), \
             patch("asyncio.wait_for", side_effect=capture_wait):
            await run_agent("relay.com", stop)

        # After a healthy long connection, delay should reset
        # The exact values depend on implementation but first delay
        # after a healthy disconnection should be RECONNECT_DELAY
        assert len(delays) >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run --native-tls pytest tests/test_agent.py::TestReconnectDelayReset -v`
Expected: FAIL or errors with current implementation

- [ ] **Step 3: Modify connect_and_run to return connection duration**

In `netbridge-agent/src/netbridge_agent/agent.py`, change `connect_and_run` to track how long the connection lived:

```python
# Add constant near top of file, after CONNECTION_LIVENESS_TIMEOUT
HEALTHY_CONNECTION_THRESHOLD = 60  # seconds — reset backoff if connection lasted this long

async def connect_and_run(
    state: AgentState,
    relay_url: str,
    proxy: Optional[str],
    proxy_auth_header: Optional[str],
    auth_token: Optional[str],
    stop_event: asyncio.Event,
    on_status_change: Optional[StatusCallback],
    on_session_info: Optional[SessionInfoCallback],
) -> tuple[bool, float]:
    """Establish WebSocket connection and process messages.

    Returns (intentional_stop, connection_duration_seconds).
    """
    connected_at = time.monotonic()
    # ... (existing code unchanged until the return) ...
    
                return stop_event.is_set(), time.monotonic() - connected_at

            finally:
                # ... existing cleanup ...
```

Then in `run_agent`, change the success check:

```python
                result = await connect_and_run(
                    state, relay_url, proxy, proxy_auth_header,
                    token_holder.get(), stop_event,
                    on_status_change, on_session_info,
                )
                intentional_stop, duration = result

                if stop_event.is_set():
                    break

                if intentional_stop:
                    token_holder.failure_count = 0
                    current_delay = RECONNECT_DELAY
                elif duration >= HEALTHY_CONNECTION_THRESHOLD:
                    # Connection was alive long enough — not a connect failure
                    current_delay = RECONNECT_DELAY
```

- [ ] **Step 4: Run all agent tests**

Run: `cd /mnt/data/projects/netbridge/netbridge-agent && uv run --native-tls pytest tests/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/agent.py netbridge-agent/tests/test_agent.py
git commit -m "fix(agent): reset reconnect delay after healthy connection"
```

---

### Task 3: Increase WebSocket heartbeat interval for clients

aiohttp's WebSocket heartbeat sends pings every `HEARTBEAT_INTERVAL` (30s) and expects a pong within `heartbeat/2` (15s). Azure App Service's load balancer can add latency, causing false disconnects. The relay should keep 30s (server-side), but clients (proxy + agent) should use a more generous interval. Also increase the agent's `CONNECTION_LIVENESS_TIMEOUT` proportionally.

**Files:**
- Modify: `shared/src/shared_auth/session.py` — add `CLIENT_HEARTBEAT_INTERVAL`
- Modify: `socks-proxy/src/socks_proxy/tunnel.py:348` — use `CLIENT_HEARTBEAT_INTERVAL`
- Modify: `netbridge-agent/src/netbridge_agent/agent.py:60,722` — use `CLIENT_HEARTBEAT_INTERVAL` and update `CONNECTION_LIVENESS_TIMEOUT`
- Test: `shared/tests/test_session.py`

**Interfaces:**
- Produces: `CLIENT_HEARTBEAT_INTERVAL = 45` in shared_auth.session (45s ping → 22.5s pong timeout, vs current 15s)

- [ ] **Step 1: Add CLIENT_HEARTBEAT_INTERVAL to shared session**

In `shared/src/shared_auth/session.py`, after `HEARTBEAT_INTERVAL`:

```python
HEARTBEAT_INTERVAL = get_int_env("NETBRIDGE_HEARTBEAT_INTERVAL", 30)
CLIENT_HEARTBEAT_INTERVAL = get_int_env("NETBRIDGE_CLIENT_HEARTBEAT_INTERVAL", 45)
```

- [ ] **Step 2: Update proxy tunnel.py to import and use CLIENT_HEARTBEAT_INTERVAL**

In `socks-proxy/src/socks_proxy/tunnel.py`, add `CLIENT_HEARTBEAT_INTERVAL` to the import from `.auth` and change `_connect` at line 348:

```python
self.ws = await self.session.ws_connect(
    self.relay_url,
    headers=headers,
    heartbeat=CLIENT_HEARTBEAT_INTERVAL,
)
```

- [ ] **Step 3: Update agent to use CLIENT_HEARTBEAT_INTERVAL for its WS connection**

In `netbridge-agent/src/netbridge_agent/agent.py`:
1. Add `CLIENT_HEARTBEAT_INTERVAL` to the import from `.auth`
2. Change `CONNECTION_LIVENESS_TIMEOUT` from 90 to 135 (3 × CLIENT_HEARTBEAT_INTERVAL)
3. Change `ws_connect` call at line 722 to use `heartbeat=CLIENT_HEARTBEAT_INTERVAL`

- [ ] **Step 4: Update the auth re-export in proxy and agent**

In `socks-proxy/src/socks_proxy/auth.py` and `netbridge-agent/src/netbridge_agent/auth.py`, add `CLIENT_HEARTBEAT_INTERVAL` to the re-exports from `shared_auth.session`.

- [ ] **Step 5: Run all tests**

Run:
```bash
cd /mnt/data/projects/netbridge/shared && uv run --native-tls pytest -v
cd /mnt/data/projects/netbridge/socks-proxy && uv run --native-tls pytest -v
cd /mnt/data/projects/netbridge/netbridge-agent && uv run --native-tls pytest -v
```
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add shared/src/shared_auth/session.py socks-proxy/src/socks_proxy/tunnel.py socks-proxy/src/socks_proxy/auth.py netbridge-agent/src/netbridge_agent/agent.py netbridge-agent/src/netbridge_agent/auth.py
git commit -m "fix: increase client-side heartbeat interval to reduce false disconnects"
```

---

### Task 4: Increase agent TCP buffer size

The agent reads TCP data in 8KB chunks (`TCP_BUFFER_SIZE = 8192`) while the proxy uses 64KB (`READ_BUFFER_SIZE = 65536`). Each chunk becomes a separate WebSocket message. Using 8KB means 8× more messages for the same data volume — direct throughput impact.

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/agent.py:56`

**Interfaces:**
- No interface changes — internal constant only

- [ ] **Step 1: Change TCP_BUFFER_SIZE**

In `netbridge-agent/src/netbridge_agent/agent.py`, change line 56:

```python
TCP_BUFFER_SIZE = 65536
```

- [ ] **Step 2: Run agent tests**

Run: `cd /mnt/data/projects/netbridge && cd netbridge-agent && uv run --native-tls pytest tests/ -v`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add netbridge-agent/src/netbridge_agent/agent.py
git commit -m "perf(agent): increase TCP read buffer from 8KB to 64KB"
```

---

### Task 5: Fix token refresh spinning

`TOKEN_REFRESH_THRESHOLD = 600` (10 minutes) causes continuous refreshing when Azure tokens only last ~10 minutes. Each refresh produces a new 10-minute token that immediately triggers the next refresh cycle. Lower the threshold so we only refresh once near expiry instead of spinning for the entire token lifetime.

**Files:**
- Modify: `shared/src/shared_auth/session.py:36` — reduce `TOKEN_REFRESH_THRESHOLD`
- Test: `shared/tests/test_session.py`

**Interfaces:**
- Modifies: `TOKEN_REFRESH_THRESHOLD` from 600 to 300 (5 minutes)

- [ ] **Step 1: Change TOKEN_REFRESH_THRESHOLD**

In `shared/src/shared_auth/session.py`, change line 36:

```python
TOKEN_REFRESH_THRESHOLD = 300  # seconds - refresh when less than 5 minutes remaining
```

- [ ] **Step 2: Run shared tests**

Run: `cd /mnt/data/projects/netbridge/shared && uv run --native-tls pytest tests/ -v`
Expected: ALL PASS

- [ ] **Step 3: Run proxy and agent tests to verify no regressions**

Run:
```bash
cd /mnt/data/projects/netbridge/socks-proxy && uv run --native-tls pytest tests/ -v
cd /mnt/data/projects/netbridge/netbridge-agent && uv run --native-tls pytest tests/ -v
```
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add shared/src/shared_auth/session.py
git commit -m "fix: reduce token refresh threshold to avoid spinning with short-lived tokens"
```
