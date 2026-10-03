# Fault and reconnect e2e (sub-project B)

Date: 2026-10-03
Status: autonomous design (user: "προχώρα τα" after sub-project A); decisions logged below
Depends on: sub-project A (`coverage-gate`, PR #20) — this branch is stacked on it

## Context

The e2e journey covers exactly one failure: a clean relay restart
(`journey.py` `_reconnect`). The agent/proxy reconnect paths, the relay's
cleanup when one side vanishes, and what happens to streams that are open at
the moment of a fault are untested end to end, and mostly untested in unit
tests too (see "Unit gaps").

Facts this design relies on (verified in code, 2026-10-03):

- Agent connects to `<relay>/ws`, proxy to `<relay>/tunnel`, both plain
  `ws://` in e2e; the relay checks neither Host nor Origin, so a TCP proxy in
  front of the relay is transparent.
- Ping/pong heartbeats: relay → clients every `RELAY_HEARTBEAT_INTERVAL`
  (default 30 s); clients → relay every `NETBRIDGE_CLIENT_HEARTBEAT_INTERVAL`
  (default 45 s). aiohttp drops the socket when a pong is ~interval/2 late.
  The agent also has a hard-coded 135 s liveness timeout (not used here).
- Reconnect: agent 5 → 10 → … → 60 s, no jitter, reset only after a
  connection that lasted ≥ 60 s; proxy 5 s + up to 30 % jitter, reset after
  every successful connect.
- Relay rate limits: 10 connections/min per user (agent + proxy share
  `anonymous@local` in no-auth mode) and 30/min per IP — a fault loop from
  127.0.0.1 would hit 429s. Both are env-tunable
  (`RELAY_RATE_CONNECTIONS_PER_MIN`, `RELAY_RATE_IP_CONNECTIONS_PER_MIN`).
- Streams never survive a reconnect. On agent disconnect the relay sends
  `tcp_close reason=agent_disconnected` to the tunnel clients; on proxy
  disconnect the proxy closes every local socket itself. While disconnected,
  the proxy answers new SOCKS connects with reply `0x04`.

## Goals

1. Exercise, in both journey modes (source and exe), each realistic link
   fault between a client and the relay, and assert the promises a user
   relies on:
   - the tunnel recovers by itself within a bounded time;
   - streams open at the moment of the fault end promptly (EOF/error), they
     never hang;
   - while the tunnel is down, new connections fail fast with a SOCKS error
     instead of hanging.
2. Cover the untested reconnect/cleanup logic with unit tests that use
   deterministic fakes instead of real sockets and timers.
3. Show the result in the e2e coverage report from sub-project A.

## Non-goals

- Changing product behaviour (reconnect timings, liveness timeout). If a test
  exposes a real bug, it is reported, not silently worked around; product
  fixes are separate commits with their own unit tests.
- Fault injection between agent and target, or proxy and local client.
- Stream resumption (not a product feature).
- Network-level tools (tc/iptables/toxiproxy): they need root or extra
  binaries and do not work on the Windows runner.

## Design

### 1. `FaultProxy` (new `e2e/src/netbridge_e2e/faultproxy.py`)

A threaded TCP forwarder that runs inside the driver process (works on Linux
and the Windows runner, no extra binaries). One instance listens on a free
loopback port and forwards each accepted connection to the relay port.

API:

```python
class FaultProxy:
    def __init__(self, upstream: tuple[str, int], name: str): ...
    port: int                      # where clients connect
    url: str                       # "ws://127.0.0.1:<port>"
    def start(self) -> None
    def close(self) -> None        # stop listening, close everything
    def active(self) -> int        # open client connections
    def cut(self) -> int           # close every open connection now (both legs); returns how many
    def blackhole(self) -> int     # open connections stay open but forward nothing either way
                                   #   (half-open link); new connections pass normally; returns how many
    def refuse(self, on: bool) -> None  # while on: accept and immediately close new connections
                                        #   (relay unreachable); existing connections unaffected
```

- Each connection is two sockets pumped by two threads with `select`-free
  blocking `recv`/`sendall`; a per-connection state flag (`open`, `blackholed`,
  `closed`) decides whether received bytes are forwarded or dropped.
  Blackholed connections keep reading (so the kernel buffers never fill and
  the peer never sees backpressure) and discard the bytes.
- `cut()` uses `SO_LINGER(1, 0)` before close so the peer sees a reset, like
  a dropped NAT entry, rather than a graceful FIN.
- Thread-safe; `close()` is idempotent and joins its threads with a timeout.
- Upstream connect failure (relay down) closes the client connection at once,
  so the existing relay-restart step behaves as before.

### 2. Wiring into the journey

- Two proxies, created right after `relay_up`:
  `agent_link = FaultProxy(("127.0.0.1", relay.port), "agent")` and
  `proxy_link = FaultProxy(..., "proxy")`. The agent's `relay_url` and the
  proxy's `--relay` (source) / `relay_url` (exe config) use their `url`.
  Both are closed in the journey's cleanups.
- A new step `fault_links_up` records the two ports.
- Every existing step keeps passing unchanged (the links are in pass-through
  mode); the existing relay restart still works because the links reconnect
  upstream for each new connection.
- Environment for relay, agent and proxy (both modes, plus the docker relay
  via its `-e` list):
  - `RELAY_HEARTBEAT_INTERVAL=10`, `NETBRIDGE_CLIENT_HEARTBEAT_INTERVAL=10`
    — a half-open link is detected in ~15 s instead of ~45 s;
  - `RELAY_RATE_CONNECTIONS_PER_MIN=600`,
    `RELAY_RATE_IP_CONNECTIONS_PER_MIN=600` — fault-driven reconnects from one
    IP must not be throttled (the limiter itself is unit-tested).

### 3. New journey steps (`_faults`, after `_reconnect`, before uninstall)

Helper: `_open_echo()` opens a SOCKS5 stream to the echo target and proves a
round trip; `_wait_stream_end(sock, timeout)` returns how long it took until
`recv` returned `b""` or raised (reset/aborted), or `None` on timeout.
`_wait_traffic(timeout)` repeats the SOCKS GET until it succeeds (the loop
from `_reconnect`, extracted and reused there).

In order (each step's timeout is a promise, chosen from the facts above with
margin):

1. **`agent_cut_ends_streams`** — open an echo stream, `agent_link.cut()`;
   the stream must end within 15 s (relay sends `agent_disconnected`).
2. **`agent_cut_recovers`** — traffic flows again within 45 s, and the agent
   logged a new `CONNECTED` status line after the cut.
3. **`proxy_cut_ends_streams`** — open an echo stream, `proxy_link.cut()`;
   the stream must end within 5 s (the proxy closes local sockets itself).
4. **`proxy_cut_recovers`** — traffic within 45 s; the proxy logged a new
   `RELAY_SESSION` line after the cut.
5. **`agent_blackhole_detected`** — open an echo stream,
   `agent_link.blackhole()`; the stream must end within 45 s (relay ping
   timeout → `agent_disconnected`) and traffic must flow again within 75 s
   (client ping timeout ~15 s + reconnect delay ≤ 20 s through a fresh,
   unaffected connection).
6. **`relay_unreachable_fails_fast`** — `refuse(True)` on both links, then
   `cut()` both. Within 20 s a SOCKS connect must fail with a `ProxyError`
   (not succeed, not hang); every attempt must return within 10 s. Then
   `refuse(False)`; **`relay_reachable_recovers`**: traffic within 90 s
   (agent backoff may have grown to 20–40 s while refused).
7. **`agent_down_fails_fast`** — stop the agent process. A SOCKS connect
   must fail with a `ProxyError` within 15 s of the stop, each attempt
   returning within 10 s. **`agent_restarted`** — start the agent again
   (same install/config); traffic within 60 s and relay `/status` shows
   exactly one agent.

Each failing step includes the relevant evidence in its detail: elapsed
time, relay `/status`, and the component log tail.

### 4. Unit tests (deterministic fakes)

Fakes live next to the tests that use them; no real timers (patch
`asyncio.sleep`/constants), no real network (pytest-socket from A stays on).

- **relay** (`relay/tests/test_relay_lifecycle.py`), driving the real
  aiohttp app through `aiohttp.test_utils` (loopback only):
  - agent disconnect → every tunnel client of that user receives
    `tcp_close` with `reason=agent_disconnected` for its streams, and
    `/status` drops the agent;
  - tunnel client disconnect → the agent receives `tunnel_client_disconnected`;
  - a second agent for the same user replaces the first (first is closed);
  - `cleanup_stale_streams` sends `idle_timeout` to both sides for a stream
    idle longer than `RELAY_STREAM_TIMEOUT`, and leaves fresh streams alone.
- **agent** (`netbridge-agent/tests/test_agent_reconnect.py`):
  - a `FlakyConnector` fake (`fail_times=N`, then a fake websocket that
    closes after a configurable lifetime) proves the backoff sequence
    5, 10, 20, 40, 60, 60 for repeated short-lived connections and the reset
    to 5 after a connection that lasted ≥ 60 s;
  - liveness: no messages for longer than `CONNECTION_LIVENESS_TIMEOUT`
    makes the receive loop give up (with the constant patched small);
  - disconnect calls `close_all_streams` (target sockets closed, pending
    connects cancelled).
- **socks-proxy** (`socks-proxy/tests/test_tunnel_reconnect.py`):
  - `_receive_loop` ending (closed websocket) closes every StreamHandler;
  - new SOCKS connects while disconnected map to reply `0x04`;
  - reconnect after `fail_times=N` failed handshakes, delays within the
    jittered bounds.
- **e2e driver** (`e2e/tests/test_faultproxy.py`): pass-through round trip;
  `cut()` makes both peers see the connection end (reset) and returns the
  count; `blackhole()` keeps the sockets open while dropping bytes, and new
  connections pass; `refuse(True)` closes new connections immediately,
  `refuse(False)` restores; upstream down → client connection closed;
  `close()` idempotent and leaves no threads.

If a unit test or journey step exposes a product bug, the fix goes in its own
commit with a unit test, and the finding is listed in the final report.

### 5. CI

No new jobs. `ci.yml` `e2e-source`, `release-relay.yml` (image mode) and
`e2e-windows.yml` (exe mode) already run the journey, so they gain the fault
steps automatically. The e2e-source job timeout (20 min) is kept; the new
steps add at most ~7 min in the worst case (sum of step deadlines), typically
~2 min. `e2e-windows.yml` has 45 min.

## Error handling

- `FaultProxy` threads never raise into the driver; socket errors end that
  connection only. A crashed pump closes both legs.
- A fault step that fails stops the journey like any other step (fail-fast
  semantics of `Journey.step`), and cleanups close the fault proxies.

## Testing

- Driver unit tests for `FaultProxy` and the new helpers (above).
- Component unit tests (above), all under pytest-socket.
- Full source journey locally (with `--coverage`), and image mode if docker
  is available; exe mode runs in `e2e-windows.yml` on the PR.

## Success criteria

- The journey (source mode) passes with all new steps; the fault steps are
  reported with their measured recovery times.
- The new unit tests pass and raise relay/agent/proxy coverage (floors raised
  per A's ratchet hints).
- E2E coverage of `relay`, `netbridge_agent` and `socks_proxy` goes up
  versus A's numbers (54.25 / 20.95 / 36.46 %).

## Decisions

| Decision | Alternatives | Why |
|---|---|---|
| In-process threaded TCP fault proxy | toxiproxy, tc/netem, iptables | no root, no binaries, works on the Windows runner |
| One fault proxy per client link | one shared proxy | fault each side independently |
| Shorten heartbeats via env in e2e | keep defaults | half-open detection in ~15 s keeps CI time bounded; the knobs already exist |
| Raise rate limits in e2e | keep defaults | fault loops from 127.0.0.1 would hit 429s; limiter is unit-tested |
| Fault steps in both modes | source only | the release exe is what users run |
