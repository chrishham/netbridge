# Error Paths, Plugin Load and Agent Gap-Fill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pin the user-visible result of every connect failure end to end, prove plugins load in the e2e stack, fix the relay/agent/proxy robustness and security bugs the review found (non-object/bad-field messages, failed-connect stream leak, DNS rebinding and IPv4-mapped bypass, pending-connect cancel, shutdown race), and fill the agent unit-test gaps.

**Architecture:** Product fixes are small guards and helpers inside the existing modules (relay `__main__.py`, agent `agent.py`/`app.py`/`remote_exec.py`/`legacy.py`, proxy `tunnel.py`), each test-first. The e2e driver gains a refused-port target, a parametrised failure matrix and plugin fixtures copied into the agent's app dir. Floors are ratcheted last from measured coverage.

**Tech Stack:** Python 3.14, uv, pytest + pytest-asyncio + pytest-socket, aiohttp (test utils), stdlib sockets for the driver.

**Spec:** `docs/superpowers/specs/2026-10-03-error-paths-gapfill-design.md` (finding numbers F1..F6f, section numbers 1..5 and decision numbers below refer to it)

## Global Constraints

- Always `uv` (`cd <component> && uv run pytest -q`); Python `>=3.14`. `shared-auth` is a non-editable path dependency: D changes nothing in `shared/`, so no `uv sync --reinstall-package shared-auth` is needed (run it only if you do touch `shared/`).
- Unit tests are network-free: pytest-socket (`--allow-hosts=127.0.0.1,::1,localhost`) is on in relay, agent and socks-proxy. DNS is always mocked; no real waiting (patch timeouts to ~0.01 s).
- Pinned replies (Decision 1): every connect failure is SOCKS5 **0x04** and HTTP **502**; do NOT add a structured error code.
- Message validation contract: every receiver requires a top-level JSON object; `stream_id` a non-empty `str` of at most **128** characters; `tcp_data.data` a `str`; `tcp_connect_result.success` a `bool`, `error` a `str` when `success` is false (relay drops otherwise) and absent/null when true; `host` a non-empty `str`, `port` a non-bool `int` in 1-65535. Bad message: warn, drop (close the stream where natural), never raise, never end the loop.
- Agent DNS: one `getaddrinfo` with `type=socket.SOCK_STREAM` under `asyncio.wait_for(..., 10.0)`, error text `DNS resolution timed out for <host>`; addresses deduplicated in resolver order; policy checks applied to EVERY address after IPv4-mapped normalisation; connect to the validated IPs in order; resolution + validation + connect all inside the tracked pending task.
- e2e: refused port = bound, never-`listen()`ed socket held by `Targets`; DNS failure name `netbridge-e2e-nxdomain.invalid`; agent denial `169.254.169.254:80`; link-local/loopback literals never need network. Every log assertion uses `LogWatch.mark()` taken before the action and `wait_for(..., since=mark)`. Journey `check` is fail-fast.
- Floors: `floor(measured)` per `scripts/coverage_report.py:41`; never lowered. diff-cover >= 80% on changed `*/src/` lines is a CI gate, so every new product line needs a test.
- Commit messages plain, no Claude attribution or Co-Authored-By lines.
- e2e source journey command (from the auth-e2e plan): `cd e2e && uv run python -m netbridge_e2e --mode source --target-hostname netbridge-e2e-target --work /tmp/e2e` (needs the `netbridge-e2e-target` hosts entry that CI adds, or omit `--target-hostname` locally).

## Review Focus

- A relay/agent/proxy connection must survive one hostile frame of ANY shape (`[1]`, `"x"`, `null`, `42`, `true`, wrong field types, unparsable syntax, lists as `stream_id`): Tasks 1, 2, 4, 7 each parametrise these.
- `::ffff:127.0.0.1`, `::ffff:169.254.169.254` and a resolver that answers a mapped or changing address must not reach the target: Tasks 2 and 3.
- A failed connect must not leave a phantom relay stream and a `tcp_close` during DNS/connect must not leave an orphan socket (including cancel between connect and registration): Tasks 1 and 3.
- Exit from the tray (exit, restart, install) must end the process even after the agent task replaced the stop event, and even if requested during start-up: Task 5.
- A blackholed resolver must not stall heartbeats or other streams: Task 3 (blocked fake `getaddrinfo`).

---

### Task 1: Relay validation, failed-connect release, port bool, AppKey

**Files:**
- Modify: `relay/src/relay/__main__.py` (`validate_tcp_connect_params` ~72-100; agent loop 603-666; tunnel loop 920-960; `_handle_tcp_connect` 679-800; `_handle_tcp_data` 800+; `_handle_tcp_close` 845+; `start_cleanup_task`/`stop_cleanup_task` 485-495)
- Create: `relay/tests/test_relay_malformed.py`, `relay/tests/test_relay_agent_loop.py`
- Modify: `relay/tests/test_relay_lifecycle.py:17-18` (drop the `filterwarnings` line), `relay/pyproject.toml` (`filterwarnings = ["error::aiohttp.web_exceptions.NotAppKeyWarning"]` under `[tool.pytest.ini_options]`)
- Test: `relay/tests/test_destinations.py` (add bool cases)

**Interfaces:**
- Produces in `relay.__main__`: `MAX_STREAM_ID_LENGTH = 128`; `_valid_stream_id(value) -> bool`; `_parse_message(raw: str, who: str) -> dict | None`; `_valid_connect_result(msg: dict) -> bool`; `CLEANUP_TASK = web.AppKey("cleanup_task", asyncio.Task)`.
- New log texts: `Ignoring non-object JSON message from {who}`, `Invalid stream_id from {who}`. `tcp_connect` with a bad `stream_id` answers `tcp_connect_result{stream_id: null, success: false, error: "Invalid stream_id"}`.

New test files import the shared fixtures from the lifecycle module (the tests dir is a package) and mark everything asyncio:

```python
# relay/tests/test_relay_malformed.py
import json

import pytest

from .test_relay_lifecycle import (  # noqa: F401  (fixtures are used by name)
    USER, Peer, client, connect_agent, connect_tunnel, open_stream, relay_state, wait_until,
)
import relay.__main__ as mod

pytestmark = pytest.mark.asyncio

NON_OBJECTS = ["[1]", '"x"', "null", "42", "true"]


def _no_traceback(caplog):
    assert not [r for r in caplog.records if r.levelname == "ERROR"], caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.parametrize("raw", NON_OBJECTS)
async def test_tunnel_survives_non_object(client, raw, caplog):
    tunnel = await connect_tunnel(client)
    await tunnel.ws.send_str(raw)
    await tunnel.send(type="tcp_connect", stream_id="s1", host="10.0.0.1", port=80)
    res = await tunnel.expect("tcp_connect_result", stream_id="s1", success=False)
    assert "agent" in res["error"].lower()          # relay still answers: not torn down
    assert not tunnel.ws.closed
    assert "non-object" in caplog.text
    _no_traceback(caplog)


@pytest.mark.parametrize("raw", NON_OBJECTS)
async def test_agent_ws_survives_non_object(client, raw, caplog):
    agent, _ = await connect_agent(client)
    await agent.ws.send_str(raw)
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "non-object" in caplog.text
    _no_traceback(caplog)


BAD_STREAM_IDS = [None, [1], {}, "", "x" * 129, 7]


@pytest.mark.parametrize("sid", BAD_STREAM_IDS)
async def test_tunnel_bad_stream_id_never_becomes_a_key(client, sid, caplog):
    tunnel = await connect_tunnel(client)
    await tunnel.send(type="tcp_connect", stream_id=sid, host="10.0.0.1", port=80)
    res = await tunnel.expect("tcp_connect_result", success=False)
    assert res["stream_id"] is None and res["error"] == "Invalid stream_id"
    for t in ("tcp_data", "tcp_close"):
        await tunnel.send(type=t, stream_id=sid, data="AA==")
    await tunnel.send(type="tcp_connect", stream_id="ok", host="10.0.0.1", port=80)
    await tunnel.expect("tcp_connect_result", stream_id="ok")
    assert mod.tcp_streams == {}
    _no_traceback(caplog)


@pytest.mark.parametrize("data", [None, 5, [1], {"a": 1}])
async def test_agent_tcp_data_with_non_str_data_is_not_forwarded(client, data):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    await agent.send(type="tcp_connect_result", stream_id="s1", success=True)
    await tunnel.expect("tcp_connect_result", stream_id="s1")
    await agent.send(type="tcp_data", stream_id="s1", data=data)
    await agent.send(type="tcp_data", stream_id="s1", data="AA==")
    got = await tunnel.expect("tcp_data", stream_id="s1")
    assert got["data"] == "AA=="                     # only the valid frame arrived


@pytest.mark.parametrize("fields", [
    {"success": "yes"},                              # non-bool success
    {"success": False},                              # failed result without error
    {"success": False, "error": None},
    {"success": False, "error": 5},
    {"success": True, "error": "boom"},              # error only allowed when absent/null on success
])
async def test_invalid_connect_results_are_dropped(client, fields):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    await agent.send(type="tcp_connect_result", stream_id="s1", **fields)
    await agent.send(type="tcp_connect_result", stream_id="s1", success=True)
    good = await tunnel.expect("tcp_connect_result", stream_id="s1")
    assert good["success"] is True                   # the invalid ones were never forwarded
```

```python
# relay/tests/test_relay_agent_loop.py  (same imports + pytestmark)
async def test_failed_connect_result_releases_the_stream(client):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    assert "s1" in mod.tcp_streams
    await agent.send(type="tcp_connect_result", stream_id="s1", success=False, error="refused")
    res = await tunnel.expect("tcp_connect_result", stream_id="s1", success=False)
    assert res["error"] == "refused"                 # still forwarded
    await wait_until(lambda: "s1" not in mod.tcp_streams)


async def test_successful_connect_result_keeps_the_stream(client):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    await agent.send(type="tcp_connect_result", stream_id="s1", success=True)
    await tunnel.expect("tcp_connect_result", stream_id="s1", success=True)
    assert "s1" in mod.tcp_streams


async def test_failed_result_from_a_foreign_agent_does_not_release(client, monkeypatch):
    agent, _ = await connect_agent(client)
    tunnel = await connect_tunnel(client)
    await open_stream(tunnel, agent, "s1")
    mod.tcp_streams["s1"]["user_email"] = "someone@else"   # stream owned by another user
    await agent.send(type="tcp_connect_result", stream_id="s1", success=False, error="x")
    await agent.send(type="heartbeat")
    await agent.expect("heartbeat_ack")
    assert "s1" in mod.tcp_streams
```

Add to the same file: tcp_close forwarded and removes; ownership denied (other agent socket) dropped with `ownership denied` in caplog; oversized message (`RELAY_MAX_MESSAGE_SIZE` patched to 100) dropped; unknown type warns; invalid JSON warns and loop continues; bandwidth limiter acquired only for `tcp_data` (patch `mod._global_bandwidth_limiter` with an `AsyncMock` having `acquire`, `mod._bytes_per_sec = 1000`).

Port bool test (`test_destinations.py`): `validate_tcp_connect_params("h", True)` and `("h", False)` return `(False, "Port must be an integer")`.

- [ ] **Step 1:** Write the tests above (plus the `test_destinations.py` cases). Run `cd relay && uv run pytest tests/test_relay_malformed.py tests/test_relay_agent_loop.py tests/test_destinations.py -q`; expected FAIL (AttributeError tracebacks, leaked stream, bool accepted).
- [ ] **Step 2:** Implement the helpers (place after `validate_tcp_connect_params`):

```python
MAX_STREAM_ID_LENGTH = 128


def _valid_stream_id(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_STREAM_ID_LENGTH


def _parse_message(raw: str, who: str) -> dict | None:
    """json.loads that only returns objects; warns and returns None otherwise."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON from {who}")
        return None
    if not isinstance(data, dict):
        logger.warning(f"Ignoring non-object JSON message from {who}")
        return None
    return data


def _valid_connect_result(msg: dict) -> bool:
    success = msg.get("success")
    if not isinstance(success, bool):
        return False
    error = msg.get("error")
    return isinstance(error, str) if not success else error is None
```

Then: `validate_tcp_connect_params`: `if type(port) is not int: return False, "Port must be an integer"`. Agent loop (`:613`): `response = _parse_message(msg.data, f"agent {user_email}")`; `if response is None: continue`; for the three TCP types require `_valid_stream_id(response.get("stream_id"))` (else warn `Invalid stream_id from agent {user_email}` and `continue`), `tcp_data` requires `isinstance(response.get("data"), str)`, `tcp_connect_result` requires `_valid_connect_result`; in the cleanup block after forwarding, pop the stream when `msg_type == "tcp_close"` **or** (`msg_type == "tcp_connect_result"` and `response["success"] is False`). Tunnel loop (`:934`): `_parse_message(msg.data, f"tunnel client {tunnel_key}")`; `_handle_tcp_connect` replies the `Invalid stream_id` result before any use of `stream_id`; `_handle_tcp_data`/`_handle_tcp_close` return with a warning on an invalid id (and `tcp_data` on non-str `data`). `app[CLEANUP_TASK]` / `app.get(CLEANUP_TASK)` in the cleanup hooks. Remove the `filterwarnings` line from the lifecycle tests and add the pyproject filter.
- [ ] **Step 3:** `cd relay && uv run pytest -q`; expected all green, no `NotAppKeyWarning`.
- [ ] **Step 4: Commit** "Harden relay message handling and release failed streams".

---

### Task 2: Agent field validation, IPv4-mapped policy, legacy reuse

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/agent.py` (`validate_destination` 72-190; `handle_tcp_connect` 409+; `handle_tcp_data` ~570; `handle_tcp_close` ~599; `handle_message` 607; receive loop 769), `netbridge-agent/src/netbridge_agent/legacy.py` (282, 375, 397, 493, 557, 595)
- Test: `netbridge-agent/tests/test_agent_malformed.py` (create), `netbridge-agent/tests/test_agent.py` (extend `TestValidateDestination`), `netbridge-agent/tests/test_legacy.py`

**Interfaces:**
- Produces in `agent.py`: `MAX_STREAM_ID_LENGTH = 128`; `valid_stream_id(v) -> bool`; `valid_connect_fields(host, port) -> str | None` (None = ok, else the error text `"Invalid host or port"`); `_normalize_ip(addr)` (IPv6 with `ipv4_mapped` -> that `IPv4Address`, else unchanged). `legacy.py` imports `valid_stream_id`, `valid_connect_fields` from `.agent`.

```python
# netbridge-agent/tests/test_agent_malformed.py
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from netbridge_agent.agent import AgentState, handle_message


def _ws():
    ws = MagicMock(closed=False)
    ws.send_str = AsyncMock()
    return ws


def _sent(ws):
    return [json.loads(c.args[0]) for c in ws.send_str.await_args_list]


@pytest.mark.parametrize("raw", ["[1]", '"x"', "null", "42", "true"])
async def test_handle_message_ignores_non_objects(raw):
    await handle_message(AgentState(), _ws(), raw)       # must not raise


@pytest.mark.parametrize("host,port", [([], 80), (None, 80), ("", 80), ("h", True), ("h", "80"),
                                       ("h", 0), ("h", 65536), ("h", None)])
async def test_tcp_connect_with_bad_host_or_port_is_answered_not_crashed(host, port):
    ws = _ws()
    await handle_message(AgentState(), ws, json.dumps(
        {"type": "tcp_connect", "stream_id": "s1", "host": host, "port": port}))
    (res,) = _sent(ws)
    assert res == {"type": "tcp_connect_result", "stream_id": "s1", "success": False,
                   "error": "Invalid host or port"}


@pytest.mark.parametrize("sid", [None, [1], "", "x" * 129, 5])
@pytest.mark.parametrize("kind", ["tcp_connect", "tcp_data", "tcp_close"])
async def test_bad_stream_id_is_dropped(kind, sid):
    ws, state = _ws(), AgentState()
    await handle_message(state, ws, json.dumps(
        {"type": kind, "stream_id": sid, "host": "8.8.8.8", "port": 80, "data": "AA=="}))
    assert state.active_streams == {} and state.pending_connections == {}


@pytest.mark.parametrize("data", [None, 5, [1], "!!not-base64!!"])
async def test_tcp_data_with_bad_data_closes_the_stream(data, mock_writer, mock_reader):
    from netbridge_agent.agent import StreamInfo
    state = AgentState()
    state.active_streams["s1"] = StreamInfo(mock_reader, mock_writer, None, "h", 80)
    await handle_message(state, _ws(), json.dumps({"type": "tcp_data", "stream_id": "s1", "data": data}))
    assert "s1" not in state.active_streams
    mock_writer.close.assert_called()
```

IPv4-mapped tests (extend `TestValidateDestination`; all network-free because literals):

```python
    @pytest.mark.parametrize("host", ["::ffff:127.0.0.1", "[::ffff:127.0.0.1]"])
    async def test_mapped_loopback_blocked(self, host):
        assert (await validate_destination(host, 80))[0] is False
        assert (await validate_destination(host, 80, allow_loopback=True))[0] is True

    @pytest.mark.parametrize("host", ["::ffff:169.254.169.254", "[::ffff:169.254.169.254]"])
    async def test_mapped_link_local_always_blocked(self, host):
        assert (await validate_destination(host, 80, allow_loopback=True))[0] is False

    async def test_mapped_private_follows_allow_private(self):
        assert (await validate_destination("::ffff:10.0.0.1", 80, allow_private=False))[0] is False
        assert (await validate_destination("::ffff:10.0.0.1", 80))[0] is True

    async def test_mapped_address_matches_ipv4_cidr_rules(self):
        assert (await validate_destination("::ffff:10.1.2.3", 80, allowed_destinations=["10.0.0.0/8"]))[0] is True
        assert (await validate_destination("::ffff:11.1.2.3", 80, allowed_destinations=["10.0.0.0/8"]))[0] is False
        assert (await validate_destination("::ffff:10.1.2.3", 80, denied_destinations=["10.0.0.0/8"]))[0] is False

    async def test_plain_ipv6_unaffected(self):
        assert (await validate_destination("2001:4860:4860::8888", 443))[0] is True
```

Legacy test (`test_legacy.py`): `await handle_message(ws, '[1]')`, `'{"type":"tcp_connect","stream_id":[1],"host":null,"port":1}'` do not raise and add nothing to `legacy.active_streams` / `pending_connections`.

- [ ] **Step 1:** Write the tests. Run `cd netbridge-agent && uv run pytest tests/test_agent_malformed.py tests/test_agent.py tests/test_legacy.py -q`; expected FAIL.
- [ ] **Step 2:** Implement in `agent.py`:

```python
MAX_STREAM_ID_LENGTH = 128


def valid_stream_id(value) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_STREAM_ID_LENGTH


def valid_connect_fields(host, port) -> str | None:
    if not isinstance(host, str) or not host:
        return "Invalid host or port"
    if type(port) is not int or not (1 <= port <= 65535):
        return "Invalid host or port"
    return None


def _normalize_ip(addr):
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr
```

In `validate_destination` apply `_normalize_ip` to `host_ip` and to every appended resolved address (before every range/CIDR check). `handle_message`: `request = json.loads(msg)`; `if not isinstance(request, dict): logger.warning("Ignoring non-object JSON message"); return`. `handle_tcp_connect`: right after reading fields, `if not valid_stream_id(stream_id): warn; return`; `err = valid_connect_fields(host, port)`; if err, `send_to_relay` the failed result and return — BEFORE `is_magic_hostname`. `handle_tcp_data`: drop on bad `stream_id`; if `not isinstance(data_b64, str)` or `base64.b64decode(data_b64, validate=True)` raises, warn and `await close_stream(state, stream_id)`; return. `handle_tcp_close`: drop on bad `stream_id` before slicing `stream_id[:8]`. Receive loop (`:769`): after `json.loads`, `isinstance(data, dict)` check before `.get("type")`. In `legacy.py` apply the same top-level guard to its three `json.loads` sites and use `valid_stream_id`/`valid_connect_fields` at `handle_tcp_connect` (282), `handle_tcp_data` (375), `handle_tcp_close` (397) (legacy already imports `validate_destination` at line 23, so it gets the mapped fix; it keeps its own validate-then-connect, spec F6b limit).
- [ ] **Step 3:** `cd netbridge-agent && uv run pytest -q`; expected green.
- [ ] **Step 4: Commit** "Validate agent message fields and normalise IPv4-mapped addresses".

---

### Task 3: Agent single bounded DNS resolution, pending-task cancel and cleanup

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/agent.py` (`validate_destination` signature; `open_tcp_connection` ~262-300; `handle_tcp_connect` `do_connect` 504-565; `close_stream` 313; `handle_tcp_close`)
- Create: `netbridge-agent/tests/test_agent_dns.py`

**Interfaces:**
- Consumes: Task 2 helpers.
- Produces: `DNS_TIMEOUT = 10.0`; `class DnsError(OSError)`; `async def resolve_destination(host: str, port: int, timeout: float = DNS_TIMEOUT) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]` (IP literal -> `[normalised ip]` without DNS; otherwise one `loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)` under `wait_for`, normalised, deduplicated in order; raises `DnsError("DNS resolution timed out for <host>")` or `DnsError(str(gaierror))`); `validate_destination(..., resolved: list | None = None)` (when `resolved` is given it is used and no lookup happens; when None it calls `resolve_destination` and treats `DnsError` as "no addresses", the old behaviour for legacy); `open_tcp_connection(host, port, timeout=30.0, proxy_auth=None, addresses: list | None = None)` (with `addresses` and no upstream proxy: tries `asyncio.open_connection(str(ip), port)` for each in order within the remaining timeout, raises the last error; the hostname is only for logging); `close_stream` also cancels a pending task.

```python
# netbridge-agent/tests/test_agent_dns.py
import asyncio
import json
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netbridge_agent import agent
from netbridge_agent.agent import AgentState, DnsError, handle_message, resolve_destination


def _ws():
    ws = MagicMock(closed=False)
    ws.send_str = AsyncMock()
    return ws


def _results(ws):
    return [json.loads(c.args[0]) for c in ws.send_str.await_args_list]


def _infos(*addrs):
    return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addrs]


async def test_resolution_is_single_and_connect_uses_validated_ip(monkeypatch):
    answers = [_infos("1.2.3.4"), _infos("127.0.0.1")]       # a rebinding resolver
    calls = []

    async def fake_getaddrinfo(self, host, port, **kw):
        calls.append(kw)
        return answers[len(calls) - 1]

    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake_getaddrinfo)
    opened = []

    async def fake_open(host, port):
        opened.append(host)
        return MagicMock(), MagicMock(close=MagicMock(), wait_closed=AsyncMock(), get_extra_info=lambda *_: None)

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    state, ws = AgentState(), _ws()
    await handle_message(state, ws, json.dumps({"type": "tcp_connect", "stream_id": "s1", "host": "rebind.test", "port": 80}))
    await asyncio.gather(*state.pending_connections.values())
    assert len(calls) == 1 and calls[0]["type"] == socket.SOCK_STREAM
    assert opened == ["1.2.3.4"]                              # never the second answer


async def test_one_blocked_address_among_several_rejects(monkeypatch):
    async def fake(self, host, port, **kw):
        return _infos("8.8.8.8", "169.254.169.254")
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake)
    state, ws = AgentState(), _ws()
    await handle_message(state, ws, json.dumps({"type": "tcp_connect", "stream_id": "s1", "host": "x.test", "port": 80}))
    await asyncio.gather(*state.pending_connections.values())
    (res,) = _results(ws)
    assert res["success"] is False and "not allowed" in res["error"]


async def test_resolver_answering_mapped_loopback_is_denied(monkeypatch):
    async def fake(self, host, port, **kw):
        return _infos("::ffff:127.0.0.1")
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake)
    assert (await agent.validate_destination("m.test", 80, resolved=await resolve_destination("m.test", 80)))[0] is False


async def test_dns_timeout_is_bounded_and_reported(monkeypatch):
    async def never(self, host, port, **kw):
        await asyncio.Event().wait()
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", never)
    monkeypatch.setattr(agent, "DNS_TIMEOUT", 0.01)
    with pytest.raises(DnsError, match="DNS resolution timed out for slow.test"):
        await resolve_destination("slow.test", 80, timeout=0.01)
    state, ws = AgentState(), _ws()
    await handle_message(state, ws, json.dumps({"type": "tcp_connect", "stream_id": "s1", "host": "slow.test", "port": 80}))
    await asyncio.wait_for(asyncio.gather(*state.pending_connections.values()), 2)
    (res,) = _results(ws)
    assert res["success"] is False and "timed out" in res["error"]


async def test_addresses_are_deduplicated_in_order(monkeypatch):
    async def fake(self, host, port, **kw):
        return _infos("1.1.1.1", "2.2.2.2", "1.1.1.1")
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake)
    assert [str(a) for a in await resolve_destination("d.test", 80)] == ["1.1.1.1", "2.2.2.2"]


async def test_connect_falls_back_to_the_next_validated_address(monkeypatch):
    tried = []

    async def fake_open(host, port):
        tried.append(host)
        if host == "1.1.1.1":
            raise ConnectionRefusedError("refused")
        return MagicMock(), MagicMock(get_extra_info=lambda *_: None)

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    import ipaddress
    await agent.open_tcp_connection("h.test", 80, addresses=[ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("2.2.2.2")])
    assert tried == ["1.1.1.1", "2.2.2.2"]
    tried.clear()
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(side_effect=ConnectionRefusedError("last")))
    with pytest.raises(ConnectionRefusedError, match="last"):
        await agent.open_tcp_connection("h.test", 80, addresses=[ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("2.2.2.2")])


async def test_dns_pending_does_not_block_other_streams(monkeypatch, mock_writer, mock_reader):
    gate = asyncio.Event()

    async def blocked(self, host, port, **kw):
        await gate.wait()
        return _infos("8.8.8.8")

    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", blocked)
    state, ws = AgentState(), _ws()
    agent_info = agent.StreamInfo(mock_reader, mock_writer, None, "b", 80)
    state.active_streams["B"] = agent_info
    await handle_message(state, ws, json.dumps({"type": "tcp_connect", "stream_id": "A", "host": "slow.test", "port": 80}))
    # the loop returned while A's DNS is pending: B's data and close are processed now
    await asyncio.wait_for(handle_message(state, ws, json.dumps({"type": "tcp_data", "stream_id": "B", "data": "AA=="})), 1)
    mock_writer.write.assert_called_once_with(b"\x00")
    await asyncio.wait_for(handle_message(state, ws, json.dumps({"type": "tcp_close", "stream_id": "B"})), 1)
    assert "B" not in state.active_streams and "A" in state.pending_connections
    state.pending_connections["A"].cancel()
    gate.set()


async def test_tcp_close_cancels_pending_dns_and_no_stream_appears(monkeypatch):
    gate, opened = asyncio.Event(), []

    async def blocked(self, host, port, **kw):
        await gate.wait()
        return _infos("8.8.8.8")

    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", blocked)
    monkeypatch.setattr(asyncio, "open_connection", lambda *a, **k: opened.append(a))
    state, ws = AgentState(), _ws()
    await handle_message(state, ws, json.dumps({"type": "tcp_connect", "stream_id": "A", "host": "slow.test", "port": 80}))
    await handle_message(state, ws, json.dumps({"type": "tcp_close", "stream_id": "A"}))
    gate.set()
    await asyncio.sleep(0.05)
    assert opened == [] and state.active_streams == {} and state.pending_connections == {}


async def test_cancel_between_connect_and_registration_closes_the_writer(monkeypatch):
    writer = MagicMock(close=MagicMock(), wait_closed=AsyncMock(), get_extra_info=lambda *_: None)

    async def fake_open(*a, **k):
        return MagicMock(), writer

    monkeypatch.setattr(agent, "open_tcp_connection", fake_open)
    state, ws = AgentState(), _ws()
    async with state.get_lock():                              # registration will block on this lock
        await handle_message(state, ws, json.dumps({"type": "tcp_connect", "stream_id": "A", "host": "8.8.8.8", "port": 80}))
        for _ in range(50):                                   # let the task connect and reach the lock
            await asyncio.sleep(0.01)
            if writer.get_extra_info is not None and state.pending_connections.get("A") and not state.pending_connections["A"].done():
                break
        task = state.pending_connections["A"]
        task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    writer.close.assert_called()
    assert state.active_streams == {} and state.pending_connections == {}
```

(`get_lock()` is held by the test in the last case, so `close_stream`/cleanup inside the cancelled task must not need the held lock before closing the writer: close the writer first, then touch the tables.)

- [ ] **Step 1:** Write the tests; run `cd netbridge-agent && uv run pytest tests/test_agent_dns.py -q`; expected FAIL (`ImportError: DnsError`).
- [ ] **Step 2:** Implement. `resolve_destination`/`DnsError`/`DNS_TIMEOUT` as in Interfaces (literal path: strip brackets, `ipaddress.ip_address`, normalise). `validate_destination(..., resolved=None)`: `resolved_ips = list(resolved)` when given, else `try: resolved_ips = await resolve_destination(...) except DnsError: resolved_ips = []`; keep every range/CIDR rule. `open_tcp_connection(..., addresses=None)`: in the non-proxy branch loop `for ip in addresses` with `deadline = time.monotonic() + timeout`, `asyncio.wait_for(asyncio.open_connection(str(ip), port), remaining)`, remember the last exception, raise it; with no `addresses` keep `asyncio.open_connection(host, port)` (legacy and callers that do not resolve); with `proxy` unchanged (name goes to the proxy). In `handle_tcp_connect`: after the intercept branch, build `do_connect` so that **resolution, validation and connect are inside it**: `addresses = await resolve_destination(host, port)` for non-intercepted hosts, `validate_destination(host, port, ..., resolved=addresses)`, denial -> the existing `not allowed` result, `DnsError`/`OSError` -> the generic failure result (`error: str(e)`), then `open_tcp_connection(host, port, timeout=30.0, proxy_auth=..., addresses=addresses)`. Track `writer`/`forward_task`; wrap in `try/except asyncio.CancelledError`: close `writer` (and `await` `wait_closed` briefly) and cancel `forward_task` unless registration into `active_streams` completed, then re-raise; `finally` pops `pending_connections` as today (only if the entry is this task). `close_stream`: also `task = state.pending_connections.pop(stream_id, None)` under the lock and `task.cancel()`; await it with the short timeout, ignoring `CancelledError`/`TimeoutError`, before the existing active-stream logic (which still returns when there is no active stream).
- [ ] **Step 3:** `cd netbridge-agent && uv run pytest -q`; expected green (existing `validate_destination` tests keep passing through the `resolved=None` path).
- [ ] **Step 4: Commit** "Resolve once with a bound in the agent and cancel pending connects on close".

---

### Task 4: Agent registration parse, remote_exec 400, AppKey

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/agent.py` (registration parse ~727-745), `netbridge-agent/src/netbridge_agent/remote_exec.py` (`handle_exec` 183, `handle_exec_stream` 236, keys 323/402/425), `netbridge-agent/src/netbridge_agent/app.py` (keys at 449, 466, 734), `netbridge-agent/pyproject.toml` (filterwarnings error)
- Test: `netbridge-agent/tests/test_agent_malformed.py` (registration cases), `netbridge-agent/tests/test_remote_exec.py` (400 cases; update key usage at lines 16, 255, 294)

**Interfaces:**
- Produces in `remote_exec.py`: `REMOTE_EXEC_ENABLED = web.AppKey("remote_exec_enabled", bool)`, `PLUGIN_RELOAD_CALLBACK = web.AppKey("plugin_reload_callback", Callable)`; all `app["_remote_exec_enabled"]` / `app["_plugin_reload_callback"]` uses switch to them (`app.py` and tests import them).

```python
# append to netbridge-agent/tests/test_agent_malformed.py
import aiohttp
from netbridge_agent.agent import connect_and_run


def _fake_session(first_frame):
    ws = MagicMock(closed=False)
    ws.receive = AsyncMock(return_value=MagicMock(type=aiohttp.WSMsgType.TEXT, data=first_frame))
    ws.close = AsyncMock()
    ws.send_str = AsyncMock()
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=ws)
    session.__aexit__ = AsyncMock()
    client = MagicMock()
    client.ws_connect = MagicMock(return_value=session)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock()
    return client


@pytest.mark.parametrize("frame", ["{not json", "[1]", "null", "42", '"x"'])
async def test_malformed_registration_ends_the_session_cleanly(frame, caplog):
    on_status = MagicMock()
    with patch("netbridge_agent.agent.aiohttp.ClientSession", return_value=_fake_session(frame)), \
         patch("netbridge_agent.agent.create_tunnel_connector"), \
         patch("netbridge_agent.agent.build_auth_headers", return_value={}):
        result = await connect_and_run(AgentState(), "ws://relay/ws", None, None, "tok", asyncio.Event(), on_status, None)
    assert result == (False, 0.0)
    on_status.assert_not_called()                           # not connected, and not an auth failure
    assert "registration" in caplog.text.lower()
```

```python
# remote_exec 400 cases
@pytest.mark.parametrize("path", ["/exec", "/exec/stream"])
@pytest.mark.parametrize("body", ["[1]", '"x"', "null", "42"])
async def test_exec_rejects_non_object_body(client, path, body, caplog):
    resp = await client.post(path, data=body, headers={"Content-Type": "application/json"})
    assert resp.status == 400
    assert await resp.json() == {"error": "JSON object required"}
    assert "Traceback" not in caplog.text
```

- [ ] **Step 1:** Write the tests; run `cd netbridge-agent && uv run pytest tests/test_agent_malformed.py tests/test_remote_exec.py -q`; expected FAIL.
- [ ] **Step 2:** Implement: registration — wrap the parse in `try: data = json.loads(msg.data) except ValueError: data = None`; `if not isinstance(data, dict): logger.warning("Malformed registration frame from relay"); return False, 0.0` (same clean result as the existing "Unexpected first message" branch); in both exec handlers after `body = await request.json()` add `if not isinstance(body, dict): return web.json_response({"error": "JSON object required"}, status=400)`. AppKeys as in Interfaces; add `filterwarnings = ["error::aiohttp.web_exceptions.NotAppKeyWarning"]` to the agent pytest config.
- [ ] **Step 3:** `cd netbridge-agent && uv run pytest -q`; expected green.
- [ ] **Step 4: Commit** "Guard agent registration and exec bodies, use AppKey".

---

### Task 5: App shutdown event, `_signal_exit`, and headless `app.py` tests

**Files:**
- Modify: `netbridge-agent/src/netbridge_agent/app.py` (`_async_main` 722-770, `request_exit` 533, `request_restart` 210-232, `request_install` 311-345)
- Create: `netbridge-agent/tests/test_app.py`

**Interfaces:**
- Produces: `NetBridgeApp._shutdown_event: Optional[asyncio.Event]` (created once in `_async_main`), `NetBridgeApp._signal_exit() -> None` (thread-safe: sets `_pending_exit`; `call_soon_threadsafe` sets `_shutdown_event` and the current `_stop_event` when the loop exists). `_async_main` sets the shutdown event itself when `_pending_exit` is already set right after start-up and again before waiting.

Test fixture and the key cases (add the remaining cases listed after the code):

```python
# netbridge-agent/tests/test_app.py
import asyncio
import subprocess
import sys
import threading
from unittest.mock import AsyncMock, MagicMock

import pytest

from netbridge_agent import app as app_mod
from netbridge_agent.app import NetBridgeApp
from netbridge_agent.tray import Status


@pytest.fixture
def nb(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    import logging
    before = list(logging.getLogger().handlers)
    a = NetBridgeApp(console=True)
    yield a
    for h in list(logging.getLogger().handlers):
        if h not in before:
            logging.getLogger().removeHandler(h)
            h.close()


@pytest.fixture
def fake_agent(monkeypatch):
    """run_agent that records its stop event and blocks until it is set."""
    seen = {}

    async def run_agent(relay_url, stop_event, **kw):
        seen["stop"] = stop_event
        seen["started"].set()
        await stop_event.wait()

    seen["started"] = asyncio.Event()
    monkeypatch.setattr("netbridge_agent.agent.run_agent", run_agent)
    return seen


async def _boot(nb, fake_agent, monkeypatch):
    monkeypatch.setattr(nb, "_check_for_update", AsyncMock())
    nb.config.auto_connect = True
    main = asyncio.create_task(nb._async_main())
    await asyncio.wait_for(fake_agent["started"].wait(), 2)
    assert nb._stop_event is fake_agent["stop"]              # the replaced, per-connection event
    return main


async def test_exit_after_agent_start_ends_async_main(nb, fake_agent, monkeypatch):
    main = await _boot(nb, fake_agent, monkeypatch)
    nb.request_exit()
    await asyncio.wait_for(main, 2)
    assert fake_agent["stop"].is_set()


async def test_restart_ends_async_main(nb, fake_agent, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("netbridge_agent.installer.get_exe_path", lambda: "C:/x/netbridge.exe", raising=False)
    monkeypatch.setattr(subprocess, "Popen", MagicMock())
    monkeypatch.setattr(subprocess, "DETACHED_PROCESS", 8, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    main = await _boot(nb, fake_agent, monkeypatch)
    nb.request_restart()
    await asyncio.wait_for(main, 2)


async def test_install_ends_async_main(nb, fake_agent, monkeypatch):
    monkeypatch.setattr("netbridge_agent.installer.Installer.install_fresh", MagicMock(return_value=False))
    main = await _boot(nb, fake_agent, monkeypatch)
    nb.request_install()                                     # non-win32: no prompt, install_fresh patched
    await asyncio.wait_for(main, 2)


async def test_exit_before_the_event_exists_is_not_lost(nb, fake_agent, monkeypatch):
    nb.request_exit()                                        # _async_loop is None: only _pending_exit is set
    monkeypatch.setattr(nb, "_check_for_update", AsyncMock())
    await asyncio.wait_for(nb._async_main(), 2)              # returns instead of waiting forever


async def test_exit_requested_from_another_thread_mid_startup(nb, fake_agent, monkeypatch):
    from netbridge_agent.intercept import InterceptServer
    real_start = InterceptServer.start

    async def start_then_exit(self):
        await real_start(self)
        threading.Thread(target=nb.request_exit).start()     # exit arrives during start-up
        await asyncio.sleep(0.05)

    monkeypatch.setattr(InterceptServer, "start", start_then_exit)
    monkeypatch.setattr(nb, "_check_for_update", AsyncMock())
    await asyncio.wait_for(nb._async_main(), 2)


async def test_disconnect_does_not_stop_the_app(nb, fake_agent, monkeypatch):
    main = await _boot(nb, fake_agent, monkeypatch)
    nb.request_disconnect()
    await asyncio.wait_for(fake_agent["stop"].wait(), 2)
    await asyncio.sleep(0.05)
    assert not main.done()
    nb.request_exit()
    await asyncio.wait_for(main, 2)
```

Remaining `test_app.py` cases (each a short test with the same fixtures): `set_status` notifications via a `MagicMock` tray (CONNECTED -> `show_notification("Connected", ...)`; DISCONNECTED from CONNECTED -> "Disconnected"; AUTH_REQUIRED -> "Login Required"; no notification with `notify=False` or unchanged status); `_on_agent_status` mapping table; `_check_pending_requests` (connect creates one task, second call while running does not; disconnect sets only the per-connection stop event); `_run_agent` exception is logged and status ends DISCONNECTED, status sequence CONNECTING -> DISCONNECTED; `_on_proxy_auth_rejected` notification text; keep-alive start/stop/toggle with `session_keepalive_loop` patched; remote-exec toggle flags and `_remote_exec_auto_disable` with `REMOTE_EXEC_TIMEOUT` patched; `_reload_plugins_locked` with `discover_plugins`/`load_plugin_app` patched and a fake intercept server (`register_app`/`unregister_app` AsyncMocks): added, reloaded, removed, a failing load does not unregister others, duplicate hostname shadowing logs a warning, concurrent `_reload_plugins` calls serialise through the lock; `_async_main` order (intercept server started and exec app registered before the agent task exists, shutdown cancels the agent task and stops the server); `request_login` non-Windows (`subprocess.Popen` patched; failure notifies the tray); `request_restart` is a no-op off Windows; `_run_tray` returns 1 when `TRAY_AVAILABLE` is False.

- [ ] **Step 1:** Write the tests. Run `cd netbridge-agent && uv run pytest tests/test_app.py -q`; expected: the exit/restart/install/early-exit cases FAIL (hang caught by `wait_for` timeouts), the rest PASS or fail on missing patch targets (fix the tests, not the product, for those).
- [ ] **Step 2:** Implement `_signal_exit`:

```python
    def _signal_exit(self) -> None:
        """End the app from any thread: app-shutdown event plus the live connection's stop event."""
        self._pending_exit.set()
        loop = self._async_loop
        if loop is None:
            return
        for event in (self._shutdown_event, self._stop_event):
            if event is not None:
                loop.call_soon_threadsafe(event.set)
```

Add `self._shutdown_event = None` in `__init__`. In `_async_main`: set `self._async_loop = asyncio.get_running_loop()` is NOT needed in tests (the run loops set it): create `self._shutdown_event = asyncio.Event()` at the top, and also set `self._async_loop = asyncio.get_running_loop()` when it is None; after the plugin/agent start-up and again just before `await`, `if self._pending_exit.is_set(): self._shutdown_event.set()`; replace `await self._stop_event.wait()` with `await self._shutdown_event.wait()` (keep `self._stop_event` creation for `_check_pending_requests` before the first `_run_agent`). `request_exit`, `request_restart` (after the new process launched) and `request_install` (before `Installer.install_fresh`) call `_signal_exit()` instead of setting only `_stop_event`; tray stop and the rest stay.
- [ ] **Step 3:** `cd netbridge-agent && uv run pytest tests/test_app.py -q` then the whole suite; expected green.
- [ ] **Step 4: Commit** "Fix the agent shutdown race and test the headless app logic".

---

### Task 6: credstore, keepalive, auth re-export, Service-not-available tests

**Files:** Create `netbridge-agent/tests/test_credstore.py`, `netbridge-agent/tests/test_keepalive.py`, `netbridge-agent/tests/test_auth_reexports.py`; Modify `netbridge-agent/tests/test_agent.py` (service-not-available). No product changes.

```python
# test_auth_reexports.py
import shared_auth
from netbridge_agent import auth


def test_every_name_is_the_shared_auth_object_and_unique():
    assert len(auth.__all__) == len(set(auth.__all__))
    for name in auth.__all__:
        assert getattr(auth, name) is getattr(shared_auth, name), name
```

```python
# test_credstore.py (non-Windows branch is real; password is PLAINTEXT there, the test pins it)
import json
import sys

import pytest

from netbridge_agent import credstore


@pytest.fixture(autouse=True)
def tmp_app(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows plaintext branch")
def test_round_trip_and_plaintext_storage():
    assert credstore.load_proxy_credentials() is None and not credstore.has_proxy_credentials()
    credstore.save_proxy_credentials("alice", "s3cret")
    assert credstore.load_proxy_credentials() == ("alice", "s3cret")
    assert credstore.has_proxy_credentials()
    assert json.loads(credstore.get_creds_path().read_text())["password"] == "s3cret"
    credstore.clear_proxy_credentials()
    assert credstore.load_proxy_credentials() is None
    credstore.clear_proxy_credentials()                      # idempotent


@pytest.mark.parametrize("content", ["{not json", "[]", '{"username": "a"}', '{"password": "p"}'])
def test_corrupt_or_partial_files_return_none(content):
    p = credstore.get_creds_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    assert credstore.load_proxy_credentials() is None


def test_windows_fork_uses_dpapi(monkeypatch):
    monkeypatch.setattr(credstore.sys, "platform", "win32")
    monkeypatch.setattr(credstore, "_dpapi_encrypt", lambda s: b"ENC" + s.encode(), raising=False)
    monkeypatch.setattr(credstore, "_dpapi_decrypt", lambda b: b[3:].decode(), raising=False)
    credstore.save_proxy_credentials("bob", "pw")
    data = json.loads(credstore.get_creds_path().read_text())
    assert "password" not in data and "password_b64" in data
    assert credstore.load_proxy_credentials() == ("bob", "pw")
```

(Adjust `test_corrupt...` expectations to the module's real behaviour on first run: read `credstore.py:119-148` and pin what it does; the cases must not raise.)

```python
# test_keepalive.py
import asyncio
from unittest.mock import MagicMock

import pytest

from netbridge_agent import keepalive


def test_noops_off_windows(monkeypatch):
    monkeypatch.setattr(keepalive.sys, "platform", "linux")
    keepalive._set_execution_state(True)
    assert keepalive._jiggle_mouse() is False


def _fake_windll(monkeypatch, sent=2):
    windll = MagicMock()
    windll.user32.SendInput.return_value = sent
    monkeypatch.setattr(keepalive.sys, "platform", "win32")
    monkeypatch.setattr(keepalive.ctypes, "windll", windll, raising=False)
    return windll


def test_execution_state_flags_and_send_input(monkeypatch):
    windll = _fake_windll(monkeypatch)
    keepalive._set_execution_state(True)
    windll.kernel32.SetThreadExecutionState.assert_called_with(
        keepalive.ES_CONTINUOUS | keepalive.ES_SYSTEM_REQUIRED | keepalive.ES_DISPLAY_REQUIRED)
    keepalive._set_execution_state(False)
    windll.kernel32.SetThreadExecutionState.assert_called_with(keepalive.ES_CONTINUOUS)
    assert keepalive._jiggle_mouse() is True
    assert windll.user32.SendInput.call_args.args[0] == 2
    windll.user32.SendInput.return_value = 1
    assert keepalive._jiggle_mouse() is False


async def test_loop_jiggles_warns_and_clears_state(monkeypatch, caplog):
    windll = _fake_windll(monkeypatch)
    monkeypatch.setattr(keepalive, "KEEPALIVE_INTERVAL", 0.01)
    stop = asyncio.Event()
    task = asyncio.create_task(keepalive.session_keepalive_loop(stop))
    await asyncio.sleep(0.05)
    windll.user32.SendInput.return_value = 0
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, 1)
    assert windll.user32.SendInput.called and "SendInput failed" in caplog.text
    assert windll.kernel32.SetThreadExecutionState.call_args.args[0] == keepalive.ES_CONTINUOUS


async def test_loop_clears_state_when_cancelled(monkeypatch):
    windll = _fake_windll(monkeypatch)
    task = asyncio.create_task(keepalive.session_keepalive_loop(asyncio.Event()))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert windll.kernel32.SetThreadExecutionState.call_args.args[0] == keepalive.ES_CONTINUOUS
```

Service-not-available (`test_agent.py`): `AgentState()` with `get_intercept_server = lambda: MagicMock(port_for=lambda h: None)`; `handle_message` a `tcp_connect` for `netbridge-exec`:80; the `ws.send_str` payload is `success: false`, `error == "Service netbridge-exec is not available"`. Add siblings for `get_intercept_server=None` (`Intercept server is not configured`) and a getter returning None (`Intercept server is not running`).

- [ ] **Step 1:** Write the tests. **Step 2:** `cd netbridge-agent && uv run pytest tests/test_credstore.py tests/test_keepalive.py tests/test_auth_reexports.py tests/test_agent.py -q`; fix test expectations that mis-assume current behaviour (these are characterization tests: product code is not changed in this task). **Step 3:** whole suite green. **Step 4: Commit** "Add agent unit tests for credstore, keepalive, auth re-exports and magic hosts".

---

### Task 7: Proxy receiver hardening and reply-mapping pins

**Files:**
- Modify: `socks-proxy/src/socks_proxy/tunnel.py` (`_receive_loop` 860-885; `_handle_message` 886-925; `connect` result handling 733-760)
- Create: `socks-proxy/tests/test_tunnel_malformed.py`
- Modify: `socks-proxy/tests/test_socks5.py`, `socks-proxy/tests/test_http_proxy.py` (mapping pins)

**Interfaces:** Produces `tunnel.MAX_STREAM_ID_LENGTH = 128`, `tunnel._valid_stream_id(v) -> bool`. `_handle_message` closes bad `tcp_data` streams through `TunnelManager.close_stream(stream_id)` (removes from `self.streams`, releases the semaphore, sends `tcp_close` to the relay). `connect()` normalises a `success:false` result: `error = result.get("error"); if not isinstance(error, str): error = "Unknown error"`; a `success` that is not a bool raises `ConnectionError("Invalid connect result")`.

```python
# socks-proxy/tests/test_tunnel_malformed.py
import asyncio
import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import WSMsgType

from socks_proxy.stream import StreamHandler
from socks_proxy.tunnel import TunnelManager, TunnelConnectError


def _tm():
    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        tm = TunnelManager("relay.com")
    tm._connected.set()
    tm.ws = MagicMock(closed=False)
    tm.ws.send_str = AsyncMock()
    return tm


def _msgs(frames):
    class WS:
        closed = False
        send_str = AsyncMock()

        def __aiter__(self):
            async def gen():
                for f in frames:
                    yield MagicMock(type=WSMsgType.TEXT, data=f)
            return gen()

    return WS()


def _register(tm, sid="s1"):
    fut = asyncio.get_running_loop().create_future()
    h = StreamHandler(stream_id=sid, connect_future=fut)
    tm.streams[sid] = h
    return h, fut


async def test_receive_loop_survives_bad_syntax_then_processes_valid():
    tm = _tm()
    h, fut = _register(tm)
    good = json.dumps({"type": "tcp_connect_result", "stream_id": "s1", "success": True})
    tm.ws = _msgs(["{not json", "[1]", "null", good])
    await tm._receive_loop()
    assert fut.done() and fut.result()["success"] is True


@pytest.mark.parametrize("sid", [None, [1], "", "x" * 129, 5])
async def test_bad_stream_id_is_dropped(sid):
    tm = _tm()
    await tm._handle_message({"type": "tcp_data", "stream_id": sid, "data": "AA=="})   # no raise
    assert tm.streams == {}


@pytest.mark.parametrize("data", [None, 5, [1], "!!not-base64!!"])
async def test_bad_tcp_data_closes_the_stream_and_notifies_the_relay(data):
    tm = _tm()
    _register(tm)
    await tm._handle_message({"type": "tcp_data", "stream_id": "s1", "data": data})
    assert "s1" not in tm.streams                                                # removed
    sent = [json.loads(c.args[0]) for c in tm.ws.send_str.await_args_list]
    assert {"type": "tcp_close", "stream_id": "s1", "reason": "client_closed"} in sent


@pytest.mark.parametrize("result", [
    {"success": False}, {"success": False, "error": None}, {"success": False, "error": 5}])
async def test_failed_result_without_str_error_is_normalised_to_pinned_failure(result):
    tm = _tm()
    task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=2))
    for _ in range(100):
        if tm.streams:
            break
        await asyncio.sleep(0.01)
    (sid,) = tm.streams
    await tm._handle_message({"type": "tcp_connect_result", "stream_id": sid, **result})
    with pytest.raises(TunnelConnectError, match="Unknown error"):
        await task


async def test_non_bool_success_fails_the_connect():
    tm = _tm()
    task = asyncio.create_task(tm.connect("10.0.0.1", 80, timeout=2))
    for _ in range(100):
        if tm.streams:
            break
        await asyncio.sleep(0.01)
    (sid,) = tm.streams
    await tm._handle_message({"type": "tcp_connect_result", "stream_id": sid, "success": "yes"})
    with pytest.raises(ConnectionError, match="Invalid connect result"):
        await task
```

Mapping pins: `test_socks5.py` — fake tunnel whose `connect` raises `TunnelConnectError("x")` -> reply byte 0x04; `asyncio.TimeoutError` -> 0x06; `RuntimeError` -> 0x01 (read the reply with the existing `_send_reply` capture pattern in that file). `test_http_proxy.py` — for CONNECT and absolute-URI forward: `TunnelConnectError` -> `HTTP/1.1 502`, `asyncio.TimeoutError` -> `504`.

- [ ] **Step 1:** Write tests; run `cd socks-proxy && uv run pytest tests/test_tunnel_malformed.py tests/test_socks5.py tests/test_http_proxy.py -q`; expected FAIL on the new malformed tests (mapping pins already PASS).
- [ ] **Step 2:** Implement: `_receive_loop` wraps `_json_loads(msg.data)` in `try/except ValueError: logger.warning("Invalid JSON from relay"); continue` and skips non-dict results; `_handle_message` returns early unless `_valid_stream_id(stream_id)`; `tcp_data`: `data` must be `str` and `base64.b64decode(data, validate=True)` must succeed, otherwise `logger.warning(...)`, `await self.close_stream(stream_id)`, return; `tcp_connect_result`: `success` bool else `handler.connect_future.set_exception(ConnectionError("Invalid connect result"))`; in `connect()` normalise `error` before `classify_connect_error` and `TunnelConnectError`.
- [ ] **Step 3:** `cd socks-proxy && uv run pytest -q`; green. **Step 4: Commit** "Harden the proxy tunnel against malformed relay frames".

---

### Task 8: e2e driver pieces (refused port, helpers, plugin fixtures)

**Files:**
- Modify: `e2e/src/netbridge_e2e/targets.py`, `e2e/src/netbridge_e2e/stack.py` (`_Component.add_plugins`), `e2e/src/netbridge_e2e/journey.py` (helpers only)
- Create: `e2e/src/netbridge_e2e/plugin_fixtures/probe/manifest.json`, `.../probe/plugin.py`, `.../broken/manifest.json`; `e2e/tests/test_journey_errors.py` (helper tests; the steps arrive in Tasks 9-10)
- Test: `e2e/tests/test_targets.py`, `e2e/tests/test_stack.py`

**Interfaces:**
- Produces: `Targets.refused_port: int` (bound, never `listen()`ed socket held until `close()`); `stack._Component.add_plugins(nonce: str) -> list[Path]` (copies `plugin_fixtures/probe` and `plugin_fixtures/broken` into `self.plugins_dir`, replacing the literal `__NONCE__` in the probe's `plugin.py`; returns the created dirs; `SourceAgent.plugins_dir = app_dir / "plugins"`, `ExeComponent.plugins_dir = install_dir / "plugins"`; `cleanup()` removes the created dirs in source mode); `Journey._fail_case(front_end, dest_host, dest_port, budget) -> tuple[str | int, float]` with `front_end in {"socks5", "http_connect", "http_forward"}`, returning the reply code (SOCKS) or status (HTTP), `"ok"` or `"hang"`, and elapsed seconds; `Journey._wait_streams_zero(relay, within, stable=2) -> tuple[bool, str]`.

Fixture files:

```json
// plugin_fixtures/probe/manifest.json
{"name": "e2e-probe", "hostname": "netbridge-e2e-probe", "description": "e2e probe", "version": "0.0.1", "entry_point": "plugin.py"}
// plugin_fixtures/broken/manifest.json  (missing entry_point)
{"name": "e2e-broken", "hostname": "netbridge-e2e-broken", "description": "broken", "version": "0.0.1"}
```

```python
# plugin_fixtures/probe/plugin.py
from aiohttp import web

NONCE = "__NONCE__"


async def index(request):
    return web.Response(text=f"netbridge-e2e-plugin {NONCE}")


def create_app():
    app = web.Application()
    app.router.add_get("/", index)
    return app
```

Tests (real code):

```python
# e2e/tests/test_targets.py additions
def test_refused_port_refuses_and_is_held_until_close():
    with Targets("127.0.0.1") as t:
        s = socket.socket()
        s.settimeout(5)
        with pytest.raises(ConnectionRefusedError):
            s.connect(("127.0.0.1", t.refused_port))
        s.close()
        probe = socket.socket()
        with pytest.raises(OSError):                       # still bound: nobody else can take it
            probe.bind(("127.0.0.1", t.refused_port))
        probe.close()
    again = socket.socket()
    again.bind(("127.0.0.1", t.refused_port))              # released after close()
    again.close()
```

```python
# e2e/tests/test_stack.py additions
def test_add_plugins_copies_fixtures_and_substitutes_nonce(tmp_path):
    from netbridge_e2e.stack import SourceAgent
    agent = SourceAgent(tmp_path, "ws://x", {})
    agent.install()
    dirs = agent.add_plugins("abc123")
    probe = agent.plugins_dir / "probe"
    assert "abc123" in (probe / "plugin.py").read_text() and "__NONCE__" not in (probe / "plugin.py").read_text()
    assert (agent.plugins_dir / "broken" / "manifest.json").exists()
    agent.cleanup()
    assert not any(d.exists() for d in dirs)


def test_probe_plugin_loads_with_the_agents_real_loader_and_broken_is_skipped(tmp_path):
    pytest.importorskip("netbridge_agent")
    from netbridge_agent.plugin_loader import discover_plugins, load_plugin_app
    # copy via the component method, then load with the product loader
    ...
```

(For the second test use `SourceAgent.add_plugins` into `tmp_path/plugins`, then `[m.hostname for m in discover_plugins(plugins_dir)] == ["netbridge-e2e-probe"]` and `load_plugin_app(manifest)` returns an app whose `/` answers the nonce via `aiohttp.test_utils`; skip when `netbridge_agent` is not importable. Fill in with those exact assertions, no ellipsis.)

`test_journey_errors.py` (helpers against `e2e/tests/fakeproxy.py`, the scripted fake used by `test_journey_faults.py`): `_fail_case("socks5", ...)` returns `(4, secs)` for a fake that answers reply 0x04, `("ok", _)` when it connects, `("hang", _)` for a fake that never replies within a tiny budget; `http_connect`/`http_forward` return `502`; `_wait_streams_zero` returns ok when `relay.status()` yields `active_streams` 3 then 0 then 0, fails with the last value when it stays 2 (use the `FakeTime` clock from `test_journey_faults.py`).

- [ ] **Step 1:** Write the tests; run `cd e2e && uv run pytest tests/test_targets.py tests/test_stack.py tests/test_journey_errors.py -q`; expected FAIL.
- [ ] **Step 2:** Implement. `Targets.__init__`: `self._refused = socket.socket(); self._refused.bind((host, 0)); self.refused_port = self._refused.getsockname()[1]` (never `listen`); close it in `close()`. `add_plugins`: `shutil.copytree(FIXTURES / name, self.plugins_dir / name)`; nonce substituted with `str.replace`. `_fail_case`: run the failure in a thread (like `_attempt`, `journey.py:496`) using `clients.socks5_connect` / `clients.http_connect` / `clients.http_forward_get(self.http, f"http://{host}:{port}/")` and map `ProxyError.code` / status; `_wait_streams_zero`: poll `relay.status().get("active_streams")` every 0.5 s, require `stable` consecutive zeros before `within`, else `(False, f"active_streams stuck at {last}")`.
- [ ] **Step 3:** whole e2e suite green (`cd e2e && uv run pytest -q`). **Step 4: Commit** "Add the refused-port target, plugin fixtures and failure-case helpers to the driver".

---

### Task 9: Error-path journey steps

**Files:** Modify `e2e/src/netbridge_e2e/journey.py` (`_filter`, new `_errors`, call order in `_journey` after `_filter`); Test `e2e/tests/test_journey_errors.py`.

**Interfaces:** Consumes Task 8. Produces steps (all via `self.check`): `relay_filter` (updated), then in order `refused_socks5`, `refused_http_connect`, `refused_http_forward`, `dns_failure_socks5`, `dns_failure_http_connect`, `dns_failure_http_forward`, `agent_denies_socks5`, `agent_denies_http_connect`, `agent_denies_http_forward`, `blocked_port_http_connect`, `blocked_port_http_forward`, `errors_leave_tunnel_healthy`. Constants: `NXDOMAIN = "netbridge-e2e-nxdomain.invalid"`, `LINK_LOCAL = "169.254.169.254"`.

Step implementation pattern (one generic runner keeps it compact; every case takes marks BEFORE the action):

```python
    def _error_case(self, relay, agent, front_end: str, host: str, port: int, expect: int,
                    budget: float, agent_log: str | None, relay_log: str | None,
                    not_relay_log: str | None = None):
        def run():
            rmark, amark = relay.logs.mark(), agent.logs.mark()           # before the action
            got, secs = self._fail_case(front_end, host, port, budget)
            ok = got == expect
            detail = (f"{front_end} -> {got!r} after {secs:.1f}s "
                      f"(0x04/502: the product maps all connect failures to it)")
            if ok and agent_log:
                hit = agent.logs.wait_for(agent_log, 5, since=amark)
                ok, detail = hit is not None, detail + f"; agent log {agent_log!r}: {hit is not None}"
            if ok and relay_log:
                hit = relay.logs.wait_for(relay_log, 5, since=rmark)
                ok, detail = hit is not None, detail + f"; relay log {relay_log!r}: {hit is not None}"
            if ok and not_relay_log:
                seen = relay.logs.wait_for(not_relay_log, 1, since=rmark)
                ok, detail = seen is None, detail + f"; relay logged {not_relay_log!r}: {seen is not None}"
            return ok, detail
        return run
```

Matrix table in `_errors` (refused log `Failed:`; DNS log `Failed:`; agent denial `Destination denied` and `not_relay_log=r"Blocked port"`; port block relay log `rf"Blocked port {targets.blocked_port}\b"`); expected 4 for socks5, 502 for HTTP; budgets 10/20/10/10. `relay_filter` updated: marks on both logs, `wait_for(..., since=mark)`, requires `e.code == 0x04` exactly. `errors_leave_tunnel_healthy`: `_socks_get(ip, targets)` returns 200/PAGE, then `_wait_streams_zero(relay, within=5)`. Before the group: `self.check("errors_baseline_clean", lambda: self._wait_streams_zero(relay, within=10))` (step name added; detail reports the value on timeout).

Unit tests in `test_journey_errors.py`: for each matrix row, a scripted fake (reply 0x04 / 502 plus the matching log line in a fake `LogWatch`) passes; a fake answering 0x05 (SOCKS) or 503 fails with the code in the detail; a fake that connects (`ok`) fails; a fake that hangs fails with `hang`; log evidence older than the mark does NOT satisfy a later step (pre-seed the fake log with `Blocked port` before the mark; `agent_denies_*` must not fail from it and `blocked_port_*` must not pass from it); `relay_filter` fails when the reply is 0x01.

- [ ] **Step 1:** Write the tests; `cd e2e && uv run pytest tests/test_journey_errors.py -q`; expected FAIL.
- [ ] **Step 2:** Implement `_errors` (called from `_journey` right after `self._filter(...)`) and the `relay_filter` change.
- [ ] **Step 3:** `cd e2e && uv run pytest -q` green; then run the source journey (command in Global Constraints) and confirm every new step PASSes with times printed (refused/denied < 10 s, DNS < 20 s); `errors_leave_tunnel_healthy` passing proves Task 1's stream release end to end. **Step 4: Commit** "Pin connect-failure replies on all front ends in the journey".

---

### Task 10: Plugin journey steps

**Files:** Modify `e2e/src/netbridge_e2e/journey.py` (`_journey` install/start order, new `_plugins`), `e2e/src/netbridge_e2e/clients.py` (none expected); Test `e2e/tests/test_journey_errors.py` (plugin step tests) or a new `e2e/tests/test_journey_plugins.py`.

**Interfaces:** Consumes `add_plugins` (Task 8). Steps: `plugins_installed` (after `install_agent`, before `agent.start()`: `agent.add_plugins(nonce)` with `nonce = secrets.token_hex(8)`; detail lists the dirs; registered for cleanup via the component's cleanup), then after `az_called`: `plugin_loaded_log`, `plugin_routable`, `plugins_listed`. They run before `_traffic`/`_errors`.

- `plugin_loaded_log`: `agent.logs.wait_for(r"Plugin loaded: netbridge-e2e-probe", 10, since=start_marks["agent"])` and `wait_for(r"Skipping plugin broken", 5, since=start_marks["agent"])` (the log dir name is `broken`; the manifest error text follows).
- `plugin_routable`: for front ends SOCKS5 domain, HTTP CONNECT, HTTP forward: GET `/` for `netbridge-e2e-probe:80`, expect status 200 and body `netbridge-e2e-plugin <nonce>` (SOCKS5: `clients.socks5_connect(self.socks, "netbridge-e2e-probe", 80)` + `clients.http_get(s, "netbridge-e2e-probe")`; CONNECT: `clients.http_connect(self.http, "netbridge-e2e-probe", 80)`; forward: `clients.http_forward_get(self.http, "http://netbridge-e2e-probe/")`).
- `plugins_listed`: SOCKS5 domain `netbridge-exec:80`, `GET /plugins`, JSON `plugins` names contain `e2e-probe` and not `e2e-broken`.

Unit tests (fake clients and `LogWatch`): all three steps pass against scripted fakes; the nonce in the body must match this run's nonce (a body with an old nonce fails); a missing `Plugin loaded` line fails and attaches the agent log tail; `/plugins` containing `e2e-broken` fails.

- [ ] **Step 1:** Write the tests; expected FAIL. **Step 2:** Implement (nonce stored on the journey, the fixtures copied before `start`). **Step 3:** `cd e2e && uv run pytest -q`; run the source journey; all plugin steps PASS. (Windows exe mode is exercised by `e2e-windows.yml`; if the frozen import fails the step detail carries the agent log tail: fix forward in that workflow run, do not skip the step.) **Step 4: Commit** "Prove plugins load and route in the e2e stack".

---

### Task 11: Ratchet coverage floors

**Files:** Modify `netbridge-agent/pyproject.toml`, `relay/pyproject.toml`, `socks-proxy/pyproject.toml`, `e2e/pyproject.toml` (`fail_under`).

- [ ] **Step 1:** Measure: `scripts/coverage.sh` (runs each component with floors, the combined report and diff-cover); expected green, with the hint column of `scripts/coverage_report.py` printing `raise fail_under to N` for each component whose floor can rise.
- [ ] **Step 2:** For each of agent, relay, socks-proxy, e2e set `fail_under = floor(measured)` as printed (spec estimates: agent 46, relay 80, socks-proxy 52, e2e 78; measured numbers win). Never lower a floor; leave shared and socks-proxy-win unchanged.
- [ ] **Step 3:** Re-run `scripts/coverage.sh`; expected green with no raise hints left for the four components.
- [ ] **Step 4: Commit** "Raise coverage floors after the error-path work".

---

## Self-Review notes (executed while writing)

- Spec coverage: F4/F6c -> Tasks 1, 2, 4, 7; F6a -> Task 1 + journey (9); F6b -> Task 3; F6e -> Tasks 2/3; F6f -> Task 3; F6d -> Task 5; F5 -> Tasks 1, 4; section 1 matrix -> Tasks 8-9; section 2 plugins -> Tasks 8, 10; section 5 gap-fill -> Tasks 5, 6; section 6 relay/proxy tests -> Tasks 1, 7; floors -> Task 11. Not implemented by design (spec non-goals): structured error codes, 6to4/Teredo, Windows unit job, legacy single-resolution.
- Names used across tasks: `valid_stream_id`/`valid_connect_fields`/`_normalize_ip` (Task 2) are used by Tasks 3 and legacy; `resolve_destination`/`DnsError`/`DNS_TIMEOUT`/`resolved=`/`addresses=` (Task 3); `_signal_exit`/`_shutdown_event` (Task 5); `refused_port`/`add_plugins`/`_fail_case`/`_wait_streams_zero` (Task 8) used by Tasks 9-10; AppKeys `REMOTE_EXEC_ENABLED`/`PLUGIN_RELOAD_CALLBACK` (Task 4) used by Task 5's `app.py` edits (Task 5 must import them if it touches those lines, which it does not beyond what Task 4 changed).
