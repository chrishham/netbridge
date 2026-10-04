# Relay auth-first limits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A valid token is never refused because of other traffic from the same IP. The per-IP bucket counts failed authentication only. Forced JWKS refreshes are throttled per tenant. An opt-in setting recovers the real client IP behind trusted proxies.

**Architecture:**
- The relay authenticates first. Only failures touch the per-IP limiter, via one helper shared by `/ws` and `/tunnel`.
- `shared_auth.validate` gates the unknown-kid refetch behind a per-tenant cooldown.
- `_client_ip()` reads a configurable header only when `request.remote` is inside `RELAY_TRUSTED_PROXIES`.

**Tech Stack:** Python 3.14, aiohttp, aiolimiter, pytest/pytest-asyncio, uv. Tests run with `uv run pytest` inside each component directory.

**Spec:** `docs/superpowers/specs/2026-10-04-relay-auth-first-limits-design.md`. Read it first; it is the source of truth.

## Global Constraints

- Environment variable names:
  - `RELAY_RATE_IP_CONNECTIONS_PER_MIN` keeps its name and its default of `30`.
  - The new variables are `RELAY_TRUSTED_PROXIES` (default empty) and `RELAY_CLIENT_IP_HEADER` (default `X-Forwarded-For`).
- Throttled-failure response: HTTP 429 with body `Too many failed attempts from this IP`.
- Unchanged texts:
  - the 401 bodies (the validator's messages)
  - the `Agent auth rejected for {ip}: {reason}` and `Tunnel auth rejected for {ip}: {reason}` warnings
  - the per-user `Too many connection attempts` 429
- Throttled-failure log: `Per-IP auth-failure limit exceeded for {ip}`.
- JWKS cooldown: `JWKS_FORCED_REFRESH_COOLDOWN = 60` seconds per tenant. Record the timestamp before awaiting the fetch.
- Topology independence:
  - no hard-coded proxy vendor, header or CIDR
  - default behaviour (no trusted proxies) uses `request.remote`, exactly as today
- Coverage floors stay green: shared 91, relay 82, e2e 79 (`scripts/coverage.sh`).
- Commits are plain human-style messages with no attribution lines.
- `docs/` is gitignored, so stage files under it with `git add -f <file>`.

## Review Focus

These are input classes the spec implies and the base design could miss. Each has a test in the owning task.

1. **`X-Forwarded-For` entries with a port.** Azure Application Gateway sends `1.2.3.4:5678`, and some proxies send `[2001:db8::1]:443`. Expect the port stripped and the IP used. Owner: Task 2.
2. **An IPv6 remote inside a trusted IPv6 CIDR**, e.g. `::1` with trusted `::1/128`. Expect the header honoured. Owner: Task 2.
3. **A whitespace-only or empty header value** with a trusted remote. Expect a fallback to `request.remote`, not a crash and not `""`. Owner: Task 2.
4. **Concurrent unknown-kid requests within the cooldown.** Expect exactly one fetch, even though all requests started before the first fetch returned. Owner: Task 1.
5. **A valid-token upgrade while the IP bucket is empty, on `/tunnel` as well as `/ws`.** Expect 101, with the per-user limit still applying afterwards. Owner: Task 3.

---

### Task 1: Cooldown on forced JWKS refresh (`shared`)

**Files:**
- Modify: `shared/src/shared_auth/validate.py`: near `_jwks_cache` (around line 100), and the unknown-kid branch in `validate_arm_token` (around lines 225-233)
- Test: `shared/tests/test_validate_signatures.py`. Extend the `reset_caches` fixture at line 104, and the two inline `_jwks_cache` resets near lines 333 and 400.

**Interfaces:**
- Produces:
  - `JWKS_FORCED_REFRESH_COOLDOWN: int = 60`
  - `_jwks_forced_refresh: dict[str, float]`, keyed by tenant id; the value is `time.monotonic()` of the last forced refresh
  - the error message for an unknown kid stays `Signing key not found: {kid}`

- [ ] **Step 1: Reset the new state in the test fixtures**

In `reset_caches` add:

```python
    monkeypatch.setattr(mod, "_jwks_forced_refresh", {})
```

Next to the other two `monkeypatch.setattr(mod, "_jwks_cache", {})` lines (near lines 333 and 400), add the same line with the same `mod` variable those tests use.

- [ ] **Step 2: Write the failing tests**

Append to `shared/tests/test_validate_signatures.py`:

```python
@pytest.mark.asyncio
async def test_second_unknown_kid_within_cooldown_does_not_refetch(reset_caches):
    """A forced JWKS refresh happens at most once per tenant per cooldown."""
    private_key, _ = _generate_rsa_keypair()
    claims = _make_valid_claims()
    first = _sign_jwt(private_key, {"alg": "RS256", "typ": "JWT", "kid": "ghost-1"}, claims)
    second = _sign_jwt(private_key, {"alg": "RS256", "typ": "JWT", "kid": "ghost-2"}, claims)
    fetches = []

    async def fake_get_jwks(tenant_id):
        fetches.append(tenant_id)
        return {"keys": []}

    with patch("shared_auth.validate._get_jwks", side_effect=fake_get_jwks):
        with pytest.raises(TokenValidationError, match="Signing key not found: ghost-1"):
            await validate_arm_token(first)
        assert len(fetches) == 2  # cached read + one forced refresh
        with pytest.raises(TokenValidationError, match="Signing key not found: ghost-2"):
            await validate_arm_token(second)
    assert len(fetches) == 3  # cached read only: no second forced refresh


@pytest.mark.asyncio
async def test_forced_refresh_allowed_again_after_cooldown(reset_caches, monkeypatch):
    import shared_auth.validate as mod
    private_key, _ = _generate_rsa_keypair()
    token = _sign_jwt(private_key, {"alg": "RS256", "typ": "JWT", "kid": "ghost"}, _make_valid_claims())
    clock = [1000.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    fetches = []

    async def fake_get_jwks(tenant_id):
        fetches.append(tenant_id)
        return {"keys": []}

    with patch("shared_auth.validate._get_jwks", side_effect=fake_get_jwks):
        with pytest.raises(TokenValidationError):
            await validate_arm_token(token)
        clock[0] += mod.JWKS_FORCED_REFRESH_COOLDOWN + 1
        with pytest.raises(TokenValidationError):
            await validate_arm_token(token)
    assert len(fetches) == 4  # two cached reads + two forced refreshes


@pytest.mark.asyncio
async def test_concurrent_unknown_kids_force_one_refresh(reset_caches):
    """Requests racing inside the window share one forced refresh (timestamp set before the await)."""
    import asyncio
    private_key, _ = _generate_rsa_keypair()
    tokens = [_sign_jwt(private_key, {"alg": "RS256", "typ": "JWT", "kid": f"ghost-{i}"}, _make_valid_claims())
              for i in range(5)]
    calls = []
    gate = asyncio.Event()

    async def fake_get_jwks(tenant_id):
        calls.append(tenant_id)
        if len(calls) == 2:  # the first request's forced refresh: hold it open while the others run
            await gate.wait()
        return {"keys": []}

    async def attempt(tok):
        with pytest.raises(TokenValidationError, match="Signing key not found"):
            await validate_arm_token(tok)

    with patch("shared_auth.validate._get_jwks", side_effect=fake_get_jwks):
        tasks = [asyncio.create_task(attempt(t)) for t in tokens]
        await asyncio.sleep(0.05)  # the other four finish while the forced refresh is pending
        gate.set()
        await asyncio.gather(*tasks)
    assert len(calls) == 6  # five cached reads + exactly one forced refresh
```

- [ ] **Step 3: Run the tests and verify they fail**

Run: `cd shared && uv run pytest tests/test_validate_signatures.py -k "cooldown or concurrent_unknown" -v`
Expected: FAIL, with `AttributeError: ... _jwks_forced_refresh`, or a wrong fetch count.

- [ ] **Step 4: Implement**

In `validate.py`, below `JWKS_CACHE_TTL = 3600`:

```python
# An unknown kid forces a refetch at most this often per tenant: a stream of
# forged kids must not turn the relay into a request amplifier toward Microsoft.
JWKS_FORCED_REFRESH_COOLDOWN = 60  # seconds
_jwks_forced_refresh: dict[str, float] = {}
```

Replace the unknown-kid branch:

```python
        if not signing_key:
            # Key not found - maybe a key rollover; refresh, but not more than once per cooldown
            now = time.monotonic()
            last = _jwks_forced_refresh.get(tid)
            if last is None or now - last >= JWKS_FORCED_REFRESH_COOLDOWN:
                _jwks_forced_refresh[tid] = now  # before the await: concurrent requests skip
                _jwks_cache.pop(tid, None)
                jwks = await _get_jwks(tid)
                for key in jwks.get("keys", []):
                    if key.get("kid") == kid:
                        signing_key = key
                        break
```

Drop the now-unneeded `global _jwks_cache` line in this branch. `pop` mutates the dict and does not rebind it.

- [ ] **Step 5: Run all shared tests**

Run: `cd shared && uv run pytest -q`
Expected: all pass. That includes the existing `test_unknown_kid_refetches_once`, a rollover with exactly one refetch, now covered by the fixture reset.

- [ ] **Step 6: Commit**

```bash
git add shared/src/shared_auth/validate.py shared/tests/test_validate_signatures.py
git commit -m "Throttle forced JWKS refreshes to one per tenant per minute"
```

---

### Task 2: `_client_ip()` with opt-in trusted proxies (`relay`)

**Files:**
- Modify: `relay/src/relay/__main__.py`:
  - config constants: next to `RATE_LIMIT_IP_PER_MIN`, around line 154
  - the helpers: near `_get_ip_limiter`, around line 343
  - `main()`: the startup parse and log
- Create: `relay/tests/test_client_ip.py`

**Interfaces:**
- Produces:
  - `_parse_trusted_proxies(raw: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]`; raises `ValueError` on any invalid entry
  - module globals `_TRUSTED_PROXIES: tuple = ()` and `CLIENT_IP_HEADER: str`
  - `_client_ip(request: web.Request) -> str`

- [ ] **Step 1: Write the failing tests**

Create `relay/tests/test_client_ip.py`:

```python
"""Client IP resolution behind optional trusted proxies."""

import pytest
from unittest.mock import MagicMock

import relay.__main__ as mod


def _req(remote, headers=None):
    r = MagicMock()
    r.remote = remote
    r.headers = headers or {}
    return r


@pytest.fixture
def trusted(monkeypatch):
    def set_(cidrs, header="X-Forwarded-For"):
        monkeypatch.setattr(mod, "_TRUSTED_PROXIES", mod._parse_trusted_proxies(cidrs))
        monkeypatch.setattr(mod, "CLIENT_IP_HEADER", header)
    return set_


def test_default_uses_remote_even_with_header(monkeypatch):
    monkeypatch.setattr(mod, "_TRUSTED_PROXIES", ())
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": "1.1.1.1"})) == "10.0.0.5"


def test_missing_remote_is_unknown(monkeypatch):
    monkeypatch.setattr(mod, "_TRUSTED_PROXIES", ())
    assert mod._client_ip(_req(None)) == "unknown"


def test_untrusted_remote_ignores_header(trusted):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("203.0.113.9", {"X-Forwarded-For": "1.1.1.1"})) == "203.0.113.9"


def test_xff_rightmost_untrusted_wins(trusted):
    trusted("10.0.0.0/8")
    req = _req("10.0.0.5", {"X-Forwarded-For": "6.6.6.6, 1.1.1.1, 10.0.0.7"})
    assert mod._client_ip(req) == "1.1.1.1"


def test_xff_all_trusted_falls_back_to_remote(trusted):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": "10.1.1.1, 10.2.2.2"})) == "10.0.0.5"


def test_xff_garbage_entry_is_skipped(trusted):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": "1.1.1.1, not-an-ip"})) == "1.1.1.1"


@pytest.mark.parametrize("entry, want", [
    ("1.2.3.4:5678", "1.2.3.4"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("2001:db8::1", "2001:db8::1"),
])
def test_xff_entries_with_ports(trusted, entry, want):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": entry})) == want


@pytest.mark.parametrize("value", ["", "   ", " , "])
def test_blank_header_falls_back_to_remote(trusted, value):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": value})) == "10.0.0.5"


def test_ipv6_trusted_remote(trusted):
    trusted("::1/128")
    assert mod._client_ip(_req("::1", {"X-Forwarded-For": "2001:db8::7"})) == "2001:db8::7"


def test_single_value_header(trusted):
    trusted("10.0.0.0/8", header="CF-Connecting-IP")
    assert mod._client_ip(_req("10.0.0.5", {"CF-Connecting-IP": " 1.1.1.1 "})) == "1.1.1.1"


def test_single_value_header_invalid_falls_back(trusted):
    trusted("10.0.0.0/8", header="CF-Connecting-IP")
    assert mod._client_ip(_req("10.0.0.5", {"CF-Connecting-IP": "1.1.1.1, 2.2.2.2"})) == "10.0.0.5"


def test_xff_header_name_case_insensitive(trusted):
    trusted("10.0.0.0/8", header="x-forwarded-for")
    req = _req("10.0.0.5", {"x-forwarded-for": "1.1.1.1, 10.0.0.7"})
    assert mod._client_ip(req) == "1.1.1.1"


def test_parse_trusted_proxies():
    nets = mod._parse_trusted_proxies(" 10.0.0.0/8, 192.168.1.1 ,::1/128,")
    assert [str(n) for n in nets] == ["10.0.0.0/8", "192.168.1.1/32", "::1/128"]
    assert mod._parse_trusted_proxies("") == ()


@pytest.mark.parametrize("raw", ["10.0.0.0/33", "nope", "10.0.0.0/8,bad"])
def test_parse_trusted_proxies_rejects_invalid(raw):
    with pytest.raises(ValueError):
        mod._parse_trusted_proxies(raw)
```

aiohttp `request.headers` is a case-insensitive `CIMultiDictProxy`. The tests use a plain dict, so `test_xff_header_name_case_insensitive` passes the header under the same casing as configured. The behaviour under test is that `X-Forwarded-For` parsing is selected case-insensitively by name.

- [ ] **Step 2: Run the tests and verify they fail**

Run: `cd relay && uv run pytest tests/test_client_ip.py -q`
Expected: FAIL with `AttributeError: module 'relay.__main__' has no attribute '_parse_trusted_proxies'`.

- [ ] **Step 3: Implement**

Next to `RATE_LIMIT_IP_PER_MIN`:

```python
# Client IP behind reverse proxies (opt-in). Only enable when the proxy chain
# cannot be bypassed: a client reaching the relay directly could forge the header.
CLIENT_IP_HEADER = os.environ.get("RELAY_CLIENT_IP_HEADER", "").strip() or "X-Forwarded-For"
_TRUSTED_PROXIES: tuple = ()  # parsed from RELAY_TRUSTED_PROXIES in main()
```

Near `_get_ip_limiter`:

```python
def _parse_trusted_proxies(raw: str) -> tuple:
    """Comma-separated CIDRs (bare IPs allowed); ValueError on an invalid entry."""
    return tuple(ipaddress.ip_network(part.strip(), strict=False) for part in raw.split(",") if part.strip())


def _parse_ip(value: str):
    """An IP from a forwarded-header entry, tolerating a port (1.2.3.4:80, [v6]:80); None if unusable."""
    value = value.strip()
    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]
    elif value.count(":") == 1:
        value = value.split(":", 1)[0]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_trusted(ip) -> bool:
    return any(ip in net for net in _TRUSTED_PROXIES)


def _client_ip(request: web.Request) -> str:
    """The peer address, or the client address from CLIENT_IP_HEADER when the peer is a trusted proxy."""
    remote = request.remote or "unknown"
    if not _TRUSTED_PROXIES:
        return remote
    peer = _parse_ip(remote)
    if peer is None or not _is_trusted(peer):
        return remote
    value = request.headers.get(CLIENT_IP_HEADER, "")
    if CLIENT_IP_HEADER.lower() == "x-forwarded-for":
        for entry in reversed(value.split(",")):
            ip = _parse_ip(entry)
            if ip is not None and not _is_trusted(ip):
                return str(ip)
        return remote
    ip = _parse_ip(value)
    return str(ip) if ip is not None else remote
```

In `main()`, after the auth block and before `logger.info("Routing: ...")`:

```python
    global _TRUSTED_PROXIES
    try:
        _TRUSTED_PROXIES = _parse_trusted_proxies(os.environ.get("RELAY_TRUSTED_PROXIES", ""))
    except ValueError as e:
        logger.error(f"Configuration error: RELAY_TRUSTED_PROXIES: {e}")
        sys.exit(1)
    if _TRUSTED_PROXIES:
        logger.info(f"Client IP: {CLIENT_IP_HEADER} from {len(_TRUSTED_PROXIES)} trusted proxy range(s)")
```

Move `global _TRUSTED_PROXIES` to the top of `main()`, next to `global REQUIRE_AUTH`, as a single `global REQUIRE_AUTH, _TRUSTED_PROXIES` line. Python requires a global declaration to come before any use of the name in the function.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cd relay && uv run pytest tests/test_client_ip.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add relay/src/relay/__main__.py relay/tests/test_client_ip.py
git commit -m "Resolve the client IP from a header only behind trusted proxies"
```

---

### Task 3: Authenticate first; the IP bucket counts failures (`relay`)

**Files:**
- Modify: `relay/src/relay/__main__.py`:
  - `handle_websocket` (around line 593)
  - `handle_tunnel` (around line 947)
  - the comment above `RATE_LIMIT_IP_PER_MIN`
  - the comment on `# Per-IP rate limiting (applied before authentication)`
- Modify: `relay/tests/test_relay_limits.py`; replace `test_per_ip_limit_rejects_third_request`
- Modify: `README.md`, line 161
- Modify: `security-tests/pentest_suite.py` (around line 440), comment only

**Interfaces:**
- Consumes: `_client_ip(request) -> str` (Task 2), and `_get_ip_limiter(ip) -> _TimedLimiter` (existing).
- Produces: `async def _authenticate_upgrade(request: web.Request, kind: str) -> tuple[str | None, web.Response | None]`. It returns `(user_email, None)` on success, or `(None, response)` to return to the client. `kind` is `"Agent"` or `"Tunnel"`.

- [ ] **Step 1: Write the failing tests**

In `relay/tests/test_relay_limits.py`, replace `test_per_ip_limit_rejects_third_request` with:

```python
async def _auth_by_header(request):
    """Valid iff the bearer token is 'good'."""
    if request.headers.get("Authorization") == "Bearer good":
        return True, USER
    return False, "Invalid JWT format"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/ws", "/tunnel"])
async def test_failed_auth_exhausts_ip_bucket_but_valid_token_passes(client, monkeypatch, path):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 2)
    bad = {"Authorization": "Bearer bad"}
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        for _ in range(2):
            resp = await client.get(path, headers=bad)
            assert resp.status == 401
            assert "Invalid JWT format" in await resp.text()
        resp = await client.get(path, headers=bad)
        assert resp.status == 429
        assert "Too many failed attempts from this IP" in await resp.text()

        ws = await client.ws_connect(path, headers={"Authorization": "Bearer good"})
        try:
            if path == "/ws":
                assert (await ws.receive_json())["type"] == "registered"
            else:
                assert not ws.closed
        finally:
            await ws.close()


@pytest.mark.asyncio
async def test_valid_tokens_never_consume_ip_bucket(client, monkeypatch):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 2)
    monkeypatch.setattr(mod, "RATE_LIMIT_CONNECTIONS_PER_MIN", 100)
    good = {"Authorization": "Bearer good"}
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        sockets = [await client.ws_connect("/tunnel", headers=good) for _ in range(3)]
        try:
            assert all(not ws.closed for ws in sockets)
            resp = await client.get("/tunnel", headers={"Authorization": "Bearer bad"})
            assert resp.status == 401  # bucket untouched by the three valid upgrades
        finally:
            for ws in sockets:
                await ws.close()


@pytest.mark.asyncio
async def test_per_user_limit_still_applies_when_ip_bucket_empty(client, monkeypatch):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 1)
    monkeypatch.setattr(mod, "RATE_LIMIT_CONNECTIONS_PER_MIN", 1)
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        assert (await client.get("/tunnel", headers={"Authorization": "Bearer bad"})).status == 401
        assert (await client.get("/tunnel", headers={"Authorization": "Bearer bad"})).status == 429
        ws = await client.ws_connect("/tunnel", headers={"Authorization": "Bearer good"})
        try:
            resp = await client.get("/tunnel", headers={"Authorization": "Bearer good"})
            assert resp.status == 429
            assert "Too many connection attempts" in await resp.text()
        finally:
            await ws.close()


@pytest.mark.asyncio
async def test_failed_auth_logs_keep_their_text(client, monkeypatch, caplog):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 1)
    bad = {"Authorization": "Bearer bad"}
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        await client.get("/ws", headers=bad)
        await client.get("/ws", headers=bad)
    text = caplog.text
    assert "Agent auth rejected for 127.0.0.1: Invalid JWT format" in text
    assert "Per-IP auth-failure limit exceeded for 127.0.0.1" in text
```

If `caplog` does not capture the relay logger, check how other relay tests assert log lines (`grep -rn caplog relay/tests`) and follow that. The relay logs through `logging.getLogger(__name__)` with JSON formatting.

- [ ] **Step 2: Run the tests and verify they fail**

Run: `cd relay && uv run pytest tests/test_relay_limits.py -q`
Expected: FAIL. The valid upgrade after failures gets 429, and the 429 text differs.

- [ ] **Step 3: Implement the helper and use it in both handlers**

Above `handle_websocket`:

```python
async def _authenticate_upgrade(request: web.Request, kind: str) -> tuple[str | None, web.Response | None]:
    """Authenticate first; only failures are charged to the per-IP bucket.

    Behind a reverse proxy or NAT many users share one address, so a pre-auth
    per-IP limit would let unauthenticated traffic lock out valid users.
    """
    client_ip = _client_ip(request)
    success, result = await authenticate_request(request)
    if success:
        return result, None
    ip_entry = _get_ip_limiter(client_ip)
    if not ip_entry.limiter.has_capacity():
        logger.warning(f"Per-IP auth-failure limit exceeded for {client_ip}")
        return None, web.Response(status=429, text="Too many failed attempts from this IP")
    await ip_entry.limiter.acquire()
    logger.warning(f"{kind} auth rejected for {client_ip}: {result}")
    return None, web.Response(status=401, text=result)
```

In `handle_websocket`, replace everything from `# Per-IP rate limit` through `user_email = result` with:

```python
    user_email, rejection = await _authenticate_upgrade(request, "Agent")
    if rejection is not None:
        return rejection
```

In `handle_tunnel`, make the same replacement with `"Tunnel"`. If `client_ip` is used later in either handler (`grep -n client_ip relay/src/relay/__main__.py`), replace those uses with `_client_ip(request)`, or keep a local `client_ip = _client_ip(request)`.

Update the comments:
- Above the constant: `# Per-IP limit on failed authentication attempts (valid tokens never count against it)`
- Above `_TimedLimiter`/`_ip_limiters`: `# Per-IP limiting of failed authentication attempts`

- [ ] **Step 4: Update the docs**

In the `README.md` row:

```
| `RELAY_RATE_IP_CONNECTIONS_PER_MIN` | Max failed authentication attempts per client IP per minute (valid tokens never count) | `30` |
```

Add two rows right after it:

```
| `RELAY_TRUSTED_PROXIES` | Comma-separated CIDRs of reverse proxies whose client-IP header is trusted. Only set when clients cannot bypass the proxy. | (empty: use the peer address) |
| `RELAY_CLIENT_IP_HEADER` | Header carrying the client IP from a trusted proxy; `X-Forwarded-For` is parsed right to left, any other header must hold one IP | `X-Forwarded-For` |
```

In `security-tests/pentest_suite.py`, change the comment near line 440 to:

```python
        # 35 rapid authenticated connections should hit the per-user limit (default 10/min)
```

- [ ] **Step 5: Run all relay tests and the security-tests unit tests**

Run: `cd relay && uv run pytest -q` and `cd security-tests && uv run pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add relay/src/relay/__main__.py relay/tests/test_relay_limits.py README.md security-tests/pentest_suite.py
git commit -m "Authenticate before the per-IP limit and charge it only for failures"
```

---

### Task 4: E2E step: an auth flood spares valid users (`e2e`)

**Files:**
- Modify: `e2e/src/netbridge_e2e/stack.py:35-36` (`FAULT_TUNING`)
- Modify: `e2e/src/netbridge_e2e/journey.py`:
  - add `_auth_flood`
  - call it in `_journey` between `self._pentest_step(...)` and `self._reconnect(...)` (around line 225)
- Modify: the e2e unit tests that pin `FAULT_TUNING` or the step list, if any (`grep -rn "FAULT_TUNING\|IP_CONNECTIONS\|pentest_suite" e2e/tests`)

**Interfaces:**
- Consumes:
  - `clients.ws_upgrade(host, port, path, token) -> (status, body)`
  - `self._tunnel_connect(relay, token, ip, targets) -> dict`
  - `stub.mint()` (valid token), and `self.check(name, fn)`
- Produces: the journey step `auth_flood_spares_valid_users` (source mode with auth only).

- [ ] **Step 1: Measure the failed attempts before the step**

Count the failed authentications that happen before `_reconnect`:
- 24 from `_auth_matrix` (12 failing cases × 2 paths)
- the failures from the pentest suite: count its requests made without a valid token, by reading `security-tests/pentest_suite.py` for each non-skipped test, or by grepping the relay log of a local journey run for `auth rejected`

Run the journey once locally if needed. The command is in `.github/workflows/ci.yml`, job `e2e-source`. Without sudo, omit `--target-hostname`:

```bash
uv run --project e2e python -m netbridge_e2e --mode source --work /tmp/e2e-flood
grep -c "auth rejected" /tmp/e2e-flood/logs/relay-*.log
```

Pick `IP_FAILURE_LIMIT`:
- `30` if the measured count is ≤ 20, leaving headroom for continuous refill timing
- otherwise the measured count + 15

Record the number and the reason in the commit message.

- [ ] **Step 2: Lower the tuning**

In `stack.py`, set `"RELAY_RATE_IP_CONNECTIONS_PER_MIN"` to the chosen value. Update the comment above `FAULT_TUNING`:

```python
# fault steps: detect a half-open link in ~15 s; the per-user limit is raised so fault-driven reconnects are
# never throttled. The per-IP limit only counts failed auth, so it stays near the production default.
```

- [ ] **Step 3: Add the step**

In `journey.py`, next to `_user_isolation`:

```python
    def _auth_flood(self, relay: Relay, stub: AuthStub, ip: str, targets: Targets) -> tuple[bool, str]:
        """Exhaust the per-IP failed-auth budget, then a valid user must still connect and tunnel."""
        cap = int(FAULT_TUNING["RELAY_RATE_IP_CONNECTIONS_PER_MIN"]) + 10
        throttled_at, last = None, None
        for attempt in range(1, cap + 1):
            last = clients.ws_upgrade("127.0.0.1", relay.port, "/tunnel", "not-a-jwt")
            if last[0] == 429:
                throttled_at = attempt
                break
        if throttled_at is None:
            return False, f"no 429 within {cap} bad-token upgrades; last {last}"
        reply = self._tunnel_connect(relay, stub.mint(), ip, targets)
        ok = reply.get("type") == "tcp_connect_result" and reply.get("success") is True
        return ok, f"429 after {throttled_at} bad-token upgrades; valid user then: {json.dumps(reply)}"
```

Import `FAULT_TUNING` from `.stack` if `journey.py` does not already. In `_journey`, after `self._pentest_step(relay, stub, env, logs)`:

```python
        self.check("auth_flood_spares_valid_users", lambda: self._auth_flood(relay, stub, ip, targets))
```

If the journey has a path where the relay runs without auth (for example `--relay-image` or exe mode with `--no-auth`), the step cannot apply: no failures are possible. Guard it the way `_pentest_step` guards exe mode, with `self.step(name, True, "skipped: relay runs without auth")`. Check `stack.py` for how auth mode is chosen. Only skip when auth really is off.

- [ ] **Step 4: Add a unit test for the step's decision logic**

Follow the style of the existing `e2e/tests/test_journey_auth.py`, which fakes `clients` and the relay. Cover three cases:
- 429 on attempt 3 followed by a successful tunnel connect: pass, and the detail contains `429 after 3`
- no 429 within the cap: fail
- a 429 followed by a failed connect: fail

- [ ] **Step 5: Run the e2e unit tests and the full journey**

Run: `cd e2e && uv run pytest -q`, then the journey command from Step 1. All steps must pass, including:
- `auth_flood_spares_valid_users`
- the `_reconnect` and fault steps after it. They reconnect with valid tokens while the IP bucket is empty, which is the end-to-end proof.

- [ ] **Step 6: Commit**

```bash
git add e2e/src/netbridge_e2e/stack.py e2e/src/netbridge_e2e/journey.py e2e/tests/
git commit -m "E2E: an unauthenticated flood must not lock out a valid user"
```

---

### Task 5: Whole-repo verification

- [ ] Run `scripts/coverage.sh`. Expect it green, with floors met and diff coverage reported.
- [ ] Run `cd security-tests && uv run pytest -q`. Expect it green.
- [ ] Check `git diff 10ce998..HEAD` for stray debug output, and confirm that no proxy vendor, header or CIDR is hard-coded outside the README examples and the spec.
- [ ] Note the per-component test counts for the report.
