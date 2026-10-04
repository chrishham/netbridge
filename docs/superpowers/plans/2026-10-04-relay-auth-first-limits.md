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
- JWKS fetching: one fetch in flight per tenant; `JWKS_FETCH_BACKOFF = 10` s after a failure (serve cached keys, even expired, if fetched less than `JWKS_MAX_STALE = 86400` s ago, else `Signing keys unavailable`); forced refresh at most once per `JWKS_FORCED_REFRESH_COOLDOWN = 60` s per tenant, timestamp recorded before the await, cache replaced only on success.
- Log bounding: `Per-IP auth-failure limit exceeded for {ip} ({n} more since last report)` at most once per IP per 60 s.
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
4. **A slow or hanging Microsoft fetch** while the cache is fresh. Expect validations served from cache not to wait for the in-flight fetch (fast path outside the lock). Owner: Task 1.
5. **A valid-token upgrade while the IP bucket is empty, on `/tunnel` as well as `/ws`.** Expect 101, with the per-user limit still applying afterwards. Owner: Task 3.

---

### Task 1: Bounded JWKS fetching (`shared`)

**Files:**
- Modify: `shared/src/shared_auth/validate.py`: `_jwks_cache` / `_get_jwks` (lines 100-123), and the unknown-kid branch in `validate_arm_token` (around lines 225-236)
- Create: `shared/tests/test_jwks_fetching.py`
- Modify: `shared/tests/test_validate_signatures.py`: the `reset_caches` fixture at line 104, the two inline `_jwks_cache` resets near lines 333 and 400, and the last assertion of `test_key_rotation_via_real_get_jwks` (line 261)

**Interfaces:**
- Produces:
  - `async def _get_jwks(tenant_id: str, force: bool = False) -> dict`
  - constants `JWKS_FORCED_REFRESH_COOLDOWN = 60`, `JWKS_FETCH_BACKOFF = 10` and `JWKS_MAX_STALE = 86400`
  - module state `_jwks_cache: dict[str, tuple[float, dict]]` (unchanged shape: `(time.time() at fetch, jwks)`), `_jwks_locks: dict[str, asyncio.Lock]`, `_jwks_failed_at: dict[str, float]`, `_jwks_forced_refresh: dict[str, float]` (both hold `time.monotonic()` values) and `_jwks_refreshes: set[asyncio.Task]`
  - helpers `_refresh_jwks(tenant_id, force=False) -> dict` (the locked fetch) and `_refresh_jwks_quietly(tenant_id) -> None` (background wrapper)
  - new error text: `Signing keys unavailable`
- Keeps:
  - `_get_jwks_url(tenant_id)` as the only URL source. The e2e relaysite hook patches it.
  - `Signing key not found: {kid}`

- [ ] **Step 1: Reset the new state in the existing fixtures**

In `shared/tests/test_validate_signatures.py`'s `reset_caches`, and next to the two inline `_jwks_cache` resets, add:

```python
    monkeypatch.setattr(mod, "_jwks_forced_refresh", {})
    monkeypatch.setattr(mod, "_jwks_failed_at", {})
    monkeypatch.setattr(mod, "_jwks_locks", {})
    monkeypatch.setattr(mod, "_jwks_refreshes", set())
```

Those existing tests patch `_get_jwks` with a one-argument fake. After this task, `validate_arm_token` calls `_get_jwks(tid, force=True)`, so update each such fake to accept `force=False` (`grep -n "def fake_get_jwks" shared/tests/*.py`). Fakes passed as `return_value=` need no change.

`test_key_rotation_via_real_get_jwks` (line 201) runs against the real `_get_jwks`. Its last check validates token A after the rollover to key B and expects a third fetch (`assert len(requests) == 3`). The forced refresh for kid B, a few lines earlier, started the cooldown, so after this task token A fails without fetching. Replace the tail of the test:

```python
            # Token A should now fail (key no longer served). The forced refresh for
            # kid B started the cooldown, so this unknown kid does not fetch again.
            with pytest.raises(TokenValidationError, match="Signing key not found"):
                await validate_arm_token(token_a)
            assert len(requests) == 2

            # After the cooldown an unknown kid may force one more refresh
            import shared_auth.validate as mod  # the module only imports it inside reset_caches
            mod._jwks_forced_refresh[VALID_TENANT] -= mod.JWKS_FORCED_REFRESH_COOLDOWN + 1
            with pytest.raises(TokenValidationError, match="Signing key not found"):
                await validate_arm_token(token_a)
            assert len(requests) == 3
```

Check the tenant constant the test's claims use (`_make_valid_claims` sets `tid`), and use that name in place of `VALID_TENANT` if it differs.

- [ ] **Step 2: Write the failing tests**

Create `shared/tests/test_jwks_fetching.py`. These tests exercise the real `_get_jwks`, faking HTTP by patching `httpx.AsyncClient.get`:

```python
"""JWKS fetching toward Microsoft is bounded: single flight, failure backoff, forced-refresh cooldown."""

import asyncio
import time
from unittest.mock import patch

import httpx
import pytest

import shared_auth.validate as mod
from shared_auth.validate import TokenValidationError, validate_arm_token
from tests.test_validate_signatures import (
    VALID_TENANT, _generate_rsa_keypair, _key_to_jwk, _make_valid_claims, _sign_jwt,
)


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setattr(mod, "_allowed_tenants_cache", None)
    monkeypatch.setattr(mod, "_allowed_users_cache", None)
    monkeypatch.setattr(mod, "_allowed_groups_cache", None)
    monkeypatch.setattr(mod, "_jwks_cache", {})
    monkeypatch.setattr(mod, "_jwks_forced_refresh", {})
    monkeypatch.setattr(mod, "_jwks_failed_at", {})
    monkeypatch.setattr(mod, "_jwks_locks", {})
    monkeypatch.setattr(mod, "_jwks_refreshes", set())
    monkeypatch.setenv("NETBRIDGE_ALLOWED_TENANTS", VALID_TENANT)


class FakeMicrosoft:
    """Stands in for httpx.AsyncClient.get; counts calls, can block, fail or change keys."""

    def __init__(self, keys):
        self.keys = keys
        self.calls = 0
        self.fail = False
        self.gate: asyncio.Event | None = None

    async def get(self, client, url, *args, **kwargs):
        self.calls += 1
        if self.gate is not None:
            await self.gate.wait()
        if self.fail:
            raise httpx.ConnectError("down")
        return httpx.Response(200, json={"keys": list(self.keys)}, request=httpx.Request("GET", url))


@pytest.fixture
def key():
    private, public = _generate_rsa_keypair()
    return private, _key_to_jwk(public, "k1")


def _token(private, kid="k1"):
    return _sign_jwt(private, {"alg": "RS256", "typ": "JWT", "kid": kid}, _make_valid_claims())


def _patched(ms):
    async def get(self, url, *args, **kwargs):
        return await ms.get(self, url, *args, **kwargs)
    return patch.object(httpx.AsyncClient, "get", get)


async def _drain_refreshes():
    """Let background refreshes started by expired-but-usable caches finish."""
    while mod._jwks_refreshes:
        await asyncio.gather(*list(mod._jwks_refreshes))


def _expire(seconds_past_fetch):
    fetched_at, jwks = mod._jwks_cache[VALID_TENANT]
    mod._jwks_cache[VALID_TENANT] = (fetched_at - seconds_past_fetch, jwks)


@pytest.mark.asyncio
async def test_concurrent_cache_misses_fetch_once(key):
    private, jwk = key
    ms = FakeMicrosoft([jwk])
    ms.gate = asyncio.Event()
    with _patched(ms):
        tasks = [asyncio.create_task(validate_arm_token(_token(private))) for _ in range(5)]
        await asyncio.sleep(0.05)
        ms.gate.set()
        users = await asyncio.gather(*tasks)
    assert ms.calls == 1
    assert len(set(users)) == 1


@pytest.mark.asyncio
async def test_cached_validations_do_not_wait_for_forced_refresh(key):
    private, jwk = key
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))
        ms.gate = asyncio.Event()  # the forced refresh below hangs
        forced = asyncio.create_task(validate_arm_token(_token(private, "ghost")))
        await asyncio.sleep(0.05)
        assert await asyncio.wait_for(validate_arm_token(_token(private)), 1)
        ms.gate.set()
        with pytest.raises(TokenValidationError):
            await forced


@pytest.mark.asyncio
async def test_unknown_kid_forced_refresh_is_rate_limited(key, monkeypatch):
    private, jwk = key
    clock = [1000.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))  # warm cache
        assert ms.calls == 1
        with pytest.raises(TokenValidationError, match="Signing key not found: ghost-1"):
            await validate_arm_token(_token(private, "ghost-1"))
        assert ms.calls == 2  # one forced refresh
        with pytest.raises(TokenValidationError, match="Signing key not found: ghost-2"):
            await validate_arm_token(_token(private, "ghost-2"))
        assert ms.calls == 2  # within cooldown: no fetch
        clock[0] += mod.JWKS_FORCED_REFRESH_COOLDOWN + 1
        with pytest.raises(TokenValidationError, match="Signing key not found: ghost-3"):
            await validate_arm_token(_token(private, "ghost-3"))
        assert ms.calls == 3


@pytest.mark.asyncio
async def test_concurrent_unknown_kids_force_one_fetch(key):
    private, jwk = key
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))  # warm cache: 1 call
        ms.gate = asyncio.Event()
        tasks = [asyncio.create_task(validate_arm_token(_token(private, f"ghost-{i}"))) for i in range(5)]
        await asyncio.sleep(0.05)
        ms.gate.set()
        results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(r, TokenValidationError) for r in results)
    assert ms.calls == 2


@pytest.mark.asyncio
async def test_rollover_kid_succeeds_via_forced_refresh(key):
    private, jwk = key
    new_private, new_public = _generate_rsa_keypair()
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))
        ms.keys = [jwk, _key_to_jwk(new_public, "k2")]
        assert await validate_arm_token(_token(new_private, "k2"))
    assert ms.calls == 2


@pytest.mark.asyncio
async def test_failed_forced_refresh_keeps_previous_keys(key):
    private, jwk = key
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))
        ms.fail = True
        with pytest.raises(TokenValidationError):
            await validate_arm_token(_token(private, "ghost"))
        assert await validate_arm_token(_token(private))  # old keys still cached


@pytest.mark.asyncio
async def test_failure_backoff_with_empty_cache(key, monkeypatch):
    private, jwk = key
    clock = [1000.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    ms = FakeMicrosoft([jwk])
    ms.fail = True
    with _patched(ms):
        with pytest.raises(TokenValidationError, match="Signing keys unavailable"):
            await validate_arm_token(_token(private))  # first failure: same text as during backoff
        calls = ms.calls
        with pytest.raises(TokenValidationError, match="Signing keys unavailable"):
            await validate_arm_token(_token(private))
        assert ms.calls == calls  # within backoff: no HTTP call
        clock[0] += mod.JWKS_FETCH_BACKOFF + 1
        ms.fail = False
        assert await validate_arm_token(_token(private))


@pytest.mark.asyncio
async def test_expired_cache_is_used_during_backoff(key):
    private, jwk = key
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))
        _expire(mod.JWKS_CACHE_TTL + 1)
        ms.fail = True
        assert await validate_arm_token(_token(private))  # expired keys used, refresh in background
        await _drain_refreshes()
        assert VALID_TENANT in mod._jwks_failed_at  # the background fetch failed
        calls = ms.calls
        assert await validate_arm_token(_token(private))
        await _drain_refreshes()
        assert ms.calls == calls  # backoff: no second attempt


@pytest.mark.asyncio
async def test_expired_usable_cache_does_not_wait_for_slow_fetch(key):
    private, jwk = key
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))
        _expire(mod.JWKS_CACHE_TTL + 1)
        ms.gate = asyncio.Event()  # Microsoft hangs
        users = await asyncio.wait_for(
            asyncio.gather(*(validate_arm_token(_token(private)) for _ in range(5))), timeout=1)
        assert len(users) == 5
        await asyncio.sleep(0.05)  # let the background refresh reach the hanging fetch
        assert ms.calls == 2  # the initial fetch plus one background refresh, still blocked
        ms.gate.set()
        await _drain_refreshes()
        assert ms.calls == 2
        assert mod._jwks_cache[VALID_TENANT][0] > time.time() - 5  # refreshed


@pytest.mark.asyncio
async def test_keys_older_than_max_stale_are_not_served(key):
    private, jwk = key
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))
        fetched_at, jwks = mod._jwks_cache[VALID_TENANT]
        mod._jwks_cache[VALID_TENANT] = (fetched_at - mod.JWKS_MAX_STALE - 1, jwks)
        ms.fail = True
        with pytest.raises(TokenValidationError, match="Signing keys unavailable"):
            await validate_arm_token(_token(private))  # fetch fails, keys too old to serve
        with pytest.raises(TokenValidationError, match="Signing keys unavailable"):
            await validate_arm_token(_token(private))  # within backoff
```

Check `tests/test_validate_signatures.py` for the exact helper names (`VALID_TENANT`, `_make_valid_claims` defaults), and adjust the import if `shared/tests` is not importable as `tests.` (see `shared/tests/conftest.py` / `__init__.py`). If not, copy the four helpers into the new file.

The existing `_get_jwks` retries once on `httpx.TransportError`, so one failed fetch makes two `get` calls. The assertions above compare call counts before and after rather than hard-coding failure counts.

- [ ] **Step 3: Run the tests and verify they fail**

Run: `cd shared && uv run pytest tests/test_jwks_fetching.py -q`
Expected: several FAIL, on call counts, `force` not accepted, or the missing `Signing keys unavailable`.

- [ ] **Step 4: Implement `_get_jwks`**

Replace lines 100-123 of `validate.py` with:

```python
# Cache for JWKS (public keys) - keyed by tenant ID
_jwks_cache: dict[str, tuple[float, dict]] = {}
JWKS_CACHE_TTL = 3600  # 1 hour

# Fetches toward Microsoft are bounded however many requests arrive: one fetch
# in flight per tenant, no refetch for a while after a failure, and an unknown
# kid forces a refresh at most once per cooldown.
JWKS_FETCH_BACKOFF = 10  # seconds
JWKS_FORCED_REFRESH_COOLDOWN = 60  # seconds
# During a Microsoft outage expired keys keep being served, but not forever:
# a key Microsoft revoked must stop working within a day.
JWKS_MAX_STALE = 86400  # seconds
_jwks_locks: dict[str, asyncio.Lock] = {}
_jwks_failed_at: dict[str, float] = {}
_jwks_forced_refresh: dict[str, float] = {}
_jwks_refreshes: set[asyncio.Task] = set()  # strong refs to background refreshes


async def _fetch_jwks(tenant_id: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        url = _get_jwks_url(tenant_id)
        try:
            resp = await client.get(url)
        except httpx.TransportError:
            # Single retry on transient failure (connection error, timeout)
            resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()


async def _get_jwks(tenant_id: str, force: bool = False) -> dict:
    """Microsoft's public keys for a tenant: cached, single-flight, backed off after failures.

    force=True bypasses the TTL (unknown kid) and only replaces the cache on success.
    """
    cached = _jwks_cache.get(tenant_id)
    if not force and cached is not None:
        age = time.time() - cached[0]
        if age < JWKS_CACHE_TTL:
            return cached[1]  # fast path: a fetch in flight must not stall validations served from cache
        if age < JWKS_MAX_STALE:
            # Expired but usable: refresh in the background so no validation waits on Microsoft
            if not _jwks_locks.setdefault(tenant_id, asyncio.Lock()).locked():
                task = asyncio.create_task(_refresh_jwks_quietly(tenant_id))
                _jwks_refreshes.add(task)
                task.add_done_callback(_jwks_refreshes.discard)
            return cached[1]
    return await _refresh_jwks(tenant_id, force)


async def _refresh_jwks_quietly(tenant_id: str) -> None:
    try:
        await _refresh_jwks(tenant_id)
    except Exception:
        pass  # recorded in _jwks_failed_at; callers keep the cached keys


async def _refresh_jwks(tenant_id: str, force: bool = False) -> dict:
    lock = _jwks_locks.setdefault(tenant_id, asyncio.Lock())
    async with lock:
        cached = _jwks_cache.get(tenant_id)
        fresh = cached is not None and (time.time() - cached[0]) < JWKS_CACHE_TTL
        if fresh and not force:
            return cached[1]
        usable = cached is not None and (time.time() - cached[0]) < JWKS_MAX_STALE
        failed_at = _jwks_failed_at.get(tenant_id)
        if failed_at is not None and time.monotonic() - failed_at < JWKS_FETCH_BACKOFF:
            if usable:
                return cached[1]
            raise TokenValidationError("Signing keys unavailable")
        try:
            jwks = await _fetch_jwks(tenant_id)
        except Exception as e:
            _jwks_failed_at[tenant_id] = time.monotonic()
            if usable:
                return cached[1]  # keep serving the previous keys
            raise TokenValidationError("Signing keys unavailable") from e
        _jwks_failed_at.pop(tenant_id, None)
        _jwks_cache[tenant_id] = (time.time(), jwks)
        return jwks
```

Add `import asyncio` to the imports. Keep `global` statements out: the dicts are mutated, not rebound.

Two consequences of the code above:

- When a fetch fails and the cached keys are less than `JWKS_MAX_STALE` old, `_get_jwks` returns them instead of raising. That is intended: an outage at Microsoft must not lock out users whose keys are cached. Past a day, a revoked key must not keep working, so validation fails until a fetch succeeds.
- Every fetch failure without usable keys raises `Signing keys unavailable`, on the first failure as well as during the backoff, so clients see one message for one condition. The underlying error is chained (`from e`) for the logs.
- Once the TTL has passed but the keys are younger than `JWKS_MAX_STALE`, callers get the cached keys immediately and one background task refreshes them (stale-while-revalidate). A slow or failing Microsoft endpoint never delays a validation that has usable keys. Several tasks may be created before the first takes the lock; the re-check under the lock makes the later ones return without fetching.
- `_refresh_jwks_quietly` swallows the exception, so a failing background task does not log "Task exception was never retrieved"; the failure is recorded in `_jwks_failed_at`.

- [ ] **Step 5: Implement the unknown-kid branch**

Replace the unknown-kid branch in `validate_arm_token`:

```python
        if not signing_key:
            # Maybe a key rollover: force a refresh, at most once per tenant per cooldown
            now = time.monotonic()
            last = _jwks_forced_refresh.get(tid)
            if last is None or now - last >= JWKS_FORCED_REFRESH_COOLDOWN:
                _jwks_forced_refresh[tid] = now  # before the await: concurrent requests skip
                jwks = await _get_jwks(tid, force=True)
                for key in jwks.get("keys", []):
                    if key.get("kid") == kid:
                        signing_key = key
                        break
```

This removes the old `global _jwks_cache` and the `_jwks_cache.pop(tid, None)`.

- [ ] **Step 6: Run all shared tests**

Run: `cd shared && uv run pytest -q`
Expected: all pass, including the existing `test_unknown_kid_refetches_once` and `test_unknown_kid_still_not_found_after_refetch`.

- [ ] **Step 7: Commit**

```bash
git add shared/src/shared_auth/validate.py shared/tests/test_jwks_fetching.py shared/tests/test_validate_signatures.py
git commit -m "Bound JWKS fetches: single flight, failure backoff, forced-refresh cooldown"
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
    assert "Per-IP auth-failure limit exceeded for 127.0.0.1 (0 more since last report)" in text


@pytest.mark.asyncio
async def test_throttle_warning_is_logged_once_per_window(client, monkeypatch, caplog):
    monkeypatch.setattr(mod, "RATE_LIMIT_IP_PER_MIN", 1)
    clock = [1000.0]
    monkeypatch.setattr(mod, "_now", lambda: clock[0])  # report clock only; aiolimiter keeps the real one
    bad = {"Authorization": "Bearer bad"}
    with patch("relay.__main__.authenticate_request", side_effect=_auth_by_header):
        for _ in range(6):  # 1 x 401, then 5 x 429
            await client.get("/ws", headers=bad)
        assert caplog.text.count("Per-IP auth-failure limit exceeded") == 1
        clock[0] += mod.IP_THROTTLE_REPORT_INTERVAL + 1
        await client.get("/ws", headers=bad)
    assert "(4 more since last report)" in caplog.text
```

The test patches `mod._now`, not `mod.time.monotonic`. Patching `time.monotonic` would change the whole `time` module, including the event-loop clock aiolimiter refills from, so the bucket would refill when the fake clock jumps and the test would see a 401 instead of a 429.

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
        now = _now()
        if now - ip_entry.last_report >= IP_THROTTLE_REPORT_INTERVAL:
            logger.warning(f"Per-IP auth-failure limit exceeded for {client_ip} "
                           f"({ip_entry.suppressed} more since last report)")
            ip_entry.last_report, ip_entry.suppressed = now, 0
        else:
            ip_entry.suppressed += 1
        return None, web.Response(status=429, text="Too many failed attempts from this IP")
    await ip_entry.limiter.acquire()
    logger.warning(f"{kind} auth rejected for {client_ip}: {result}")
    return None, web.Response(status=401, text=result)
```

Extend `_TimedLimiter` (it already exists, shared by all limiters) and add the interval constant next to it:

```python
IP_THROTTLE_REPORT_INTERVAL = 60  # seconds between "limit exceeded" log lines per IP
_now = time.monotonic  # report clock, patched by tests without touching aiolimiter's clock


@dataclass
class _TimedLimiter:
    """Rate limiter with last-used timestamp for cleanup."""
    limiter: AsyncLimiter
    last_used: float = field(default_factory=time.monotonic)
    last_report: float = float("-inf")  # last "limit exceeded" log line (per-IP limiters only)
    suppressed: int = 0                  # throttled requests not logged since then
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

Below the table, add a short paragraph:

```
**Client IP behind a reverse proxy.** By default the relay keys the failed-auth limit on the TCP peer. Behind a proxy that is the proxy's address, which is safe: valid tokens never count against the limit. To key on the real client, set `RELAY_TRUSTED_PROXIES`, but only if clients cannot reach the relay except through those proxies. In `X-Forwarded-For` mode, every trusted proxy must append its peer to the header, which is the default for nginx (`$proxy_add_x_forwarded_for`), Traefik, Envoy and cloud load balancers. With a single-value header (`X-Real-IP`, `CF-Connecting-IP`, …), the outermost trusted proxy must overwrite it.
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

Set the override to the measured count + 15. The auth matrix alone makes 24 failures, so the value is at least 39; the production default of 30 would throttle the matrix itself. The 15 leaves headroom so the flood step, not the earlier steps, empties the bucket.

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
        agent_status, _ = clients.ws_upgrade("127.0.0.1", relay.port, "/ws", stub.mint(upn=FLOOD_AGENT_USER))
        reply = self._tunnel_connect(relay, stub.mint(), ip, targets)
        ok = (agent_status == 101 and reply.get("type") == "tcp_connect_result"
              and reply.get("success") is True)
        return ok, (f"429 after {throttled_at} bad-token upgrades; then valid /ws upgrade: HTTP {agent_status}, "
                    f"valid /tunnel connect: {json.dumps(reply)}")
```

Next to `OTHER_USER` / `PENTEST_USER` add `FLOOD_AGENT_USER = "flood-agent@netbridge.test"`. A second user is needed so the `/ws` upgrade does not displace the journey user's connected agent. Import `FAULT_TUNING` from `.stack` if `journey.py` does not already. In `_journey`, after `self._pentest_step(relay, stub, env, logs)`:

```python
        self.check("auth_flood_spares_valid_users", lambda: self._auth_flood(relay, stub, ip, targets))
```

The relay always runs with the auth stub, in both source and exe mode (`journey.py`, `Relay(..., auth=stub)`), so the step runs unguarded in both modes. In exe mode it runs in `e2e-windows.yml`, where the pentest suite is skipped, so fewer failures precede it.

- [ ] **Step 4: Add a unit test for the step's decision logic**

Follow the style of the existing `e2e/tests/test_journey_auth.py`, which fakes `clients` and the relay. Cover three cases:
- 429 on attempt 3, then `/ws` 101 and a successful tunnel connect: pass, and the detail contains `429 after 3`
- no 429 within the cap: fail
- a 429, then `/ws` 101 and a failed connect: fail
- a 429, then `/ws` 429 and a successful connect: fail

- [ ] **Step 5: Run the e2e unit tests and the full journey**

Run: `cd e2e && uv run pytest -q`, then the journey command from Step 1. All steps must pass, including:
- `auth_flood_spares_valid_users`
- the `_reconnect` and fault steps after it. They pass with the lowered limit. They do not prove anything about an empty bucket, because `_reconnect` restarts the relay; the flood step itself is that proof.

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
