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
    monkeypatch.setattr(mod, "_jwks_refreshes", {})
    monkeypatch.setenv("NETBRIDGE_ALLOWED_TENANTS", VALID_TENANT)


class FakeMicrosoft:
    """Stands in for httpx.AsyncClient.get; counts calls, can block, fail or change keys."""

    def __init__(self, keys):
        self.keys = keys
        self.calls = 0
        self.fail = False
        self.body = None  # when set, returned as the JSON body instead of {"keys": [...]}
        self.gate: asyncio.Event | None = None

    async def get(self, client, url, *args, **kwargs):
        self.calls += 1
        if self.gate is not None:
            await self.gate.wait()
        if self.fail:
            raise httpx.ConnectError("down")
        body = self.body if self.body is not None else {"keys": list(self.keys)}
        return httpx.Response(200, json=body, request=httpx.Request("GET", url))


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
        await asyncio.gather(*list(mod._jwks_refreshes.values()))


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
        assert not mod._jwks_refreshes  # and no task was scheduled during the backoff


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
        assert len(mod._jwks_refreshes) == 1  # one pending refresh for the burst, not one per validation
        await asyncio.sleep(0.05)  # let the background refresh reach the hanging fetch
        assert ms.calls == 2  # the initial fetch plus one background refresh, still blocked
        ms.gate.set()
        await _drain_refreshes()
        assert ms.calls == 2
        assert mod._jwks_cache[VALID_TENANT][0] > time.time() - 5  # refreshed


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [[], {"keys": "x"}, {}, "keys", {"keys": []}, {"keys": [None]},
                                  {"keys": [{"kid": "k1"}]}, {"keys": [{"kid": "k1", "n": 1, "e": "AQAB"}]},
                                  {"keys": [{"kid": "k1", "n": "", "e": ""}]},
                                  {"keys": [{"kid": "k1", "n": "!!", "e": "AQAB"}]}, "empty-kid"])
async def test_malformed_jwks_response_keeps_previous_keys(key, body):
    private, jwk = key
    if body == "empty-kid":
        body = {"keys": [{**jwk, "kid": ""}]}  # valid key material, but no token can select it
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))
        ms.body = body
        with pytest.raises(TokenValidationError, match="Signing key not found"):
            await validate_arm_token(_token(private, "ghost"))  # forced refresh gets the bad body
        assert VALID_TENANT in mod._jwks_failed_at
        assert await validate_arm_token(_token(private))  # old keys still cached


@pytest.mark.asyncio
async def test_unusable_entries_are_dropped_and_usable_ones_kept(key):
    private, jwk = key
    new_private, new_public = _generate_rsa_keypair()
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))
        ms.body = {"keys": [None, {"kid": "broken"}, _key_to_jwk(new_public, "k2"), jwk]}
        assert await validate_arm_token(_token(new_private, "k2"))  # forced refresh accepts the usable keys
        assert [k["kid"] for k in mod._jwks_cache[VALID_TENANT][1]["keys"]] == ["k2", "k1"]


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


@pytest.mark.asyncio
async def test_forced_refresh_during_backoff_keeps_cooldown_unspent(key, monkeypatch):
    private, jwk = key
    clock = [1000.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    ms = FakeMicrosoft([jwk])
    with _patched(ms):
        await validate_arm_token(_token(private))  # warm cache
        _expire(mod.JWKS_CACHE_TTL + 1)
        ms.fail = True
        await validate_arm_token(_token(private))  # background refresh fails: backoff starts
        await _drain_refreshes()
        assert VALID_TENANT in mod._jwks_failed_at
        calls = ms.calls
        with pytest.raises(TokenValidationError, match="Signing key not found: ghost-1"):
            await validate_arm_token(_token(private, "ghost-1"))
        assert ms.calls == calls
        assert VALID_TENANT not in mod._jwks_forced_refresh
        clock[0] += mod.JWKS_FETCH_BACKOFF + 1
        ms.fail = False
        with pytest.raises(TokenValidationError, match="Signing key not found: ghost-2"):
            await validate_arm_token(_token(private, "ghost-2"))
        assert ms.calls == calls + 1  # backoff over: the unknown kid forces a fetch


@pytest.mark.asyncio
async def test_kidless_token_makes_no_http_request(key):
    private, jwk = key
    ms = FakeMicrosoft([jwk])
    token = _sign_jwt(private, {"alg": "RS256", "typ": "JWT"}, _make_valid_claims())
    with _patched(ms):
        with pytest.raises(TokenValidationError, match="No key ID in token header"):
            await validate_arm_token(token)
    assert ms.calls == 0
