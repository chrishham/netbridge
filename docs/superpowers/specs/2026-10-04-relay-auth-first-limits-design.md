# Relay: authenticate before the per-IP limit

## Problem

The relay runs its per-IP connection limit (`RELAY_RATE_IP_CONNECTIONS_PER_MIN`,
default 30/min) before authentication, keyed on `request.remote`
(`relay/src/relay/__main__.py`, `handle_websocket` and `handle_tunnel`).

In production every request arrives through Traefik
(Cloudflare → OCI VPS → k3s svclb → Traefik pod → relay). `request.remote`
is therefore always the Traefik pod IP. This was verified on 2026-10-04: a
request from 89.210.51.87 was logged as `Tunnel auth rejected for 10.42.0.51`.

Consequences:

- **Unauthenticated lockout.** Anyone can send 30 requests per minute with no
  token. That exhausts the single shared bucket, and every agent and proxy then
  gets 429 until it refills.
- **Reconnect storm.** After a relay restart, all users together share 30
  reconnects per minute.

The obvious fix is to trust `X-Forwarded-For` or `CF-Connecting-IP`. That is not
safe today, because the origin (130.61.31.4:443) answers directly and bypasses
Cloudflare, so those headers can be forged.

A second issue becomes reachable once the shared bucket stops capping it. A
token with an allowed `tid` and an unknown `kid` makes `validate_arm_token`
drop the tenant's JWKS cache and refetch it from Microsoft, on every such
request (`shared/src/shared_auth/validate.py`, the "Key not found" branch).
That is an unthrottled request amplifier.

## Goals

- A request carrying a valid token is never refused because of other traffic
  from the same IP.
- Failed authentication stays throttled per IP, so floods are cheap to reject
  and do not flood the logs unbounded.
- JWKS fetches toward Microsoft are bounded per tenant: single flight,
  failure backoff, and a forced-refresh cooldown.
- The fix works without any infrastructure change. An optional, off-by-default
  setting can recover the real client IP behind trusted proxies.

Non-goals:

- Changing per-user limits.
- Changing the agent or proxy.
- Making infrastructure changes. Locking the origin to Cloudflare and closing
  the public 6443 are recommended to the user separately.

## Design

### 1. Authenticate first; the IP bucket counts failures only

New flow in both `handle_websocket` (`/ws`) and `handle_tunnel` (`/tunnel`),
factored into one helper so the two stay identical:

```
client_ip = _client_ip(request)
success, result = await authenticate_request(request)
if success:
    -> continue to the existing per-user connection limit (unchanged)
else:
    entry = _get_ip_limiter(client_ip)
    if not entry.limiter.has_capacity():
        log warning "Per-IP auth-failure limit exceeded for {client_ip}"
        return 429 "Too many failed attempts from this IP"
    await entry.limiter.acquire()
    log warning "{Agent|Tunnel} auth rejected for {client_ip}: {result}"   (unchanged text)
    return 401 result                                                       (unchanged)
```

Details:

- A valid token is never charged to, or checked against, the IP bucket.
- Once the bucket is empty, failures get 429 instead of 401. The client learns
  it is being throttled; there is no auth-oracle concern, since the 401 bodies
  are already the validator's messages.
- Validation still runs while the bucket is empty, which is what lets a valid
  user through. The cost of each extra validation is:
  - garbage, or a missing header: rejected before any crypto
  - a disallowed tenant: rejected before any key fetch
  - a known-kid forgery: one RSA verify
  - an unknown kid: bounded by section 2
- The setting keeps its name `RELAY_RATE_IP_CONNECTIONS_PER_MIN`, so
  deployments keep working, and its default of 30. Its meaning becomes "failed
  authentication attempts per IP per minute". Update the comment in
  `__main__.py` and the README table row ("Max failed auth attempts per IP per
  minute").
- With `--no-auth` (dev/e2e only), authentication always succeeds, so the IP
  bucket is never used. That is acceptable for a mode that refuses to start
  without `NETBRIDGE_ALLOW_NO_AUTH`.
- **Bounded logging.** The 401 warning is already bounded by the bucket, to at
  most `RELAY_RATE_IP_CONNECTIONS_PER_MIN` per IP per minute. The
  `Per-IP auth-failure limit exceeded` warning is logged at most once per IP
  per 60 s. When it is logged, it includes the number of throttled requests
  suppressed since the last such line, e.g.
  `Per-IP auth-failure limit exceeded for {ip} (12 more since last report)`.
  Keep the suppression state on the `_TimedLimiter` entry, as two fields
  `last_report: float` and `suppressed: int`, so the existing stale-entry
  cleanup also clears it.
- **Validation work while throttled.** The relay cannot tell a valid token
  from a forged one without validating it, so any pre-validation shortcut would
  lock out valid users. That is the bug being fixed.
  - Missing headers, malformed JWTs and disallowed tenants are rejected
    before any crypto or key fetch.
  - The most expensive case is a forged token for an allowed tenant with a
    known `kid`. It costs one RSA-2048 verify (tens of µs), which is small
    next to accepting the TCP connection and parsing the HTTP upgrade. The
    attacker pays the same per-connection cost.
  - Key fetches are bounded by section 2.
  - Volumetric floods are out of scope for an application-level limiter;
    they belong to the edge (CDN or LB connection limits).

### 2. Bounded JWKS fetching

Moving authentication before the limiter means every request for an allowed
tenant reaches `_get_jwks`. Today the shared per-IP bucket caps how often that
happens, by accident. Three rules in `shared/src/shared_auth/validate.py`
bound fetches toward Microsoft regardless of request rate:

1. **Single flight per tenant.** `_get_jwks` takes a per-tenant `asyncio.Lock`
   (`_jwks_locks: dict[str, asyncio.Lock]`, created on demand) around the
   fetch. After acquiring it, it re-checks the cache. Concurrent cache misses,
   for example at TTL expiry, cause one fetch; the rest wait and reuse the
   result.
2. **Failure backoff.** When a fetch fails (transport error, HTTP error,
   invalid JSON), record `_jwks_failed_at[tid] = time.monotonic()`.
   - For `JWKS_FETCH_BACKOFF = 10` seconds after a failure, further cache
     misses for that tenant do not fetch. If a cached JWKS exists, even an
     expired one, they use it; otherwise they raise `TokenValidationError("Signing keys unavailable")`.
   - An expired-but-present cache keeps being used through a backoff, so a
     Microsoft outage does not lock out users whose keys are cached.
3. **Forced refresh, rate-limited and non-destructive.** The unknown-kid branch
   no longer evicts the cache before fetching. It calls
   `_get_jwks(tid, force=True)`. That bypasses the TTL check, still respects
   single flight and backoff, and replaces the cache only on success. A failed
   forced fetch leaves the previous keys in place.
   - A forced refresh happens at most once per tenant per
     `JWKS_FORCED_REFRESH_COOLDOWN = 60` seconds, tracked in
     `_jwks_forced_refresh: dict[str, float]`.
   - The timestamp is recorded before the fetch is awaited, so concurrent
     unknown-kid requests in the window do not fetch.
   - Within the cooldown, an unknown kid fails with the existing
     `Signing key not found: {kid}`.

Key rollover trade-off:

- Microsoft publishes new signing keys in the JWKS well before it issues tokens
  with them. The normal TTL refresh (`JWKS_CACHE_TTL`, 1 h, unchanged) picks
  them up ahead of use, so a legitimate token with an unknown kid is already
  rare.
- Worst case: an attacker has just used the forced refresh, *and* Microsoft
  starts signing with a key published less than an hour earlier. Tokens with
  that kid then fail for up to 60 s, and clients retry.
- That bounded, unlikely window is accepted in exchange for capping forced
  fetches at 1/min/tenant. The alternative is unbounded amplification toward
  Microsoft.

`shared/tests` must reset `_jwks_forced_refresh`, `_jwks_failed_at` and
`_jwks_locks` wherever they reset `_jwks_cache`. Tests for rules 1-3 must run
against the real `_get_jwks`, with `httpx` mocked at the transport (for example
`httpx.MockTransport`, or by patching `httpx.AsyncClient.get`), not by
patching `_get_jwks` itself. Otherwise single flight and backoff go
untested.

### 3. Optional real client IP behind trusted proxies (off by default)

`_client_ip(request)` in the relay:

- `RELAY_TRUSTED_PROXIES`: a comma-separated list of CIDRs, default empty.
  Parse it at startup with `ipaddress.ip_network(..., strict=False)`; an
  invalid entry is a startup error, matching how other config errors are
  handled.
- `RELAY_CLIENT_IP_HEADER`: a header name, default `X-Forwarded-For`.
- If the list is empty, or `request.remote` is not inside a trusted CIDR,
  return `request.remote or "unknown"`. That is exactly today's behaviour.
- Otherwise, read the header:
  - For `X-Forwarded-For` (compared case-insensitively), split on commas and
    walk right to left. Return the first entry that parses as an IP and is not
    inside a trusted CIDR.
  - For any other header, e.g. `CF-Connecting-IP`, use the whole value if it
    parses as an IP.
  - If nothing usable is found, fall back to `request.remote`.

The function feeds both the log lines and the IP bucket key.

Requirements for trusting a proxy, documented in the README next to the
settings:

- Clients must not be able to reach the relay except through the trusted
  proxies.
- In `X-Forwarded-For` mode, each trusted proxy must *append* its peer address
  (standard behaviour for nginx `$proxy_add_x_forwarded_for`, Traefik, Envoy,
  cloud LBs). Because the walk is right to left over trusted hops, any prefix
  the client forged is never reached.
- In single-value mode (`X-Real-IP`, `CF-Connecting-IP`, …), the outermost
  trusted proxy must *overwrite* the header with the peer address. The relay
  cannot verify this; a proxy that passes the client's value through lets
  clients choose their bucket key.

The production origin can be bypassed today, so production stays on the
default.

Even when spoofed, this setting can only let an attacker evade the
failed-auth throttle (section 1). It cannot affect valid users.

### 4. Tests

Relay (`relay/tests/test_relay_limits.py`, alongside the existing per-IP test,
which changes). Include a test that the `Per-IP auth-failure limit exceeded`
warning is logged once per window, with the suppressed count on the next
report:

- With `RATE_LIMIT_IP_PER_MIN` patched to 2 on an auth-required relay:
  - two bad-token upgrades get 401, the third gets 429 with the new text
  - a valid-token upgrade from the same IP then succeeds (101)
  - covered for both `/ws` and `/tunnel`
- Valid tokens never consume the bucket: with the limit at 2, three valid
  upgrades all succeed, subject only to the per-user limit, which is patched
  high for this test.
- The existing per-user 429 test is unchanged.
- `_client_ip` unit tests:
  - default (no trusted proxies) returns remote, even when the header is set
  - an untrusted remote ignores the header
  - with a trusted remote, `X-Forwarded-For` `"1.1.1.1, 10.0.0.5"` and
    trusted `10.0.0.0/8` returns `1.1.1.1`
  - all entries trusted falls back to remote
  - a garbage entry is skipped
  - a custom header, `CF-Connecting-IP`, with a valid value and with an
    invalid one
  - an invalid CIDR in config raises at startup
- The existing reset fixtures (`_ip_limiters` in `test_relay_limits.py` and
  `test_relay_lifecycle.py`) stay as they are.

Shared (`shared/tests`):

All of these run against the real `_get_jwks`, with HTTP mocked at the
transport:

- An unknown kid triggers one forced fetch.
- A second unknown kid within the cooldown triggers no fetch.
- After the cooldown (monkeypatched clock), a forced fetch happens again.
- A rolled-over valid kid succeeds through the first forced refresh.
- Concurrent cache misses (empty cache, N concurrent validations) cause exactly
  one HTTP fetch.
- Concurrent unknown-kid validations cause exactly one forced HTTP fetch.
- A failed forced fetch keeps the previous keys: a token with a known kid still
  validates afterwards.
- After a fetch failure with an empty cache, further validations within the
  backoff make no HTTP call and fail with `Signing keys unavailable`. After
  the backoff they fetch again.
- An expired cache plus a failing fetch: validation uses the expired keys, and
  no second fetch happens within the backoff.

E2E (`e2e/src/netbridge_e2e/journey.py`, after `pentest_suite` and before
`_reconnect`):

- The step runs in both journey modes. The relay always runs with the auth
  stub (source and exe mode), so the step also runs against the Windows exes'
  relay in `e2e-windows.yml`.
- Lower `FAULT_TUNING["RELAY_RATE_IP_CONNECTIONS_PER_MIN"]` from 600 to the
  production default of 30. Valid reconnects no longer touch it. The fault
  steps passing with this lowered limit shows that valid reconnects are not
  throttled. It does not show it under an *empty* bucket: `_reconnect`
  restarts the relay, which resets the in-memory buckets.
- The new step, `auth_flood_spares_valid_users`, is the proof under an empty
  bucket:
  - send bad-token upgrades to `/tunnel` until one returns 429 (capped, see
    below)
  - then, with the bucket still empty:
    - a valid-token `/ws` upgrade, for a second user so the journey's agent
      is not displaced, must return 101
    - a `/tunnel` session with the journey user's valid token must complete
      one `tcp_connect` to the HTTP target
  - pass if a 429 was seen and both valid checks succeeded
  - the detail reports the attempt count at which 429 appeared
- The auth matrix (24 failures), and in source mode the pentest suite, run
  *before* this step under the lowered limit. Measure their combined failed
  attempts. If the count exceeds 20, set the override to the measured count
  + 15 instead of 30. The flood step's attempt cap is the override + 10. The
  bucket refills continuously (a leaky bucket), so pick the value from a
  measured count plus headroom, not by guesswork.
- The pentest's `rapid_connection_dos` (skipped in the journey) uses a valid
  token and expects 429 within 35 connections. The per-user limit (10/min)
  still provides that. Update its comment, which mentions the per-IP limit,
  and verify it with security-tests against a local relay.

## Deployment independence

The relay runs in several environments, not only the kantoliana.gr k3s
cluster. That cluster is the motivating case, not a design assumption. Nothing
here depends on a specific proxy, ingress, CDN or address range.

Sections 1 and 2 need no configuration and behave identically everywhere. The
design covers these topologies:

- Relay exposed directly (no proxy): `request.remote` is the real client.
  Behaviour is the same as today, except that valid users are never charged to
  the IP bucket.
- Behind any reverse proxy or ingress (nginx, Traefik, Azure Application
  Gateway, a cloud LB with SNAT, …): every request shares one IP. Valid users
  are unaffected; only failures share the throttle.
- Many legitimate users behind one egress or NAT IP (for example a corporate
  network or VDI farm), in any of the above: this case was equally broken
  before, and is fixed the same way.
- Multiple proxy layers: section 3's right-to-left `X-Forwarded-For` walk over
  `RELAY_TRUSTED_PROXIES` handles any depth.
- IPv4 and IPv6: both are handled by `ipaddress`.

Section 3 is generic and opt-in:

- No header name, proxy vendor or CIDR is hard-coded.
- `CF-Connecting-IP` and `10.42.0.0/16` appear only as examples in the rollout
  notes.
- Any single-value header (`X-Real-IP`, `CF-Connecting-IP`,
  `True-Client-IP`, …) works through `RELAY_CLIENT_IP_HEADER`.
- RFC 7239 `Forwarded` is not parsed. Add it only if an environment needs it.

The e2e step uses no proxy-specific behaviour. The topology e2e (Traefik)
that follows this change will exercise section 1 behind a proxy. It is not a
prerequisite.

## Compatibility

- Clients see no protocol change. A legitimate client that used to get a
  spurious 429 now connects.
- Clients with bad tokens get 401 as before until the per-IP failure budget is
  spent, then 429.
- No configuration change is needed to deploy. `RELAY_TRUSTED_PROXIES` is
  opt-in.

## Rollout notes for the user (not part of this change)

- Restrict 80/443 on the VPS to Cloudflare ranges, or enable Authenticated
  Origin Pulls. After that, `RELAY_TRUSTED_PROXIES=10.42.0.0/16` with
  `RELAY_CLIENT_IP_HEADER=CF-Connecting-IP` gives real client IPs in logs and
  in the failure throttle.
- Close 6443 to the internet, or restrict it to a known IP or the Headscale
  network.
