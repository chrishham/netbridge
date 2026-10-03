# Auth and security e2e (sub-project C)

Date: 2026-10-03
Status: autonomous design (user: "προχώρα τα"); decisions logged below
Depends on: A (merged, #20) and B (#22)

## Context

Every e2e run so far starts the relay with `--no-auth`. Production never
does: there the relay validates an Azure AD token on every `/ws` (agent) and
`/tunnel` (client) upgrade, pairs agent and client by the token's user, and
hides `/status` counts from anonymous callers. None of that is exercised end
to end; the unit tests mock `_get_jwks` and never check a real signature.
`security-tests/pentest_suite.py` covers rejection cases but runs by hand,
and several of its checks pass when the relay is down.

Facts (verified in code, 2026-10-03):

- `shared_auth.validate.validate_arm_token`: tenant in
  `NETBRIDGE_ALLOWED_TENANTS`, issuer `https://sts.windows.net/{tid}/` or
  `https://login.microsoftonline.com/{tid}/v2.0`, audience exactly
  `https://management.azure.com`, `exp` (no skew), `nbf` (60 s skew), then the
  RS256 signature against the key with the token's `kid` from
  `_get_jwks(tid)`, which fetches `_get_jwks_url(tid)` =
  `https://login.microsoftonline.com/{tid}/discovery/v2.0/keys` (httpx,
  cached per tenant). Identity: `upn` → `unique_name` → … .
- There is **no configuration seam** for the key URL. The relay runs as a
  subprocess (source) or container (image), so tests cannot monkeypatch it
  in-process.
- Relay: token only from `Authorization: Bearer`; rejection is HTTP 401
  before the upgrade, logged `Agent auth rejected for {ip}: …` /
  `Tunnel auth rejected for {ip}: …`. `/status` adds `agents`,
  `tunnel_clients`, `active_streams` only for authenticated callers.
  Pairing: `bridge_agents[user]`, tunnel clients keyed by user.
- Agent and proxy get tokens from `az account get-access-token`; the e2e
  fake `az` currently returns an unsigned `alg: none` token without
  `iss`/`aud`/`kid`.

## Goals

1. Run the whole journey with **auth on**, in all modes (source, docker
   image, Windows exe), with real RS256 signatures checked by the relay's
   real validation code.
2. An **auth matrix** against the live relay: every rejection reason gets a
   401 on both endpoints, a valid token gets the upgrade.
3. **User isolation** end to end: a client of another user cannot reach
   this user's agent.
4. Run the pentest suite in CI against the journey's relay, and make it
   unable to pass against a dead relay.
5. Unit tests for the untested auth paths (real signatures, `kid` refetch,
   allowlists; agent/proxy 401 refresh, 3-strike give-up, 403 stop).

## Non-goals

- Any product-code seam for the key URL (an env var that redirects key
  fetching is an auth bypass in waiting; decided against — see Decisions).
- Real Azure AD.
- Token refresh timing in e2e (unit-tested instead).

## Design

### 1. `AuthStub` (new `e2e/src/netbridge_e2e/authstub.py`)

```python
class AuthStub:
    def __init__(self, work: Path, tenant: str = TEST_TENANT): ...
    tenant: str
    kid: str
    jwks_url: str                  # http://127.0.0.1:<port>/<tenant>/discovery/v2.0/keys
    key_path: Path                 # PEM private key in a private temp dir OUTSIDE the work dir
                                   #   (the work dir is uploaded as a CI artifact), mode 0600, removed by close()
    def start(self) -> None        # HTTP server thread serving the JWKS (only that path; 404 otherwise)
    def close(self) -> None
    def mint(self, *, upn="e2e@netbridge.test", lifetime=3600, **overrides) -> str
    def requests(self) -> int      # JWKS fetches served (proves the relay really fetched keys)
```

- RSA-2048 key generated per run with `cryptography` (new direct dependency
  of the e2e package); JWKS entry `{kty, kid, use: "sig", alg: "RS256", n, e}`.
- `mint` builds a real RS256 JWT with header `{alg: RS256, typ: JWT, kid}`
  and claims `tid`, `iss` (v2 issuer), `aud` (`https://management.azure.com`),
  `upn`, `iat`, `nbf`, `exp`; `overrides` replace or (with value `None`)
  remove claims, and `kid`/`key` overrides allow signing with a foreign key.

### 2. Fake `az` signs tokens

`fakeaz/bin/az.py`: when `NETBRIDGE_E2E_SIGNING_KEY` (PEM path),
`NETBRIDGE_E2E_KID`, `NETBRIDGE_E2E_TENANT` are set, `get-access-token`
returns a token minted the same way as `AuthStub.mint` (shared helper module
importable by both — the fake az runs under the driver's interpreter,
`NETBRIDGE_E2E_PYTHON`) and `account show` reports that tenant. Without them
it keeps today's unsigned token (used by tests of the fake itself).
`NETBRIDGE_E2E_UPN` selects the user (default `e2e@netbridge.test`).

### 3. Point the relay at the stub without a product seam

New `e2e/src/netbridge_e2e/relaysite/sitecustomize.py`, put on the relay's
`PYTHONPATH` (source: env; image: `docker run -v <dir>:/e2e-site:ro -e
PYTHONPATH=/e2e-site`). At interpreter start it:

- reads `NETBRIDGE_E2E_JWKS_URL`; does nothing if unset;
- refuses (prints to stderr and does nothing) unless the URL's host is
  `127.0.0.1`/`localhost`/`::1`;
- imports `shared_auth.validate` and replaces `_get_jwks_url` with a function
  returning that URL for the stub's tenant (and raising for any other tenant,
  so a wrong-tenant token can never reach a key);
- prints one loud line `E2E: relay key URL redirected to <url>` to stderr
  (captured in the relay log; the journey asserts it).

The relay's own validation code (issuer, audience, expiry, signature, kid
refetch, caching) runs unmodified.

### 4. Journey with auth on

- `Relay` gains `auth: AuthStub | None`. With a stub: no `--no-auth`, no
  `NETBRIDGE_ALLOW_NO_AUTH`; `NETBRIDGE_ALLOWED_TENANTS=<stub tenant>`;
  `NETBRIDGE_E2E_JWKS_URL`, `PYTHONPATH` (source) or the docker `-v`/`-e`
  pair (image). Without a stub it behaves as today (kept for the driver's own
  tests). `Relay.status()` sends `Authorization: Bearer <stub.mint()>` when it
  has a stub, so `wait_paired` keeps working.
- The journey creates the stub before the relay, passes it to `Relay`, and
  adds the fake-az env (`NETBRIDGE_E2E_SIGNING_KEY`, `_KID`, `_TENANT`) to the
  client env. Step `auth_stub_up` (URL, kid); `relay_up` additionally
  requires the relay log line from §3 and `/status` reporting
  `auth_required: true`.
- `az_called` stays; new step **`relay_fetched_keys`** after `relay_paired`:
  `stub.requests() >= 1`.

### 5. Auth matrix (step `auth_matrix`, right after `relay_up`)

`clients.ws_upgrade(host, port, path, token|None) -> tuple[int, str]`
performs a raw HTTP/1.1 websocket upgrade and returns the status code (101 or
the error) and the response body (the relay puts the rejection reason in the
401 body), closing the socket. A 401 alone is not enough: each case also
asserts the **reason** in the body, so a regression in one check cannot hide
behind another check that happens to reject the token too. For each of `/ws`
and `/tunnel`:

| Case | Token | Expect (status, reason in body) |
|---|---|---|
| none | — | 401, `Missing Authorization header` |
| garbage | `not-a-jwt` | 401, `Invalid JWT format` |
| wrong signature | minted with a foreign key, same `kid` | 401, `Signature verification failed` |
| unknown kid | minted with stub key, `kid=other` | 401, `Signing key not found` |
| expired | `lifetime=-60` | 401, `Token expired` |
| not yet valid | `nbf=now+600` | 401, `not yet valid` |
| wrong tenant | `tid=<other uuid>` (+ matching iss) | 401, `Invalid tenant`, and the stub's JWKS request count is unchanged (tenant is rejected before any key fetch) |
| wrong issuer | `iss=https://evil.example/` | 401, `Invalid issuer` |
| wrong audience | `aud=https://graph.microsoft.com` | 401, `Invalid audience` |
| no identity | `upn=None` (no other identity claims) | 401, `No user identity` |
| no kid | header without `kid` | 401, `No key ID in token header` |
| malformed payload | three segments, payload not base64 JSON | 401, `Token validation failed` (or the decode error text in the code) |
| valid | `stub.mint(upn="matrix@netbridge.test")` | 101 |

The exact reason strings are taken from `validate.py`/`authenticate_request`
at implementation time (the table reflects the current code). The optional
max-token-age check (`NETBRIDGE_MAX_TOKEN_AGE_HOURS`, off by default) and
the user/group allowlists are not enabled on the journey relay; they are
covered by the unit tests in §8.

All 26 outcomes in the step detail on failure; the step also checks that the
relay logged at least one `auth rejected` line per endpoint. The valid
upgrades use a user nobody else uses and close immediately, so they cannot
disturb pairing.

### 6. User isolation (step `auth_user_isolation`, after the traffic steps)

`clients.WsClient` — a minimal websocket client (upgrade with a bearer token,
masked text frames out, text frames in; enough for one JSON request and its
reply). The driver connects to `/tunnel` as `other@netbridge.test` and sends
`{"type": "tcp_connect", "stream_id": <random>, "host": <target ip>, "port":
<http port>}`; it must receive `tcp_connect_result` with `success: false` and
the relay's "No bridge agent available" error within 10 s. To prove the
precondition (the journey user's agent really is connected during the
attempt), a SOCKS echo stream of the journey user is opened and round-tripped
**before** the other-user attempt and round-tripped again **after** it, on the
same connection. Then, as a control, a
`WsClient` for `e2e@netbridge.test` sending the same request gets
`success: true` (it is answered by the real agent; the driver then sends
`tcp_close`).

### 7. Pentest suite in the journey (step `pentest_suite`)

- `security-tests/pentest_suite.py` gets a **precheck**: before any test it
  requires `GET /status` to answer 200 with JSON, and — when `--token` is
  given — a successful `/tunnel` websocket upgrade with that token; otherwise
  it prints the reason and exits 2. Tests that need an authenticated
  connection now **fail** (instead of passing) when that connection cannot
  be established. Together this removes the "dead relay / bad token passes"
  holes (several checks treated any connection error as a pass).
- New `--skip NAME` option (repeatable) that marks a test as skipped with the
  reason in the report.
- New `--strict` mode used by the journey: exit non-zero if **any**
  non-skipped test fails (any severity) or errors (exceptions are recorded
  as failures, not `INFO`), not only on CRITICAL findings. Without
  `--strict` the existing CRITICAL-only exit behaviour is kept for manual
  runs against real relays.
- Fix its broken `[project.scripts]` entry (points at an async `main`) with a
  sync wrapper.
- Journey step after `auth_user_isolation`: run
  `uv run --project security-tests python security-tests/pentest_suite.py
  ws://127.0.0.1:<relay> --token <stub.mint(upn="pentest@netbridge.test")>
  --strict --skip rapid_connection_dos --skip session_hijack --skip
  stream_id_enumeration` with a 180 s timeout; pass if exit code 0 (every
  non-skipped test passed). `session_hijack` and `stream_id_enumeration` are
  skipped because they are not observable tests (one connection without a
  separation check; a hard-coded pass): cross-user separation is proven by
  `auth_user_isolation`, stream ownership by the relay unit tests from B. Its full
  output is saved to `<work>/logs/pentest.log` and the summary line goes in
  the step detail. Source mode only (needs the checkout); in exe mode the
  step records "skipped" with the reason. The journey passes
  `--skip rapid_connection_dos`: e2e raises the relay's connection limits on
  purpose (B), so that test (which counts a missing 429 as CRITICAL) cannot
  apply; rate limiting is covered instead by new relay unit tests (§8).

### 8. Unit tests

- **shared** (`shared/tests/test_validate_signatures.py`), keys generated
  in-test, `_get_jwks` patched to return them, module caches reset:
  valid RS256 token accepted with identity; bad signature, unknown `kid`
  after one refetch (refetch happens exactly once), non-RS256 key `alg`,
  missing identity → rejected; **key rotation through the real cache**: a
  loopback HTTP server stands in for the key endpoint (`_get_jwks_url`
  patched to it, `_get_jwks` NOT mocked) serving key A, a token signed by A
  is accepted (JWKS now cached); the server switches to key B (new kid); a
  token signed by B is accepted after exactly one more fetch, and a token
  signed by A afterwards is rejected; `NETBRIDGE_ALLOWED_USERS` (upn and oid) and
  `NETBRIDGE_ALLOWED_GROUPS` allow/deny.
- **agent** (`netbridge-agent/tests/test_agent_auth.py`): `run_agent` with a
  faked `connect_and_run` raising `WSServerHandshakeError(401)`: token
  refreshed and retried; three consecutive 401s → stops with
  `Max auth failures reached` and the auth-failed status callback; 403 →
  stops immediately with `Access forbidden`.
- **relay** (`relay/tests/test_relay_limits.py`, real app via
  `aiohttp.test_utils` like B's lifecycle tests): the per-IP limit answers
  429 `Too many requests from this IP` before authentication; the per-user
  connection limit answers 429 after authentication; both with the limits
  patched small; a rejected token does not consume the per-user budget.
- **socks-proxy** (`socks-proxy/tests/test_tunnel_auth.py`): same three
  behaviours for the proxy's connect loop (`Token refreshed after auth
  failure`, give-up after 3, 403 permanent).
- **e2e driver**: `AuthStub` (JWKS shape; minted tokens verify with
  `shared_auth.validate` against the stub's JWKS; overrides), fake-az signed
  mode, `sitecustomize` (patches only for loopback URLs, raises for other
  tenants), `ws_upgrade`/`WsClient` against a tiny loopback websocket server.

## Error handling

- Stub or sitecustomize problems surface as `relay_up` failing with the relay
  log tail (missing redirect line, auth_required false).
- Matrix/isolation failures list every case's outcome.
- The pentest step's timeout and non-zero exit attach the last lines of its
  log.

## Success criteria

- The journey passes with auth on in source, image and Windows exe modes.
- `auth_matrix`: 24 × 401 and 2 × 101; `auth_user_isolation` passes;
  `relay_fetched_keys` ≥ 1; `pentest_suite` exit 0 (source mode).
- New unit tests pass; `shared_auth` coverage rises (floor raised).

## Decisions

| Decision | Alternatives | Why |
|---|---|---|
| `sitecustomize` on the relay's PYTHONPATH, e2e only | env var in product code (`NETBRIDGE_TEST_AUTHORITY`) | no auth seam ships in the product; nothing to misconfigure in production |
| Auth on for the whole journey, all modes | separate auth run | production runs auth; one run keeps CI time flat |
| Raw upgrade + minimal ws client in the driver | add `websockets`/aiohttp to the driver | driver stays stdlib-only (+cryptography) and runs on Windows |
| Pentest suite as a journey step | separate CI job with its own relay | reuses the auth-on relay; no second stack |
| Keep no-auth `Relay` mode for driver tests | remove | the driver's own unit tests and relay smoke test use it |
