# Structured connect error codes

Date: 2026-10-04. Status: approved (decided autonomously, AFK; see the decision log).

## Problem

Every failed tunnel connect reaches the client as SOCKS5 `0x04` (host
unreachable) or HTTP `502`. That covers a refused port, an NXDOMAIN, a
destination the agent's policy denies, a port the relay blocks, and a relay
with no agent. The proxy only gets the agent's or relay's free-text `error`.
That text depends on the OS and locale (Windows wording differs), so mapping
it to a reply code would be fragile. Spec D (`2026-10-03-error-paths-gapfill-design.md`,
decision 1) pinned `0x04`/`502` and logged this follow-up. The e2e journey
currently proves which failure happened by regex over the agent and relay
logs.

## Goal

Add an optional machine-readable `error_code` to failed `tcp_connect_result`
messages. Set it wherever a failure is produced (agent, legacy agent, relay).
The proxy maps it to the correct SOCKS5 reply and HTTP status. The journey
pins the specific codes.

## Non-goals

- Changing `classify_connect_error` (agent-availability evidence). It keeps
  its text markers. Switching it to codes would change health-check
  behaviour, and it must still work against old relays. Follow-up.
- Changing reply codes for local failures: no relay connection, send failed,
  local timeout, malformed result. These keep today's replies.
- A protocol version handshake. The field is optional, which is enough.
- Removing the free-text `error`. It stays required and unchanged, for logs,
  old proxies and humans.

## Protocol

`tcp_connect_result` with `success: false` may carry
`error_code: <string>`. The field is absent on success. Valid values match
`^[a-z_]{1,32}$`.

| code | meaning | producers |
|---|---|---|
| `refused` | target actively refused (RST / ECONNREFUSED / WSAECONNREFUSED) | agent, legacy |
| `dns_failed` | name did not resolve (NXDOMAIN, SERVFAIL, resolver timeout) | agent, legacy |
| `host_unreachable` | EHOSTUNREACH / WSAEHOSTUNREACH; upstream proxy 502 | agent, legacy |
| `network_unreachable` | ENETUNREACH / WSAENETUNREACH | agent, legacy |
| `timeout` | agent-side connect timeout (TimeoutError / ETIMEDOUT / WSAETIMEDOUT); upstream proxy 504 | agent, legacy |
| `not_allowed` | destination or port denied by policy (agent allow/deny/always-blocked, relay blocked port, relay destination list); upstream proxy 403 | agent, legacy, relay |
| `no_agent` | relay has no agent for the user | relay |
| `capacity` | a limit was hit (agent pending/active caps, relay max streams, relay stream rate limit) | agent, legacy, relay |
| `invalid_request` | malformed host/port/stream id, stream id collision | agent, legacy, relay |
| `unavailable` | intercept service not configured / not running / unknown magic host | agent |
| `upstream_proxy` | corporate passthrough proxy failed for another reason (auth rejected, other status, unreachable proxy) | agent |
| `general` | anything else (unexpected exception) | agent, legacy |

### Compatibility (all four skew directions)

- **New agent, old relay**: the relay's `_valid_connect_result` only checks
  `success` and `error`. It forwards the raw frame, so the extra field
  reaches the proxy.
- **Old agent, new relay**: no field. The relay accepts an absent
  `error_code`.
- **New proxy, old agent or relay**: no field, so the proxy falls back to
  today's behaviour (`0x04` / `502`).
- **Old proxy, new agent or relay**: the field is ignored.
- **Unknown code** (a newer peer): the relay accepts any value that is
  well-formed (forward compatible). The proxy maps unknown values to the
  fallback (`0x04` / `502`).

### Relay validation

`_valid_connect_result` additionally requires `error_code` to be either
absent, or present only on `success: false` as a `str` matching the pattern.
A frame that fails this is dropped and logged, the same as other invalid
results today. The relay never rewrites agent frames: it forwards `msg.data`
as is.

## Shared vocabulary

New module `shared/src/shared_auth/connect_errors.py`. `shared-auth` is
already a path dependency of agent, relay and socks-proxy and is bundled in
the image, the exes and the Homebrew source tarball. It holds:

- string constants for each code, plus `ALL_CODES: frozenset`
- `ERROR_CODE_RE` and `valid_error_code(v) -> bool`
- `SOCKS5_REPLY: dict[str, int]` and `HTTP_STATUS: dict[str, int]`, with
  `socks5_reply_for(code)` / `http_status_for(code)` returning the fallback
  for `None` or unknown codes

Keeping both mappings next to the vocabulary means one table to read and
test. The relay and agent import only the constants and the validator.

### Mapping

| code | SOCKS5 | HTTP |
|---|---|---|
| `refused` | 0x05 connection refused | 502 |
| `dns_failed` | 0x04 host unreachable | 502 |
| `host_unreachable` | 0x04 | 502 |
| `network_unreachable` | 0x03 network unreachable | 502 |
| `timeout` | 0x06 TTL expired (matches today's local-timeout reply) | 504 |
| `not_allowed` | 0x02 not allowed by ruleset | 403 |
| `no_agent` | 0x01 general failure | 503 |
| `capacity` | 0x01 | 503 |
| `invalid_request` | 0x01 | 400 |
| `unavailable` | 0x01 | 502 |
| `upstream_proxy` | 0x01 | 502 |
| `general` | 0x01 | 502 |
| absent / unknown | 0x04 (today) | 502 (today) |

HTTP responses get a matching reason phrase. 403/503/400 send
`Content-Length: 0` like the existing 413 template.

## Agent

`DnsError` moves from `agent.py` to `tunnel.py`. `agent.py` already imports
from `tunnel.py` (`from .tunnel import ProxyAuthRejected`), so importing back
would be circular. `agent.py` re-exports it (`from .tunnel import DnsError,
ProxyAuthRejected`), so `netbridge_agent.agent.DnsError`, its tests and the
logged type name (`DnsError`) stay unchanged. New function in `tunnel.py`:
`connect_error_code(exc: BaseException) -> str`. It checks in order:

1. `ProxyAuthRejected` → `upstream_proxy`
2. `ProxyConnectionError`: status 403 → `not_allowed`, 504 → `timeout`,
   502 → `host_unreachable`, else `upstream_proxy`
3. `DnsError` → `dns_failed`
4. `socket.gaierror` → `dns_failed`
5. `ConnectionRefusedError` → `refused`
6. `TimeoutError` (includes `asyncio.TimeoutError`) → `timeout`
7. other `OSError`: the errno is checked first, then `winerror`
   - ECONNREFUSED / 10061 → `refused`
   - EHOSTUNREACH / 10065 → `host_unreachable`
   - ENETUNREACH / 10051 → `network_unreachable`
   - ETIMEDOUT / 10060 → `timeout`
   - otherwise `general`
8. anything else → `general`

`open_tcp_connection` re-raises the last per-address exception
(`raise last_exc`), so a multi-address target reports the last failure. That
is the same exception today's text comes from, so the code and the message
agree.

`handle_tcp_connect` / `do_connect` add `error_code` to every failure
message:
- `valid_connect_fields` failure and reused id → `invalid_request` (a reused
  id sends nothing today and stays silent)
- pending/active caps → `capacity`
- intercept branches → `unavailable`
- destination denied with a policy reason (`dest_reason` non-empty) →
  `not_allowed`
- resolution returned no usable addresses (`dest_reason` empty and
  `addresses` empty; `getaddrinfo` returned nothing usable) → `dns_failed`.
  The log line becomes `DNS returned no usable addresses: ... [dns_failed]`
  instead of `Destination denied`.
- the two `except` handlers → `connect_error_code(e)`. A `DnsError` from
  `resolve_destination` lands there and maps to `dns_failed`.

The log line `Failed: <id> -> host:port: <Type>: <text>` gains a
` [<code>]` suffix. Existing journey regexes anchor on the prefix, so they
still match. Denied destinations log
`Destination denied: ... [not_allowed]`.

`legacy.py` gets the same treatment in its own except paths:
- the `CancelledError` reply, sent while the task is still pending, →
  `general`
- timeout → `timeout`
- `OSError` and the generic `Exception` handler → `connect_error_code(e)`.
  `ProxyConnectionError` is not an `OSError`, so it lands in the generic
  handler and still has to get its semantic code.

The same applies to its field, cap and denial replies.

Legacy DNS: today `handle_tcp_connect` calls `validate_destination(host,
port)`, which swallows `DnsError` (resolved = `[]`, and an empty list passes
policy). The dial then resolves the name again, so a resolver failure could
show up as `timeout`, or as `general` on a slow name. Legacy now calls
`resolve_destination` itself first:
- `DnsError`, or an empty result → reply `dns_failed` and log
  `[TCP] DNS failed: ...`
- otherwise pass `resolved=` into `validate_destination`, so the policy is
  judged on the same answer

The dial still uses the hostname. Porting the single-resolution dial to
legacy stays out of scope, per spec D decision 30. The only behaviour change
is that an unresolvable name now fails fast with a code instead of going
through a doomed dial. The legacy path is deprecated, but it is cheap
to keep it consistent, so every producer stays honest.

## Relay

Every relay-originated failure in `_handle_tcp_connect` gets a code:
- invalid stream id / params, collision → `invalid_request`
- rate limit, max streams → `capacity`
- blocked port, destination denied → `not_allowed`
- no agent → `no_agent`

`_valid_connect_result` is extended as described above. The text stays
unchanged, so `classify_connect_error` keeps working.

## Proxy (socks-proxy)

- `TunnelConnectError` gains `error_code: Optional[str]`. `TunnelManager.connect`
  reads `result.get("error_code")` and keeps it only if
  `valid_error_code(...)` passes (otherwise `None`), then raises
  `TunnelConnectError(error, error_code=code)`.
- `socks5.py`: `except TunnelConnectError as e` comes before
  `except ConnectionError` and replies `socks5_reply_for(e.error_code)`. The
  other branches are unchanged. The warning log gains the code.
- `http_proxy.py`: the CONNECT and forward paths catch `TunnelConnectError`
  first and write the status line for `http_status_for(e.error_code)`. Local
  `ConnectionError` keeps `502` and timeouts keep `504`.

`socks-proxy-win` reuses `socks_proxy` and needs no changes.

## e2e journey

`_errors` / `_filter` pin specific replies instead of `4`/`502`:

| case | SOCKS5 | HTTP CONNECT / forward |
|---|---|---|
| refused | 0x05 | 502 |
| dns_failure | 0x04 | 502 |
| agent_denies | 0x02 | 403 |
| blocked_port (relay) | 0x02 | 403 |

Each case also asserts that the agent log line carries the code where the
agent produced it (`[refused]`, `[dns_failed]`, `[not_allowed]`).
Pinning a code that only the new path can produce (`0x05`, `0x02`, `403`)
proves the end-to-end plumbing in both source mode and installed-exe mode.
`_user_isolation` (the only user of the raw `/tunnel` helper
`_tunnel_connect`) additionally requires `error_code == "no_agent"` on the
other user's failed result. This gives a relay-originated code a direct wire
check, independent of any proxy mapping. The fault journey's `refused` kind (reply
0x04 after the agent or relay dies) is a local-failure path and stays as it
is.

## Testing

TDD per component. Each test must fail without its change.
- shared: vocabulary, pattern, both mappings including the fallback for
  None and unknown codes, and all codes covered by both maps.
- agent: `connect_error_code` per exception class and errno/winerror, and on
  the real `DnsError` raised by `resolve_destination` (monkeypatched
  `getaddrinfo` failure and timeout);
  `handle_tcp_connect` sends the right code for each branch; legacy
  likewise.
- relay: each relay-originated failure carries its code;
  `_valid_connect_result` accepts absent and valid codes and rejects bad type
  or pattern and codes on success; an agent frame with an unknown valid code
  is forwarded unchanged.
- socks-proxy: `connect` attaches valid codes and drops malformed ones;
  SOCKS5 and HTTP reply per code; the absent-code fallback keeps
  `0x04`/`502`.
- e2e: journey steps as above, plus driver unit tests where `e2e/tests`
  covers the step helpers.
- Coverage floors must stay green, with diff coverage at or above 80%.

## Decision log

| # | Decision | Alternatives | Why |
|---|---|---|---|
| 1 | Optional `error_code` alongside the required `error` text | replace `error`; version handshake | Compatible in every skew direction with no negotiation; old peers ignore it |
| 2 | Vocabulary and mappings in `shared_auth.connect_errors` | duplicate constants per component; new package | shared-auth is already a dependency of all three and ships in every artifact; a new package means new packaging in 4 release paths |
| 3 | Relay accepts unknown well-formed codes | strict allowlist | A newer agent behind an older relay must not get its results dropped; the proxy already falls back on unknown codes |
| 4 | Fallback for absent/unknown stays `0x04`/`502` | `0x01` | Old agents keep exactly today's client-visible behaviour |
| 5 | `timeout` → SOCKS `0x06`, HTTP `504` | `0x04` | Matches the proxy's existing local-timeout replies, so clients see one meaning |
| 6 | `not_allowed` → HTTP 403 | 502 | Standard forbidden semantics; browsers and curl show it clearly |
| 7 | `no_agent`/`capacity` → HTTP 503 | 502 | Transient service condition; 503 tells clients to retry |
| 8 | `classify_connect_error` unchanged | switch to codes | Out of scope; would change health logic and needs a text fallback for old relays anyway |
| 9 | Legacy agent gets codes too | leave legacy | Cheap with the shared classifier; keeps all producers consistent |
| 10 | Upstream proxy statuses map 403/502/504 to semantic codes, the rest to `upstream_proxy` | everything `upstream_proxy` | The corporate proxy's 403/504 mean the same thing to the user as a direct deny or timeout |
| 11 | Agent log lines gain a ` [code]` suffix | separate field / no change | Journey can pin the code from logs too; prefix stays stable for existing regexes |
