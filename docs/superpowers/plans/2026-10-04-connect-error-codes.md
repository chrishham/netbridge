# Structured connect error codes: implementation plan

Spec: `docs/superpowers/specs/2026-10-04-connect-error-codes-design.md`. Read
it first; it is the source of truth for codes, mappings and compatibility.

Conventions:
- Run tests with `uv run pytest` inside each component dir. The agent needs
  `uv sync --group dev` first.
- TDD: write each test, watch it fail, then implement.
- Match the surrounding style: f-string logs, short comments only where the
  why is not obvious.
- Commit after each task with a plain human-style message and no attribution
  lines.
- Do not loosen existing assertions except where the spec changes behaviour.

## Task 1: shared vocabulary (`shared`)

Files: `shared/src/shared_auth/connect_errors.py` (new),
`shared/tests/test_connect_errors.py` (new).

1. Tests:
   - every constant is in `ALL_CODES` and matches `ERROR_CODE_RE`
   - `valid_error_code` accepts each code and an unknown well-formed
     `"future_code"`; it rejects `None`, `1`, `""`, `"A"`, `"a-b"`, and 33
     chars
   - both maps cover exactly `ALL_CODES`
   - `socks5_reply_for` / `http_status_for` return the spec table values
   - both functions return `0x04` / `502` for `None`, unknown and malformed
     input
2. Implement per the spec section "Shared vocabulary". Use plain module-level
   `str` constants (`REFUSED = "refused"`, …). Use `re.fullmatch` with
   `[a-z_]{1,32}`, so a trailing newline is rejected, unlike `$`. Add a test
   for `"refused\n"`.
3. `uv run pytest` in `shared` with the coverage floor of 91 green. Commit.

## Task 2: agent producers (`netbridge-agent`)

Files: `src/netbridge_agent/tunnel.py`, `agent.py`, `legacy.py`; tests in
`tests/test_tunnel.py`, `tests/test_agent.py` (or `test_agent_malformed.py`
for field errors), `tests/test_legacy.py`.

1. `connect_error_code(exc)` in `tunnel.py`, following the spec's ordered
   rules. Tests, one per rule:
   - `ProxyAuthRejected`
   - `ProxyConnectionError` with 403/502/504/407/None
   - `DnsError`
   - `socket.gaierror`
   - `ConnectionRefusedError`
   - `TimeoutError` and `asyncio.TimeoutError`
   - `OSError(errno.EHOSTUNREACH)`, `OSError(errno.ENETUNREACH)`,
     `OSError(errno.ETIMEDOUT)`
   - an `OSError` with only `winerror=10061/10065/10051/10060` set: build it,
     then set the attribute
   - an unrelated `OSError`
   - `ValueError` → `general`

   First move `class DnsError(OSError)` from `agent.py` to `tunnel.py`, and
   change `agent.py`'s import to `from .tunnel import DnsError,
   ProxyAuthRejected`. A back-import from `agent.py` would be circular.
   `tests/test_agent_dns.py` imports `DnsError` from `netbridge_agent.agent`
   and must keep passing unchanged. Check `DnsError` before the generic
   `OSError` branch. Add a test that feeds the exception actually raised by
   `resolve_destination` (patch `getaddrinfo` to raise `socket.gaierror`,
   and the timeout case) into `connect_error_code` and gets `dns_failed`.
2. `agent.py` `handle_tcp_connect`: add `"error_code"` to every failure send,
   per the spec's Agent section. Import the constants from
   `shared_auth.connect_errors`. Append ` [<code>]` to the `Failed:` and
   `Destination denied:` warning lines. Keep their prefixes byte-identical.
   Tests drive `handle_tcp_connect` with the existing fakes/helpers in
   `test_agent.py`. Cover the cases below, asserting the sent `error_code`
   and, for the last two, the log suffix:
   - invalid fields
   - pending cap, active cap
   - the three intercept branches
   - denied destination
   - refused (a closed local port, or monkeypatched `open_tcp_connection`
     raising `ConnectionRefusedError`)
   - `DnsError`
   - `ProxyAuthRejected`
3. `legacy.py`: the same treatment per the spec. Remember that
   `ProxyConnectionError` reaches the generic `except Exception` handler,
   which must therefore use `connect_error_code(e)`. The pending-cancel
   reply gets `general`; the existing test around `test_legacy.py:423`
   should assert it. Tests in
   `test_legacy.py` follow the file's existing style.
4. `uv sync --group dev && uv run pytest` green with floor 54. Commit.

## Task 3: relay (`relay`)

Files: `relay/src/relay/__main__.py`; tests in
`tests/test_relay_malformed.py`, `tests/test_relay_limits.py`,
`tests/test_relay_agent_loop.py`, `tests/test_destinations.py` (wherever the
existing case for each branch lives; add an `error_code` assertion next to
the existing `error` assertion).

1. Add `error_code` to each relay-originated failure in
   `_handle_tcp_connect` (invalid stream id, invalid params, rate limit,
   blocked port, destination denied, max streams, no agent, collision).
   Check for other failure-result senders in the same file (`grep -n
   '"success": False'`) and code those too, choosing from the vocabulary;
   note any judgement call in the commit message.
2. Extend `_valid_connect_result`:
   - absent `error_code` OK
   - on failure it must satisfy `valid_error_code`
   - on success it must be absent

   Tests:
   - agent frames with a valid code, an unknown-but-well-formed code, a
     malformed code (int, uppercase, too long), and a code on success
   - assert forwarded vs dropped
   - the forwarded frame equals the agent's bytes
3. `uv run pytest` green with floor 81. Commit.

## Task 4: proxy consumers (`socks-proxy`)

Files: `src/socks_proxy/tunnel.py`, `socks5.py`, `http_proxy.py`; tests in
`tests/test_tunnel.py`, `tests/test_socks5.py`, `tests/test_http_proxy.py`.

1. `TunnelConnectError.__init__(self, message, error_code=None)` stores
   `self.error_code`. Keep it a `ConnectionError` subclass. In
   `TunnelManager.connect`, attach the code only if `valid_error_code`
   passes. Tests:
   - a valid code is attached
   - a malformed code (int, `"BAD"`) becomes `None`
   - an absent code gives `None`
   - classification and agent-availability behaviour are unchanged (an
     existing test likely covers this; make sure it still passes)
2. `socks5.py`: add `except TunnelConnectError` before
   `except ConnectionError` and send `socks5_reply_for(e.error_code)`. Log
   the code. Tests, one per spec row (parametrize):
   - `refused` → 0x05, `not_allowed` → 0x02, `timeout` → 0x06,
     `network_unreachable` → 0x03, `no_agent` → 0x01
   - absent code → 0x04
   - plain `ConnectionError` → 0x04 (unchanged)
3. `http_proxy.py`: in the CONNECT and forward paths, catch
   `TunnelConnectError` first and write the status line from
   `http_status_for`. Build the response bytes with a small helper:
   `HTTP/1.1 <code> <reason>\r\nContent-Length: 0\r\n\r\n`. The reason
   phrases are 400 Bad Request, 403 Forbidden, 502 Bad Gateway, 503 Service
   Unavailable, 504 Gateway Timeout. Keep the existing `HTTP_502_BAD_GATEWAY`
   and `HTTP_504_TIMEOUT` constants for the local paths. Parametrized tests
   for both paths: 403, 503, 400, 504 via the `timeout` code, absent → 502,
   plain `ConnectionError` → 502.
4. `uv run pytest` green with floor 54. Commit.

## Task 5: e2e journey (`e2e`)

Files: `e2e/src/netbridge_e2e/journey.py`, and `e2e/tests/test_journey_errors.py`
if it unit-tests the step helpers.

1. `_errors`: replace `expect = 4 if front == "socks5" else 502` with
   per-case expectations from the spec table. Add the agent-log code suffix
   to the `alog` regexes: `... ConnectionRefusedError: .*\[refused\]`,
   `DnsError: .*\[dns_failed\]`, `Destination denied: ... \[not_allowed\]`.
   Check how `_error_case` compares HTTP statuses and update it if it
   hard-codes 502. Update the comment in `healthy()`.
2. `_filter.blocked`: expect `0x02` and update the message.
3. `_user_isolation` (it uses the raw `/tunnel` helper `_tunnel_connect`):
   add `and other.get("error_code") == "no_agent"` to `isolated`. The detail
   string already dumps the full reply.
4. Update the driver unit tests that pin the old values.
5. `uv run pytest` in `e2e` green with floor 79.
6. Run the full journey in source mode locally (see `ci.yml` e2e-source for
   the exact command, including the `/etc/hosts` mapping step; if `sudo`
   for `/etc/hosts` is unavailable, run without `--target-hostname` and
   note it). It must pass all steps. Commit.

## Task 6: whole-repo verification

- `scripts/coverage.sh` green.
- `git diff adc0ee6..HEAD` contains no stray debug output.
- Note the final test counts per component for the report.
