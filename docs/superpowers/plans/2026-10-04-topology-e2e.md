# Topology e2e (TLS edge) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the whole e2e journey with an in-process TLS reverse proxy (the "edge") between the clients and the relay. The edge's proxy behaviours are parameters. The run also proves the trusted-proxy client IP from #27 through a real hop.

**Architecture:** A new driver module, `edgeproxy.py`, terminates TLS with a per-run CA, rewrites the HTTP/1.1 request head (X-Forwarded-For, prefix strip, X-Forwarded-Proto), then pumps bytes to the relay and closes idle links. It follows the thread style of `faultproxy.py`. With `--edge`, the chain is `client --wss--> FaultProxy --> edge --ws--> relay`, the clients get `NETBRIDGE_CA_BUNDLE`, and the relay trusts `127.0.0.1/32` for X-Forwarded-For. Six new journey steps assert on the edge.

**Tech Stack:** Python 3.14, stdlib `socket`/`ssl`/`select`/`threading`, `cryptography` (already an e2e dependency), pytest, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-04-topology-e2e-design.md`

## Global Constraints

- No product code changes. If one turns out to be needed, it is a compatibility finding: stop, record it, and fix it with its own test in a separate commit.
- Default (no `--edge`) runs behave exactly as today: plain `ws://`, no edge, and `RELAY_TRUSTED_PROXIES` unset.
- Edge profiles: `traefik` = `xff_port=False, prefix=""`; `arr` = `xff_port=True, prefix="/netbridge"`. Default is `traefik` in source mode and `arr` in exe mode. `--edge-profile` overrides the default.
- Edge head cap 64 KiB (the relay accepts 32 KiB header fields), then `400`. A request outside the prefix gets `404`. If the relay is unreachable, the edge answers `502`.
- e2e `idle_timeout` = 25 s, against heartbeats of 10 s (`CLIENT_TUNING` / `FAULT_TUNING`, unchanged).
- Relay env with `--edge`: `RELAY_TRUSTED_PROXIES=127.0.0.1/32`, `RELAY_CLIENT_IP_HEADER=X-Forwarded-For`.
- Client URLs with `--edge`: `wss://127.0.0.1:<link port><prefix>/ws` (agent) and `.../tunnel` (proxy). Certificate SANs: DNS `localhost` and IP `127.0.0.1`.
- TLS verification stays on everywhere. Never set `NETBRIDGE_VERIFY_SSL=false`. Nothing goes into an OS trust store.
- Driver probes, the auth matrix, the flood step and the pentest suite stay direct to the relay.
- e2e coverage floor 79 (`e2e/pyproject.toml`). Diff coverage on new lines must be ≥ 80 %.
- Use `uv`, never bare `python`. Commit messages are human-style with no Claude attribution or Co-Authored-By. `docs/` is gitignored, so docs commits need `git add -f`.

## Review Focus

1. **Relay down behind the edge** (relay restart step): the edge accepts TLS and then cannot reach the relay. It must answer `502` and close, and the clients must treat that as a transient failure and reconnect. Pinned by `test_upstream_down_answers_502`, and in the journey by `edge_relay_down_502` (the relay stays down until the edge has counted a 502 for each client and each client has logged its `handshake failed … 502`) followed by `reconnect`.
2. **Decrypted bytes buffered inside the SSL object**: `select` does not see them. A large transfer in both directions at once must not stall or deadlock. Pinned by `test_large_payload_round_trips` (32 MiB each way against an echo that blocks on its own writes).
3. **A request head trickled across many segments**: it must still parse. Pinned by `test_trickled_head_is_parsed`.
4. **Bytes sent in the same segment as the head** (a client pipelining its first frame): they must be forwarded, not dropped. Pinned by `test_bytes_after_head_are_forwarded`.
7. **TLS reads that need a write and writes that need a read** (post-handshake records): the pump retries both operations on either readiness and tracks `SSLWantWriteError` on reads and `SSLWantReadError` on writes, so neither spins nor stalls; the server sends no session tickets (`num_tickets = 0`). No unit test can force these states deterministically: the code is the guard, and the 32 MiB test plus the journey are the net.
6. **A spoofed X-Forwarded-For from a direct client**: the relay must key on the edge's peer, never on what the client wrote. Pinned by `test_listening_on_all_interfaces_appends_the_real_peer` and the journey's `edge_appends_peer`.
5. **Client-supplied forwarding headers**: repeated `X-Forwarded-For` fields merge in order into one field, and a client's `X-Forwarded-Proto` is replaced, not duplicated. Pinned by `test_repeated_xff_fields_merge_in_order` and `test_xff_appended_bare_ip_and_proto_replaced`.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `e2e/src/netbridge_e2e/edgeproxy.py` | create | TLS material, `EdgeProfile`/`PROFILES`, `RELAY_ENV`, `rewrite_head`, `EdgeProxy` |
| `e2e/tests/test_edgeproxy.py` | create | edge unit tests (TLS trust, head rewrite, pump, idle, errors) |
| `e2e/src/netbridge_e2e/clients.py` | modify | `tls_connect`; `ws_upgrade(..., ssl_context=, extra_headers=)`; `http_get(..., keep_alive=)` |
| `e2e/tests/test_clients.py` | modify | tests for the three client additions |
| `e2e/src/netbridge_e2e/stack.py` | modify | `Relay(..., extra_env=)` |
| `e2e/tests/test_stack.py` | modify | `extra_env` reaches the process env and the docker `-e` list |
| `e2e/src/netbridge_e2e/journey.py` | modify | `--edge`/`--edge-profile`, wiring, six steps |
| `e2e/tests/test_journey_edge.py` | create | edge steps against fakes; arg parsing |
| `e2e/README.md` | modify | mode table, flags, steps |
| `.github/workflows/ci.yml` | modify | new `e2e-edge` job |
| `.github/workflows/e2e-windows.yml` | modify | `--edge` on the exe run |

---

### Task 1: The edge proxy

**Files:**
- Create: `e2e/src/netbridge_e2e/edgeproxy.py`
- Test: `e2e/tests/test_edgeproxy.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `EdgeProfile(name: str, xff_port: bool, prefix: str)` (frozen dataclass), `PROFILES: dict[str, EdgeProfile]` with keys `"traefik"`, `"arr"`
  - `RELAY_ENV: dict[str, str]`
  - `make_tls_material(directory: Path) -> tuple[Path, Path, Path]` returning (ca, cert, key)
  - `rewrite_head(head: bytes, peer: tuple[str, int], profile: EdgeProfile) -> bytes`, which raises `ValueError` for a malformed head and `LookupError` outside the prefix
  - `EdgeProxy(upstream: tuple[str, int], tls_dir: Path, profile: EdgeProfile, idle_timeout: float)` with attributes `.port: int`, `.ca_path: Path`, `.profile`, `.idle_timeout`, `.accepted: int`, `.idle_closes: int`, and methods `start()`, `client_context() -> ssl.SSLContext`, `active() -> int`, `close()`

- [ ] **Step 1: Write the failing tests**

`e2e/tests/test_edgeproxy.py`:

```python
import os
import select
import socket
import ssl
import struct
import threading
import time

import pytest

from netbridge_e2e.edgeproxy import MAX_HEAD, PROFILES, EdgeProfile, EdgeProxy, rewrite_head

TRAEFIK, ARR = PROFILES["traefik"], PROFILES["arr"]
PEER = ("127.0.0.1", 40000)


class Upstream:
    """Plays the relay: records each request head, answers 101, then echoes; `answer` overrides the reply."""

    def __init__(self, answer=b"HTTP/1.1 101 Switching Protocols\r\n\r\n"):
        self.answer = answer
        self.heads: list[bytes] = []
        self.srv = socket.create_server(("127.0.0.1", 0))
        self.address = self.srv.getsockname()
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                c, _ = self.srv.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        with c:
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = c.recv(65536)
                    if not chunk:
                        return
                    buf += chunk
                head, _, rest = buf.partition(b"\r\n\r\n")
                self.heads.append(head + b"\r\n\r\n")
                c.sendall(self.answer + rest)
                while data := c.recv(65536):
                    c.sendall(data)
            except OSError:
                pass

    def close(self):
        self._stop.set()
        self.srv.close()


@pytest.fixture
def upstream():
    u = Upstream()
    yield u
    u.close()


def make_edge(tmp_path, upstream_address, profile=TRAEFIK, idle=5.0):
    e = EdgeProxy(upstream_address, tmp_path / "edge", profile, idle)
    e.start()
    return e


@pytest.fixture
def edge(tmp_path, upstream):
    e = make_edge(tmp_path, upstream.address)
    yield e
    e.close()


def tls(edge, host="127.0.0.1", ctx=None):
    raw = socket.create_connection(("127.0.0.1", edge.port), timeout=5)
    return (ctx or edge.client_context()).wrap_socket(raw, server_hostname=host)


def read_until(sock, marker: bytes) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return buf


def get(path="/ws", extra="") -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}\r\n".encode()


def ended_by_edge(s, timeout=4.0) -> bool:
    """The edge closed the link. Its close sends no TLS close_notify, so a verifying client may see
    SSLEOFError instead of b""; a timeout (TimeoutError) still fails the test."""
    s.settimeout(timeout)
    try:
        return s.recv(1) == b""
    except (ConnectionError, ssl.SSLError):
        return True


def wait_until(pred, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


# --- TLS -----------------------------------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_run_ca_verifies_the_edge_for_both_sans(edge, host):
    with tls(edge, host) as s:
        assert s.version() is not None


def test_default_trust_rejects_the_edge(edge):
    with pytest.raises(ssl.SSLCertVerificationError):
        tls(edge, ctx=ssl.create_default_context())


def test_shared_auth_context_trusts_the_ca_bundle(edge):
    """The clients' own SSL context (agent and proxy, frozen or not) accepts the edge via NETBRIDGE_CA_BUNDLE."""
    from shared_auth.connection import create_tunnel_ssl_context
    ctx = create_tunnel_ssl_context(verify=True, ca_bundle=str(edge.ca_path))
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    with tls(edge, ctx=ctx) as s:
        s.sendall(get())
        assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 101")


# --- head rewrite --------------------------------------------------------

def test_xff_appended_bare_ip_and_proto_replaced():
    out = rewrite_head(get(extra="X-Forwarded-For: 198.51.100.7\r\nX-Forwarded-Proto: http\r\n"), PEER, TRAEFIK)
    assert b"X-Forwarded-For: 198.51.100.7, 127.0.0.1\r\n" in out
    assert out.count(b"X-Forwarded-Proto") == 1 and b"X-Forwarded-Proto: https\r\n" in out
    assert out.startswith(b"GET /ws HTTP/1.1\r\n") and out.endswith(b"\r\n\r\n")


def test_xff_with_port_and_prefix_stripped():
    out = rewrite_head(get("/netbridge/tunnel"), PEER, ARR)
    assert out.startswith(b"GET /tunnel HTTP/1.1\r\n")
    assert b"X-Forwarded-For: 127.0.0.1:40000\r\n" in out


def test_bare_prefix_becomes_root():
    assert rewrite_head(get("/netbridge"), PEER, ARR).startswith(b"GET / HTTP/1.1\r\n")


def test_query_survives_the_prefix_strip():
    assert rewrite_head(get("/netbridge?x=1"), PEER, ARR).startswith(b"GET /?x=1 HTTP/1.1\r\n")
    assert rewrite_head(get("/netbridge/ws?x=/a"), PEER, ARR).startswith(b"GET /ws?x=/a HTTP/1.1\r\n")


@pytest.mark.parametrize("path", ["/ws", "/netbridgex/ws", "/", "/netbridgex?x=1"])
def test_outside_the_prefix_is_a_lookup_error(path):
    with pytest.raises(LookupError):
        rewrite_head(get(path), PEER, ARR)


def test_repeated_xff_fields_merge_in_order():
    out = rewrite_head(get(extra="X-Forwarded-For: 203.0.113.1\r\nx-forwarded-for: 198.51.100.7\r\n"), PEER, TRAEFIK)
    assert out.count(b"orwarded-For") == 1
    assert b"X-Forwarded-For: 203.0.113.1, 198.51.100.7, 127.0.0.1\r\n" in out


def test_other_headers_are_kept_verbatim():
    out = rewrite_head(get(extra="Authorization: Bearer abc\r\nUpgrade: websocket\r\n"), PEER, TRAEFIK)
    assert b"Authorization: Bearer abc\r\n" in out and b"Upgrade: websocket\r\n" in out


@pytest.mark.parametrize("head", [
    b"GET /ws\r\n\r\n",                                   # no version
    b"GET ws HTTP/1.1\r\n\r\n",                           # not origin-form
    b"GET /ws HTTP/2\r\n\r\n",                            # not HTTP/1.x
    b"GET /ws HTTP/1.1\r\nno-colon-here\r\n\r\n",         # header without a colon
    b"GET /ws HTTP/1.1\r\n folded: x\r\n\r\n",            # obsolete line folding
])
def test_malformed_heads_are_value_errors(head):
    with pytest.raises(ValueError):
        rewrite_head(head, PEER, TRAEFIK)


# --- through the edge ----------------------------------------------------

def test_head_reaches_the_relay_rewritten(edge, upstream):
    with tls(edge) as s:
        s.sendall(get(extra="X-Forwarded-For: 198.51.100.7\r\n"))
        assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 101")
    assert b"X-Forwarded-For: 198.51.100.7, 127.0.0.1\r\n" in upstream.heads[0]
    assert b"X-Forwarded-Proto: https\r\n" in upstream.heads[0]
    assert edge.accepted == 1


def test_large_authorization_header_passes(edge, upstream):
    """Entra ID tokens with many groups exceed 12 KiB; the relay accepts 32 KiB fields, so must the edge."""
    with tls(edge) as s:
        s.sendall(get(extra=f"Authorization: Bearer {'a' * 30_000}\r\n"))
        assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 101")
    assert b"a" * 30_000 in upstream.heads[0]


def test_trickled_head_is_parsed(edge, upstream):
    with tls(edge) as s:
        for b in get():
            s.sendall(bytes([b]))
        assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 101")
    assert upstream.heads[0].startswith(b"GET /ws HTTP/1.1\r\n")


def test_bytes_after_head_are_forwarded(edge, upstream):
    with tls(edge) as s:
        s.sendall(get() + b"first-frame")
        # the echo can only return it if the edge forwarded it
        assert read_until(s, b"first-frame").endswith(b"first-frame")


def test_large_payload_round_trips(edge):
    """32 MiB each way at once, against an echo that blocks on its own writes: well past the loopback
    socket buffers, so a pump that blocked on one direction's write would deadlock here."""
    data = os.urandom(32 * 1024 * 1024)
    with tls(edge) as s:
        s.sendall(get())
        read_until(s, b"\r\n\r\n")
        # one thread, non-blocking: an SSL socket is not safe to read and write from two threads
        s.setblocking(False)
        sent, got = 0, bytearray()
        while len(got) < len(data):
            want_write = [s] if sent < len(data) else []
            # decrypted bytes held by the SSL object are invisible to select: do not wait on them
            readable, writable, _ = select.select([s], want_write, [], 0 if s.pending() else 5)
            assert readable or writable or s.pending(), f"stalled: sent {sent}, got {len(got)}"
            if writable:
                try:
                    sent += s.send(data[sent:sent + 65536])
                except (ssl.SSLWantWriteError, ssl.SSLWantReadError):
                    pass
            if readable or s.pending():
                try:
                    chunk = s.recv(65536)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    continue
                assert chunk, f"closed after {len(got)} bytes"
                got += chunk
    assert got == data


def test_arr_profile_through_the_edge(tmp_path, upstream):
    e = make_edge(tmp_path, upstream.address, ARR)
    try:
        with tls(e) as s:
            s.sendall(get("/netbridge/ws"))
            assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 101")
        assert upstream.heads[0].startswith(b"GET /ws HTTP/1.1\r\n")
        assert b"X-Forwarded-For: 127.0.0.1:" in upstream.heads[0]
    finally:
        e.close()


def test_outside_prefix_answers_404(tmp_path, upstream):
    e = make_edge(tmp_path, upstream.address, ARR)
    try:
        with tls(e) as s:
            s.sendall(get("/ws"))
            assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 404")
        assert upstream.heads == []
    finally:
        e.close()


def test_malformed_head_answers_400(edge, upstream):
    with tls(edge) as s:
        s.sendall(b"BOGUS\r\n\r\n")
        assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 400")
    assert upstream.heads == []


def test_head_of_exactly_the_cap_without_terminator_answers_400(edge, upstream):
    with tls(edge) as s:
        line = "GET /ws HTTP/1.1\r\nX-Pad: "
        s.sendall((line + "a" * (MAX_HEAD - len(line))).encode())  # exactly MAX_HEAD bytes, no blank line
        assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 400")
    assert upstream.heads == []


def test_oversized_head_answers_400(edge, upstream):
    with tls(edge) as s:
        s.sendall(get(extra=f"X-Pad: {'a' * MAX_HEAD}\r\n"))
        assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 400")
    assert upstream.heads == []


class Sink(Upstream):
    """Answers 101 and then reads nothing until `release` is set: the edge has to queue what it gets."""

    def __init__(self):
        self.release, self.received = threading.Event(), 0
        super().__init__()

    def _handle(self, c):
        with c:
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = c.recv(65536)
                    if not chunk:
                        return
                    buf += chunk
                head, _, rest = buf.partition(b"\r\n\r\n")
                self.heads.append(head + b"\r\n\r\n")
                self.received += len(rest)
                c.sendall(self.answer)
                self.release.wait(10)
                while data := c.recv(65536):
                    self.received += len(data)
            except OSError:
                pass


def test_client_reset_still_delivers_what_the_edge_queued(tmp_path):
    sink = Sink()
    e = make_edge(tmp_path, sink.address)
    try:
        s = tls(e)
        s.sendall(get())
        read_until(s, b"\r\n\r\n")
        payload = 512 * 1024  # under MAX_BUFFERED plus the loopback buffers: sendall does not block
        s.sendall(b"x" * payload)
        time.sleep(0.5)  # the edge reads it all and queues what the sink will not take yet
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()  # RST, no close_notify: the edge's recv raises instead of returning b""
        time.sleep(0.2)
        sink.release.set()
        assert wait_until(lambda: sink.received == payload, 5), f"sink got {sink.received} of {payload}"
        assert wait_until(lambda: e.active() == 0)
    finally:
        e.close()
        sink.close()


def test_upstream_down_answers_502(tmp_path):
    held = socket.socket()
    held.bind(("127.0.0.1", 0))  # bound but never listening: connects are refused, and no one else gets the port
    e = make_edge(tmp_path, held.getsockname())
    try:
        with tls(e) as c:
            c.sendall(get())
            assert read_until(c, b"\r\n\r\n").startswith(b"HTTP/1.1 502")
        assert e.bad_gateways == {"/ws": 1}
    finally:
        e.close()
        held.close()


def test_failed_handshake_does_not_stop_the_edge(edge):
    with socket.create_connection(("127.0.0.1", edge.port), timeout=5) as raw:
        raw.sendall(b"not tls at all\r\n\r\n")
        raw.recv(1024)
    with tls(edge) as s:
        s.sendall(get())
        assert read_until(s, b"\r\n\r\n").startswith(b"HTTP/1.1 101")


# --- idle ----------------------------------------------------------------

def test_idle_link_is_closed_and_counted(tmp_path, upstream):
    e = make_edge(tmp_path, upstream.address, idle=1.0)
    try:
        with tls(e) as s:
            s.sendall(get())
            read_until(s, b"\r\n\r\n")
            start = time.monotonic()
            assert ended_by_edge(s)
            assert 0.8 <= time.monotonic() - start < 3.5
        assert wait_until(lambda: e.idle_closes == 1)
    finally:
        e.close()


def test_traffic_keeps_the_link_open(tmp_path, upstream):
    e = make_edge(tmp_path, upstream.address, idle=1.0)
    try:
        with tls(e) as s:
            s.sendall(get())
            read_until(s, b"\r\n\r\n")
            for _ in range(6):  # 2.4 s total, never 1 s quiet
                time.sleep(0.4)
                s.sendall(b"x")
                assert s.recv(1) == b"x"
        assert e.idle_closes == 0
    finally:
        e.close()


def test_silent_client_before_its_head_is_idle_too(tmp_path, upstream):
    e = make_edge(tmp_path, upstream.address, idle=1.0)
    try:
        with tls(e) as s:
            assert ended_by_edge(s)
        assert wait_until(lambda: e.idle_closes == 1)
        assert upstream.heads == []
    finally:
        e.close()


def test_close_ends_open_links(edge):
    s = tls(edge)
    s.sendall(get())
    read_until(s, b"\r\n\r\n")
    assert wait_until(lambda: edge.active() == 1)
    edge.close()
    try:
        assert ended_by_edge(s, 3)
    finally:
        s.close()
    assert edge.active() == 0


def test_close_does_not_wait_for_a_silent_client(tmp_path, upstream):
    e = make_edge(tmp_path, upstream.address, idle=30.0)
    s = tls(e)  # handshake done, no head: the edge sits in a blocking recv
    try:
        assert wait_until(lambda: e.active() == 1)
        start = time.monotonic()
        e.close()
        assert time.monotonic() - start < 1.5
        assert ended_by_edge(s, 3)
    finally:
        s.close()


def test_close_does_not_wait_for_a_silent_tcp_client(tmp_path, upstream):
    e = make_edge(tmp_path, upstream.address, idle=30.0)
    s = socket.create_connection(("127.0.0.1", e.port))  # no ClientHello: the edge sits in its handshake
    try:
        assert wait_until(lambda: e.active() == 1)
        start = time.monotonic()
        e.close()
        assert time.monotonic() - start < 1.5
        s.settimeout(3)
        assert s.recv(1) == b""  # the edge closed it, well before HANDSHAKE_TIMEOUT
    finally:
        s.close()


def test_listening_on_all_interfaces_appends_the_real_peer(tmp_path, upstream):
    e = EdgeProxy(upstream.address, tmp_path / "edge", TRAEFIK, 5.0, host="0.0.0.0").start()
    try:
        with tls(e) as s:
            s.sendall(get(extra="X-Forwarded-For: 203.0.113.9\r\n"))
            read_until(s, b"\r\n\r\n")
        assert b"X-Forwarded-For: 203.0.113.9, 127.0.0.1\r\n" in upstream.heads[0]
    finally:
        e.close()


def test_profiles_match_the_spec():
    assert PROFILES == {"traefik": EdgeProfile("traefik", False, ""), "arr": EdgeProfile("arr", True, "/netbridge")}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd e2e && uv run pytest tests/test_edgeproxy.py -q`
Expected: collection error, `ModuleNotFoundError: No module named 'netbridge_e2e.edgeproxy'`.

- [ ] **Step 3: Implement `edgeproxy.py`**

`e2e/src/netbridge_e2e/edgeproxy.py`:

```python
"""TLS edge in front of the relay (--edge): the properties real reverse proxies give it.

Terminates TLS with a CA made for the run, reads the HTTP/1.1 request head,
appends the peer to X-Forwarded-For (a bare IP like Traefik, or ip:port like
App Service), strips an optional path prefix, sets X-Forwarded-Proto, then
pumps bytes to the relay over plain TCP. A link with no byte in either
direction for idle_timeout seconds is closed, as Cloudflare and App Service do.
"""
import collections
import datetime
import ipaddress
import select
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TICK = 0.2
MAX_HEAD = 64 * 1024  # the relay itself accepts 32 KiB header fields (large Entra ID tokens)
HANDSHAKE_TIMEOUT = 10.0
CONNECT_TIMEOUT = 5.0
MAX_BUFFERED = 1024 * 1024  # per direction, toward a side that is not reading
# the edge reaches the relay from loopback: trust exactly that hop
RELAY_ENV = {"RELAY_TRUSTED_PROXIES": "127.0.0.1/32", "RELAY_CLIENT_IP_HEADER": "X-Forwarded-For"}


@dataclass(frozen=True)
class EdgeProfile:
    name: str
    xff_port: bool
    prefix: str


PROFILES = {
    "traefik": EdgeProfile("traefik", xff_port=False, prefix=""),
    "arr": EdgeProfile("arr", xff_port=True, prefix="/netbridge"),
}


def _usage(**on) -> x509.KeyUsage:
    flags = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
             "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")
    return x509.KeyUsage(**{f: on.get(f, False) for f in flags})


def make_tls_material(directory: Path) -> tuple[Path, Path, Path]:
    """A CA and a server cert for localhost / 127.0.0.1 signed by it: (ca.pem, cert.pem, key.pem)."""
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    valid = dict(not_valid_before=now - datetime.timedelta(minutes=5), not_valid_after=now + datetime.timedelta(days=1))
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "netbridge-e2e edge CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(valid["not_valid_before"]).not_valid_after(valid["not_valid_after"])
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(_usage(digital_signature=True, key_cert_sign=True, crl_sign=True), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(valid["not_valid_before"]).not_valid_after(valid["not_valid_after"])
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            # Python's default context sets VERIFY_X509_STRICT, which wants the key identifiers
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    paths = directory / "ca.pem", directory / "cert.pem", directory / "key.pem"
    paths[0].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths[1].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths[2].write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return paths


def rewrite_head(head: bytes, peer: tuple[str, int], profile: EdgeProfile) -> bytes:
    """The request head as the relay sees it. ValueError: malformed; LookupError: outside the prefix."""
    lines = head.decode("latin-1").removesuffix("\r\n\r\n").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[1].startswith("/") or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
        raise ValueError(f"bad request line {lines[0]!r}")
    method, target, version = parts
    if profile.prefix:
        path, mark, query = target.partition("?")
        if path != profile.prefix and not path.startswith(profile.prefix + "/"):
            raise LookupError(target)
        target = (path[len(profile.prefix):] or "/") + mark + query
    fields, forwarded = [], []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            raise ValueError(f"bad header line {line!r}")
        key = name.lower()
        if key == "x-forwarded-for":
            forwarded.append(value.strip())
        elif key != "x-forwarded-proto":  # replaced below, never passed through
            fields.append(line)
    hop = f"{peer[0]}:{peer[1]}" if profile.xff_port else peer[0]  # the edge listens on IPv4 only
    fields.append("X-Forwarded-For: " + ", ".join([*filter(None, forwarded), hop]))
    fields.append("X-Forwarded-Proto: https")
    return ("\r\n".join([f"{method} {target} {version}", *fields]) + "\r\n\r\n").encode("latin-1")


def _read_head(sock: socket.socket) -> tuple[bytes | None, bytes]:
    """(head, bytes after it); (None, b"") on EOF before any byte. ValueError if too large or cut short."""
    buf = b""
    while (end := buf.find(b"\r\n\r\n")) < 0:
        if len(buf) >= MAX_HEAD:  # never reads past the cap, so the cap is exact
            raise ValueError("request head too large")
        chunk = sock.recv(min(4096, MAX_HEAD - len(buf)))
        if not chunk:
            if buf:
                raise ValueError("connection closed inside the request head")
            return None, b""
        buf += chunk
    return buf[:end + 4], buf[end + 4:]


def _respond(sock: socket.socket, status: int, reason: str) -> None:
    body = f"{status} {reason} (e2e edge)\n".encode()
    try:
        sock.sendall(f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                     .encode() + body)
    except OSError:
        pass


def _close(s: socket.socket) -> None:
    """Shut down first: a bare close() from another thread does not wake a recv blocked on it."""
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


class EdgeProxy:
    def __init__(self, upstream: tuple[str, int], tls_dir: Path, profile: EdgeProfile, idle_timeout: float,
                 host: str = "127.0.0.1"):
        self.upstream = upstream
        self.profile = profile
        self.idle_timeout = idle_timeout
        self.ca_path, cert, key = make_tls_material(tls_dir)
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        self._ctx.num_tickets = 0  # no post-handshake session tickets for the pump to carry
        self._srv = socket.create_server((host, 0))
        self.port = self._srv.getsockname()[1]
        self.accepted = 0
        self.idle_closes = 0
        self.bad_gateways: collections.Counter[str] = collections.Counter()  # 502s, by path as the relay would see it
        self._lock = threading.Lock()
        self._links: dict[int, list[socket.socket]] = {}  # per connection: client socket (+ upstream)
        self._threads: list[threading.Thread] = []
        self._closed = False

    def client_context(self) -> ssl.SSLContext:
        """What a client of the edge uses: default verification plus this run's CA."""
        return ssl.create_default_context(cafile=str(self.ca_path))

    def start(self) -> "EdgeProxy":
        self._spawn(self._accept_loop)
        return self

    def active(self) -> int:
        with self._lock:
            return len(self._links)

    def close(self) -> None:
        with self._lock:  # after this, no thread starts and no link registers
            self._closed = True
            links = [s for socks in self._links.values() for s in socks]
            threads = list(self._threads)
        _close(self._srv)
        for s in links:
            _close(s)
        for t in threads:
            if t is not threading.current_thread():
                t.join(2)

    def _spawn(self, target, *args) -> bool:
        t = threading.Thread(target=target, args=args, name=f"edge-{target.__name__}", daemon=True)
        with self._lock:  # atomic with close(): every recorded thread is started, none starts after it
            if self._closed:
                return False
            self._threads = [x for x in self._threads if x.is_alive()]
            self._threads.append(t)
            t.start()
        return True

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                # a listener closed by another thread does not reliably wake accept(): poll instead
                if not select.select([self._srv], [], [], TICK)[0]:
                    continue
                raw, peer = self._srv.accept()
            except (OSError, ValueError):  # ValueError: listener closed by close() mid-select
                return
            with self._lock:
                self.accepted += 1
            if not self._spawn(self._serve, raw, peer):
                _close(raw)  # closed meanwhile: nobody else owns this socket
                return

    def _count_idle(self) -> None:
        with self._lock:
            self.idle_closes += 1

    def _track(self, socks: list[socket.socket], index: int, s: socket.socket) -> None:
        """Record a link's socket so close() can end it; raises if close() already ran."""
        with self._lock:
            if self._closed:
                raise OSError("edge closed")
            if index < len(socks):
                socks[index] = s
            else:
                socks.append(s)
            self._links[id(socks)] = socks

    def _serve(self, raw: socket.socket, peer: tuple[str, int]) -> None:
        socks: list[socket.socket] = []
        try:
            self._track(socks, 0, raw)
            raw.settimeout(HANDSHAKE_TIMEOUT)
            client = self._ctx.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            # raw is detached now: track the TLS socket *before* the handshake, so close() can end
            # a client that connected and never sent a ClientHello
            self._track(socks, 0, client)
            client.do_handshake()
            client.settimeout(self.idle_timeout)  # a client silent before its head is idle too
            try:
                head, rest = _read_head(client)
            except socket.timeout:
                self._count_idle()
                return
            except ValueError:
                _respond(client, 400, "Bad Request")
                return
            if head is None:
                return
            try:
                out = rewrite_head(head, peer, self.profile)
            except ValueError:
                _respond(client, 400, "Bad Request")
                return
            except LookupError:
                _respond(client, 404, "Not Found")
                return
            try:
                upstream = socket.create_connection(self.upstream, timeout=CONNECT_TIMEOUT)
            except OSError:
                with self._lock:
                    self.bad_gateways[out.split(b" ", 2)[1].decode("latin-1")] += 1
                _respond(client, 502, "Bad Gateway")
                return
            self._track(socks, 1, upstream)
            upstream.sendall(out + rest)
            self._pump(client, upstream)
        except (OSError, ValueError):  # OSError includes SSLError; ValueError: a socket close() shut mid-select
            pass
        finally:
            with self._lock:
                self._links.pop(id(socks), None)
            for s in socks:
                _close(s)
            if not socks:
                _close(raw)

    def _pump(self, client: ssl.SSLSocket, upstream: socket.socket) -> None:
        """Both directions in one thread that never blocks on a write: a side that stops reading
        stalls only the direction toward it (at most MAX_BUFFERED bytes), never the other one."""
        other = {client: upstream, upstream: client}
        pending = {client: bytearray(), upstream: bytearray()}  # bytes waiting to be written to that socket
        ended: set[socket.socket] = set()
        # a TLS read can need the socket writable, and a TLS write readable (post-handshake records)
        read_wants_write = {client: False, upstream: False}
        write_wants_read = {client: False, upstream: False}
        for s in other:
            s.setblocking(False)
        last = time.monotonic()
        while not self._closed:
            # one side hung up: finish delivering what it sent, then end both (FIN is not forwarded)
            if ended and not any(pending[other[s]] for s in ended):
                return
            room = {s: 0 if s in ended else MAX_BUFFERED - len(pending[other[s]]) for s in other}
            readers = [s for s in other if (room[s] > 0 and not read_wants_write[s]) or write_wants_read[s]]
            writers = [s for s in other if (pending[s] and not write_wants_read[s]) or read_wants_write[s]]
            if room[client] > 0 and client.pending():
                ready = {client}  # decrypted bytes already inside the SSL object are invisible to select
            else:
                readable, writable, _ = select.select(readers, writers, [], TICK)
                ready = set(readable) | set(writable)
            moved = False
            for s in ready:  # retry both operations: either may have been waiting for this readiness
                if pending[s]:
                    try:
                        n = s.send(pending[s][:65536])
                    except (ssl.SSLEOFError, ConnectionError):  # s is gone: what was queued for it is lost
                        pending[s].clear()
                        ended.add(s)
                        continue
                    except ssl.SSLWantReadError:
                        write_wants_read[s] = True
                    except (ssl.SSLWantWriteError, BlockingIOError):
                        write_wants_read[s] = False
                    else:
                        write_wants_read[s] = False
                        del pending[s][:n]
                        moved = moved or n > 0
                if room[s] > 0:
                    try:
                        data = s.recv(min(65536, room[s]))
                    except (ssl.SSLEOFError, ConnectionError):  # abrupt end: still deliver what s sent
                        ended.add(s)
                        continue
                    except ssl.SSLWantWriteError:
                        read_wants_write[s] = True
                    except (ssl.SSLWantReadError, BlockingIOError):  # e.g. a partial TLS record
                        read_wants_write[s] = False
                    else:
                        read_wants_write[s] = False
                        if data:
                            pending[other[s]] += data
                            moved = True
                        else:
                            ended.add(s)
            now = time.monotonic()
            if moved:
                last = now
            elif now - last >= self.idle_timeout:
                self._count_idle()
                return
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd e2e && uv run pytest tests/test_edgeproxy.py -q`
Expected: all pass, in under ~15 s.

Then run the whole e2e suite: `cd e2e && uv run pytest -q`. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add e2e/src/netbridge_e2e/edgeproxy.py e2e/tests/test_edgeproxy.py
git commit -m "Add a TLS edge proxy to the e2e driver"
```

---

### Task 2: Client helpers and relay env for the edge

**Files:**
- Modify: `e2e/src/netbridge_e2e/clients.py`: add `tls_connect`; extend `ws_upgrade` (~line 162) and `http_get` (~line 124)
- Modify: `e2e/src/netbridge_e2e/stack.py`: `Relay.__init__` (~line 72-85)
- Test: `e2e/tests/test_clients.py`, `e2e/tests/test_stack.py`

**Interfaces:**
- Consumes: `EdgeProxy`, `PROFILES` from Task 1 (tests only).
- Produces:
  - `clients.tls_connect(host: str, port: int, ssl_context: ssl.SSLContext, timeout: float = 10.0, server_hostname: str | None = None) -> ssl.SSLSocket` (`server_hostname` defaults to `host`; set it to reach the edge by another address while verifying the cert for `127.0.0.1`)
  - `clients.ws_upgrade(host, port, path, token, timeout=10, *, ssl_context: ssl.SSLContext | None = None, server_hostname: str | None = None, extra_headers: dict[str, str] | None = None) -> tuple[int, str]`. Existing positional callers are unchanged.
  - `clients.http_get(sock, host_header, path="/", timeout=15.0, keep_alive: bool = False) -> tuple[int, bytes]`
  - `stack.Relay(..., extra_env: dict[str, str] | None = None)`, which is merged into the relay's own env and therefore also into the docker `-e` list.

- [ ] **Step 1: Write the failing tests**

Append to `e2e/tests/test_clients.py`:

```python
# TLS through the e2e edge

@pytest.fixture
def ws_edge(tmp_path):
    from netbridge_e2e.edgeproxy import PROFILES, EdgeProxy
    seen = []

    def handler(client):
        req = bytearray()
        while not req.endswith(b"\r\n\r\n"):
            req += client.recv(1)
        seen.append(bytes(req))
        if b"GET /status" in req:
            body = b'{"status": "ok"}'
            client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            client.recv(1)  # keep-alive: wait for the peer to go away
            return
        client.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\n\r\nnope")

    server = _WsServer(handler)
    edge = EdgeProxy(server.address, tmp_path / "edge", PROFILES["traefik"], 5.0).start()
    yield edge, seen
    edge.close()
    server.close()


def test_ws_upgrade_over_tls_with_extra_headers(ws_edge):
    edge, seen = ws_edge
    status, body = clients.ws_upgrade("127.0.0.1", edge.port, "/tunnel", "tok", ssl_context=edge.client_context(),
                                      extra_headers={"X-Forwarded-For": "198.51.100.7"})
    assert (status, body) == (401, "nope")
    assert b"X-Forwarded-For: 198.51.100.7, 127.0.0.1\r\n" in seen[0]
    assert b"Authorization: Bearer tok\r\n" in seen[0]


def test_tls_connect_refuses_an_untrusted_edge(ws_edge):
    edge, _ = ws_edge
    with pytest.raises(ssl.SSLCertVerificationError):
        clients.tls_connect("127.0.0.1", edge.port, ssl.create_default_context())


def test_tls_connect_verifies_the_given_server_hostname(ws_edge):
    edge, _ = ws_edge
    with pytest.raises(ssl.SSLCertVerificationError):  # not a SAN of the edge's cert
        clients.tls_connect("127.0.0.1", edge.port, edge.client_context(), server_hostname="example.test")
    clients.tls_connect("127.0.0.1", edge.port, edge.client_context(), server_hostname="localhost").close()


def test_http_get_keep_alive_leaves_the_connection_open(ws_edge):
    edge, seen = ws_edge
    with clients.tls_connect("127.0.0.1", edge.port, edge.client_context()) as s:
        status, body = clients.http_get(s, f"127.0.0.1:{edge.port}", "/status", keep_alive=True)
        assert (status, body) == (200, b'{"status": "ok"}')
        assert not clients.wait_closed(s, 0.5)
    assert b"Connection: keep-alive\r\n" in seen[0]
```

Add `import ssl` to the imports at the top of `test_clients.py` if it is missing.

Append to `e2e/tests/test_stack.py`:

```python
def test_relay_extra_env_reaches_process_and_container(tmp_path, monkeypatch):
    extra = {"RELAY_TRUSTED_PROXIES": "127.0.0.1/32", "RELAY_CLIENT_IP_HEADER": "X-Forwarded-For"}
    seen = captured_argv(monkeypatch)
    r = stack.Relay(tmp_path, 1, blocked_port=2, env={}, extra_env=extra)
    assert extra.items() <= r._env.items()
    monkeypatch.setattr(stack.Relay, "_remove_container", lambda self: None)
    stack.Relay(tmp_path, 1, blocked_port=2, env={}, image="img", extra_env=extra).start()
    assert "RELAY_TRUSTED_PROXIES=127.0.0.1/32" in seen["relay"]
    assert "RELAY_CLIENT_IP_HEADER=X-Forwarded-For" in seen["relay"]


def test_relay_without_extra_env_trusts_no_proxy(tmp_path):
    r = stack.Relay(tmp_path, 1, blocked_port=2, env={})
    assert "RELAY_TRUSTED_PROXIES" not in r._env
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd e2e && uv run pytest tests/test_clients.py tests/test_stack.py -q -k "tls or extra_env or keep_alive or trusts_no_proxy"`
Expected: FAIL. You should see `TypeError: ws_upgrade() got an unexpected keyword argument 'ssl_context'`, `AttributeError: ... 'tls_connect'`, and `TypeError: ... unexpected keyword argument 'extra_env'`.

- [ ] **Step 3: Implement**

In `clients.py`, add `import ssl` to the imports. Add this after `recv_exact`:

```python
def tls_connect(host: str, port: int, ssl_context: ssl.SSLContext, timeout: float = 10.0,
                server_hostname: str | None = None) -> ssl.SSLSocket:
    """TCP + TLS handshake, verifying the peer for server_hostname (default: host) with ssl_context."""
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        return ssl_context.wrap_socket(raw, server_hostname=server_hostname or host)
    except BaseException:
        raw.close()
        raise
```

Replace `http_get` with:

```python
def http_get(sock: socket.socket, host_header: str, path: str = "/", timeout: float = 15.0,
             keep_alive: bool = False) -> tuple[int, bytes]:
    """GET over an already-established tunnel (keep_alive: the server may hold the connection open)."""
    conn = "keep-alive" if keep_alive else "close"
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: {conn}\r\n\r\n".encode())
    return _read_response(sock, timeout)
```

In `ws_upgrade`, change the signature and the first lines, and add the extra headers after the Authorization header:

```python
def ws_upgrade(host: str, port: int, path: str, token: str | None, timeout: float = 10, *,
               ssl_context: ssl.SSLContext | None = None, server_hostname: str | None = None,
               extra_headers: dict[str, str] | None = None) -> tuple[int, str]:
    """WebSocket upgrade with `Authorization: Bearer <token>` (none if token is None), over TLS if
    ssl_context is given. Returns (status, body up to 4 KiB); closes the connection."""
    deadline = time.monotonic() + timeout
    if ssl_context is not None:
        sock = tls_connect(host, port, ssl_context, timeout, server_hostname)
    else:
        sock = socket.create_connection((host, port), timeout=timeout)
    try:
        ...  # unchanged up to the Authorization header
        if token:
            headers.append(f"Authorization: Bearer {token}")
        headers.extend(f"{k}: {v}" for k, v in (extra_headers or {}).items())
        headers.append("")
        headers.append("")
        ...  # unchanged
```

In `stack.py`, change `Relay.__init__` like this:

```python
    def __init__(self, logs_dir: Path, port: int, blocked_port: int, env: dict, image: str | None = None, cov=None,
                 auth: "AuthStub | None" = None, extra_env: dict[str, str] | None = None):
        ...
        self._relay_env = dict(auth_env, RELAY_BLOCKED_PORTS=str(blocked_port), **FAULT_TUNING, **(extra_env or {}))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd e2e && uv run pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add e2e/src/netbridge_e2e/clients.py e2e/src/netbridge_e2e/stack.py e2e/tests/test_clients.py e2e/tests/test_stack.py
git commit -m "Let e2e clients speak TLS and pass extra relay env"
```

---

### Task 3: Journey wiring and the six edge steps

**Files:**
- Modify: `e2e/src/netbridge_e2e/journey.py`: imports, constants, `_journey` (~lines 172-232), new methods next to `_auth_flood`, `parse_args` (~848-875)
- Create: `e2e/tests/test_journey_edge.py`
- Modify: `e2e/README.md`

**Interfaces:**
- Consumes:
  - From Task 1: `EdgeProxy`, `PROFILES`, `RELAY_ENV`.
  - From Task 2: `clients.tls_connect`, `clients.ws_upgrade(..., ssl_context=, extra_headers=)`, `clients.http_get(..., keep_alive=)`, `Relay(..., extra_env=)`.
- Produces:
  - CLI flags `--edge` and `--edge-profile {arr,traefik}`. After parsing, `args.edge_profile` is always set when `--edge` is given.
  - Steps `edge_up`, `edge_appends_peer`, `edge_client_ip`, `edge_idle_survives`, `edge_idle_closes_dead_link`, `edge_relay_down_502`.

Where the steps run:
- `edge_up` and `edge_client_ip` run right after `auth_matrix`, before `fault_links_up`.
- `edge_idle_survives` runs right after `_traffic` (both tunnels are proven working, so the quiet period is the only variable).
- `edge_idle_closes_dead_link` runs right after `edge_idle_survives`.

- [ ] **Step 1: Write the failing tests**

`e2e/tests/test_journey_edge.py`:

```python
"""The journey's edge steps against fakes: no relay, no edge sockets."""
import re
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from netbridge_e2e import journey
from netbridge_e2e.edgeproxy import PROFILES
from netbridge_e2e.stack import FAULT_TUNING

CAP = int(FAULT_TUNING["RELAY_RATE_IP_CONNECTIONS_PER_MIN"])


@pytest.fixture
def j(tmp_path):
    return journey.Journey(journey.parse_args(["--mode", "source", "--work", str(tmp_path), "--edge"]))


def fake_edge(profile="arr", idle=0.0):
    return SimpleNamespace(port=4443, profile=PROFILES[profile], idle_timeout=idle, idle_closes=0,
                           bad_gateways=Counter(), ca_path=Path("ca.pem"), client_context=lambda: "CTX")


class Logs:
    def __init__(self, text=""):
        self._text = text

    def mark(self):
        return None

    def wait_for(self, pattern, timeout, since=None, alive=None):
        return re.search(pattern, self._text)

    def text(self, since=None):
        return self._text

    def tail(self, n=1500):
        return self._text[-n:]


class Stub:
    def mint(self, **kw):
        return "valid-token"


# --- arguments -----------------------------------------------------------

def test_edge_profile_defaults_to_traefik_in_source_mode(tmp_path):
    assert journey.parse_args(["--mode", "source", "--edge"]).edge_profile == "traefik"


def test_edge_profile_override(tmp_path):
    assert journey.parse_args(["--mode", "source", "--edge", "--edge-profile", "arr"]).edge_profile == "arr"


def test_edge_profile_needs_edge(capsys):
    with pytest.raises(SystemExit):
        journey.parse_args(["--mode", "source", "--edge-profile", "arr"])
    assert "--edge-profile needs --edge" in capsys.readouterr().err


def test_no_edge_by_default():
    a = journey.parse_args(["--mode", "source"])
    assert a.edge is False and a.edge_profile is None


def test_exe_mode_defaults_to_the_arr_profile():
    assert journey.EDGE_DEFAULT_PROFILE == {"source": "traefik", "exe": "arr"}


# --- client env ----------------------------------------------------------

def test_edge_client_env_forces_verification_with_the_run_ca(j):
    env = {"NETBRIDGE_VERIFY_SSL": "false", "NETBRIDGE_ALLOW_INSECURE": "1", "OTHER": "x"}
    j._edge_client_env(env, fake_edge())
    assert env == {"NETBRIDGE_CA_BUNDLE": "ca.pem", "NETBRIDGE_VERIFY_SSL": "true", "OTHER": "x"}


# --- client urls ---------------------------------------------------------

def test_client_urls_plain_without_edge(j):
    links = SimpleNamespace(url="ws://127.0.0.1:1", port=1), SimpleNamespace(url="ws://127.0.0.1:2", port=2)
    assert j._client_urls(*links, None) == ("ws://127.0.0.1:1", "ws://127.0.0.1:2")


@pytest.mark.parametrize("profile, prefix", [("traefik", ""), ("arr", "/netbridge")])
def test_client_urls_through_the_edge(j, profile, prefix):
    links = SimpleNamespace(url="ws://127.0.0.1:1", port=1), SimpleNamespace(url="ws://127.0.0.1:2", port=2)
    assert j._client_urls(*links, fake_edge(profile)) == (f"wss://127.0.0.1:1{prefix}/ws",
                                                          f"wss://127.0.0.1:2{prefix}/tunnel")


# --- edge_up -------------------------------------------------------------

def tls_fakes(monkeypatch, status=200, closed=True, on_wait=None):
    seen = {}

    @contextmanager
    def tls_connect(host, port, ctx, timeout=10.0):
        seen["connect"] = (host, port, ctx)
        yield "SOCK"

    def http_get(sock, host_header, path="/", timeout=15.0, keep_alive=False):
        seen.setdefault("gets", []).append((path, keep_alive))
        return status, b"{}"

    def wait_closed(sock, timeout):
        seen["wait"] = timeout
        if on_wait:
            on_wait()
        return closed

    monkeypatch.setattr(journey.clients, "tls_connect", tls_connect)
    monkeypatch.setattr(journey.clients, "http_get", http_get)
    monkeypatch.setattr(journey.clients, "wait_closed", wait_closed)
    return seen


def test_edge_status_uses_the_prefix_and_the_run_ca(j, monkeypatch):
    seen = tls_fakes(monkeypatch)
    ok, detail = j._edge_status(fake_edge("arr"))
    assert ok and seen["connect"] == ("127.0.0.1", 4443, "CTX") and seen["gets"] == [("/netbridge/status", False)]
    assert "HTTP 200" in detail and "arr" in detail


def test_edge_status_fails_on_non_200(j, monkeypatch):
    tls_fakes(monkeypatch, status=502)
    ok, detail = j._edge_status(fake_edge())
    assert not ok and "HTTP 502" in detail


# --- edge_client_ip ------------------------------------------------------

def fake_upgrades(monkeypatch, throttle_after=CAP, other=401, valid=101):
    calls = []
    count = {"bad": 0}

    def ws_upgrade(host, port, path, token, timeout=10, *, ssl_context=None, server_hostname=None,
                   extra_headers=None):
        entries = [e.strip() for e in extra_headers["X-Forwarded-For"].split(",")]
        assert entries[0] == journey.EDGE_SPOOF  # every request carries the spoofed leftmost entry
        client = entries[-1]
        calls.append((path, token, client, ssl_context))
        if token == "valid-token":
            return valid, ""
        if client == journey.EDGE_OTHER_CLIENT:
            return other, "Token validation failed"
        count["bad"] += 1
        return (429, "Too many") if count["bad"] > throttle_after else (401, "Token validation failed")

    monkeypatch.setattr(journey.clients, "ws_upgrade", ws_upgrade)
    return calls


def relay_with(text):
    return SimpleNamespace(logs=Logs(text))


LOGGED = f"Tunnel auth rejected for {journey.EDGE_CLIENT}: bad token"


def test_edge_client_ip_passes(j, monkeypatch):
    calls = fake_upgrades(monkeypatch)
    ok, detail = j._edge_client_ip(fake_edge("arr"), relay_with(LOGGED), Stub())
    assert ok, detail
    assert all(path == "/netbridge/tunnel" and ctx == "CTX" for path, _, _, ctx in calls)
    assert f"429 after {CAP + 1}" in detail
    assert calls[-2][2] == journey.EDGE_OTHER_CLIENT and calls[-1][1:3] == ("valid-token", journey.EDGE_CLIENT)


def test_edge_client_ip_needs_the_forwarded_ip_in_the_log(j, monkeypatch):
    fake_upgrades(monkeypatch)
    ok, detail = j._edge_client_ip(fake_edge(), relay_with("Tunnel auth rejected for 127.0.0.1: x"), Stub())
    assert not ok and "missing" in detail


def test_edge_client_ip_needs_a_429(j, monkeypatch):
    fake_upgrades(monkeypatch, throttle_after=10_000)
    ok, detail = j._edge_client_ip(fake_edge(), relay_with(LOGGED), Stub())
    assert not ok and f"within {CAP + 10}" in detail


@pytest.mark.parametrize("other, valid", [(429, 101), (401, 429)])
def test_edge_client_ip_buckets_are_per_forwarded_client(j, monkeypatch, other, valid):
    fake_upgrades(monkeypatch, other=other, valid=valid)
    ok, _ = j._edge_client_ip(fake_edge(), relay_with(LOGGED), Stub())
    assert not ok


# --- edge_appends_peer ---------------------------------------------------

def test_edge_appends_peer_passes(j, monkeypatch):
    calls = []

    def ws_upgrade(host, port, path, token, timeout=10, *, ssl_context=None, server_hostname=None,
                   extra_headers=None):
        calls.append((host, path, server_hostname, extra_headers))
        return 401, "Token validation failed"

    monkeypatch.setattr(journey.clients, "ws_upgrade", ws_upgrade)
    ok, detail = j._edge_appends_peer(fake_edge("arr"), relay_with("Tunnel auth rejected for 10.0.0.1: x"), "10.0.0.1")
    assert ok, detail
    assert calls == [("10.0.0.1", "/netbridge/tunnel", "127.0.0.1", {"X-Forwarded-For": journey.EDGE_SPOOF})]


@pytest.mark.parametrize("log", [
    "Tunnel auth rejected for 127.0.0.1: x",                                        # edge address, not the peer
    f"Tunnel auth rejected for 10.0.0.1: x\nTunnel auth rejected for {journey.EDGE_SPOOF}: x",  # spoof honoured
])
def test_edge_appends_peer_fails(j, monkeypatch, log):
    monkeypatch.setattr(journey.clients, "ws_upgrade", lambda *a, **k: (401, ""))
    ok, _ = j._edge_appends_peer(fake_edge(), relay_with(log), "10.0.0.1")
    assert not ok


def test_edge_appends_peer_needs_a_non_loopback_host(j):
    ok, detail = j._edge_appends_peer(fake_edge(), relay_with(""), "127.0.0.1")
    assert not ok and "loopback" in detail


# --- edge_relay_down_502 ------------------------------------------------

AGENT_502 = "ERROR Handshake failed: 502 Invalid response status\n"
PROXY_502 = "ERROR Reconnection failed: WebSocket handshake failed (502): Invalid response status\n"
MARKS = {"agent": None, "proxy": None}


def test_edge_relay_down_sees_both_clients(j, monkeypatch):
    edge = fake_edge()
    edge.bad_gateways.update({"/ws": 3})  # earlier 502s do not count
    agent, proxy = SimpleNamespace(name="agent", logs=Logs()), SimpleNamespace(name="proxy", logs=Logs())

    def sleep(_):
        edge.bad_gateways.update({"/ws": 1, "/tunnel": 1})
        agent.logs, proxy.logs = Logs(AGENT_502), Logs(PROXY_502)

    monkeypatch.setattr(journey.time, "sleep", sleep)
    ok, detail = j._edge_relay_down(edge, agent, proxy, MARKS)
    assert ok and "agent (/ws) 1, proxy (/tunnel) 1" in detail and "agent True, proxy True" in detail


def test_edge_relay_down_fails_without_the_proxy(j, monkeypatch):
    edge = fake_edge()
    agent, proxy = SimpleNamespace(name="agent", logs=Logs(AGENT_502)), SimpleNamespace(name="proxy", logs=Logs())
    monkeypatch.setattr(journey, "EDGE_502_WAIT", 0.2)
    monkeypatch.setattr(journey.time, "sleep", lambda _: edge.bad_gateways.update({"/ws": 1}))
    ok, detail = j._edge_relay_down(edge, agent, proxy, MARKS)
    assert not ok and "proxy (/tunnel) 0" in detail


def test_edge_relay_down_fails_when_a_client_never_saw_the_502(j, monkeypatch):
    edge = fake_edge()
    agent = SimpleNamespace(name="agent", logs=Logs(AGENT_502))
    proxy = SimpleNamespace(name="proxy", logs=Logs("ERROR Reconnection failed: Connection failed: reset\n"))
    monkeypatch.setattr(journey, "EDGE_502_WAIT", 0.2)
    # the edge counts both 502s, but the proxy's response was lost to a reset
    monkeypatch.setattr(journey.time, "sleep", lambda _: edge.bad_gateways.update({"/ws": 1, "/tunnel": 1}))
    ok, detail = j._edge_relay_down(edge, agent, proxy, MARKS)
    assert not ok and "agent True, proxy False" in detail


def test_handshake_502_pattern_matches_both_clients():
    assert re.search(journey.HANDSHAKE_502, AGENT_502) and re.search(journey.HANDSHAKE_502, PROXY_502)
    assert not re.search(journey.HANDSHAKE_502, "Handshake failed: 401 Invalid response status")


# --- idle ----------------------------------------------------------------

def comp(name, sessions=1):
    return SimpleNamespace(name=name, logs=Logs("Connected to relay (session: abc)\n" * sessions))


def test_edge_idle_survives(j, monkeypatch):
    monkeypatch.setattr(journey.time, "sleep", lambda s: None)
    echoes = []
    monkeypatch.setattr(j, "_open_echo", lambda ip, t: echoes.append(1) or SimpleNamespace(close=lambda: None))
    ok, detail = j._edge_idle(fake_edge(idle=25.0), comp("agent"), comp("proxy"), "10.0.0.1", None)
    assert ok, detail
    assert echoes == [1] and "quiet for 30s" in detail


def test_edge_idle_fails_when_the_edge_closed_a_tunnel(j, monkeypatch):
    edge = fake_edge(idle=25.0)
    monkeypatch.setattr(journey.time, "sleep", lambda s: setattr(edge, "idle_closes", 1))
    monkeypatch.setattr(j, "_open_echo", lambda ip, t: SimpleNamespace(close=lambda: None))
    ok, detail = j._edge_idle(edge, comp("agent"), comp("proxy"), "10.0.0.1", None)
    assert not ok and "0->1" in detail


def test_edge_idle_fails_on_a_new_session(j, monkeypatch):
    agent = comp("agent")
    monkeypatch.setattr(journey.time, "sleep",
                        lambda s: setattr(agent, "logs", Logs("Connected to relay (session: abc)\n" * 2)))
    monkeypatch.setattr(j, "_open_echo", lambda ip, t: SimpleNamespace(close=lambda: None))
    ok, _ = j._edge_idle(fake_edge(idle=25.0), agent, comp("proxy"), "10.0.0.1", None)
    assert not ok


def test_dead_link_closed_by_the_edge(j, monkeypatch):
    edge = fake_edge("traefik", idle=0.0)
    seen = tls_fakes(monkeypatch, on_wait=lambda: setattr(edge, "idle_closes", 1))
    ok, detail = j._edge_dead_link(edge)
    assert ok, detail
    assert seen["gets"] == [("/status", True)] and seen["wait"] == 5.0


def test_dead_link_fails_when_nothing_closes_it(j, monkeypatch):
    tls_fakes(monkeypatch, closed=False)
    ok, _ = j._edge_dead_link(fake_edge(idle=0.0))
    assert not ok


def test_dead_link_fails_when_the_edge_did_not_count_it(j, monkeypatch):
    tls_fakes(monkeypatch)  # closed, but by someone else: the counter stays at 0
    ok, detail = j._edge_dead_link(fake_edge(idle=0.0))
    assert not ok and "counted 0" in detail
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd e2e && uv run pytest tests/test_journey_edge.py -q`
Expected: FAIL with `error: unrecognized arguments: --edge` / `AttributeError: ... '_client_urls'` / `... 'EDGE_CLIENT'`.

- [ ] **Step 3: Implement the arguments, constants and step methods**

In `journey.py`:

1. Update the module docstring. After the `install → connect ...` paragraph, add:

```
With --edge, both clients reach the relay through a TLS reverse proxy (edgeproxy.py):
client --wss--> fault proxy --> edge --ws--> relay; the relay trusts the edge's
X-Forwarded-For, and six edge steps prove client IP, relay-down and idle behaviour.
```

2. Imports: add `from .edgeproxy import PROFILES, RELAY_ENV, EdgeProxy`.

3. Constants, after `PENTEST_TIMEOUT`:

```python
EDGE_DEFAULT_PROFILE = {"source": "traefik", "exe": "arr"}
EDGE_IDLE_TIMEOUT = 25.0  # vs 10 s heartbeats: more than two missed beats of margin
EDGE_CLIENT = "198.51.100.7"  # TEST-NET-2: stands in for the upstream hop that wrote X-Forwarded-For
EDGE_OTHER_CLIENT = "198.51.100.8"
EDGE_SPOOF = "203.0.113.9"  # TEST-NET-3: a client's own, untrustworthy X-Forwarded-For entry
EDGE_IP_USER = "edge-ip@netbridge.test"
EDGE_502_WAIT = 30.0  # both clients retry within it: the reconnect backoff starts at 5 s (+30 % jitter)
# aiohttp's WSServerHandshakeError, as each client logs it: the agent "Handshake failed: 502 Invalid response
# status", the proxy "WebSocket handshake failed (502): Invalid response status"
HANDSHAKE_502 = r"[Hh]andshake failed\W{1,3}502\b"
```

4. New methods, placed right after `_auth_flood`:

```python
    # --- the edge ----------------------------------------------------------

    def _edge_up(self, relay: Relay, stub: AuthStub, env: dict, ip: str) -> EdgeProxy:
        # all interfaces: edge_appends_peer reaches the edge from the host's own (untrusted) address
        edge = EdgeProxy(("127.0.0.1", relay.port), self.work / "edge", PROFILES[self.args.edge_profile],
                         EDGE_IDLE_TIMEOUT, host="0.0.0.0")
        self.cleanups.append(edge.close)
        edge.start()
        self._edge_client_env(env, edge)
        self.check("edge_up", lambda: self._edge_status(edge))
        self.check("edge_appends_peer", lambda: self._edge_appends_peer(edge, relay, ip))
        self.check("edge_client_ip", lambda: self._edge_client_ip(edge, relay, stub))
        return edge

    @staticmethod
    def _edge_client_env(env: dict, edge: EdgeProxy) -> None:
        """Clients verify the edge with the run's CA, and nothing inherited may switch verification off:
        a run with NETBRIDGE_VERIFY_SSL=false + NETBRIDGE_ALLOW_INSECURE=1 would pass without the CA."""
        env["NETBRIDGE_CA_BUNDLE"] = str(edge.ca_path)
        env["NETBRIDGE_VERIFY_SSL"] = "true"
        env.pop("NETBRIDGE_ALLOW_INSECURE", None)

    def _client_urls(self, agent_link: FaultProxy, proxy_link: FaultProxy, edge: EdgeProxy | None) -> tuple[str, str]:
        if edge is None:
            return agent_link.url, proxy_link.url
        prefix = edge.profile.prefix  # an explicit path: the clients keep it as given
        return f"wss://127.0.0.1:{agent_link.port}{prefix}/ws", f"wss://127.0.0.1:{proxy_link.port}{prefix}/tunnel"

    def _edge_status(self, edge: EdgeProxy) -> tuple[bool, str]:
        url = f"https://127.0.0.1:{edge.port}{edge.profile.prefix}/status"
        with clients.tls_connect("127.0.0.1", edge.port, edge.client_context()) as s:
            status, _ = clients.http_get(s, f"127.0.0.1:{edge.port}", f"{edge.profile.prefix}/status")
        return status == 200, f"{url} via edge ({edge.profile.name}, verified with {edge.ca_path.name}): HTTP {status}"

    def _edge_appends_peer(self, edge: EdgeProxy, relay: Relay, ip: str) -> tuple[bool, str]:
        """A client the edge sees directly is keyed on its own address, whatever X-Forwarded-For it sends:
        proves the edge appends its peer and the relay ignores what the client wrote."""
        if ip.startswith("127."):
            return False, f"host address {ip} is loopback, which the relay trusts: it cannot play a direct client"
        mark = relay.logs.mark()
        status, _ = clients.ws_upgrade(ip, edge.port, f"{edge.profile.prefix}/tunnel", "not-a-jwt",
                                       ssl_context=edge.client_context(), server_hostname="127.0.0.1",
                                       extra_headers={"X-Forwarded-For": EDGE_SPOOF})
        logged = relay.logs.wait_for(rf"Tunnel auth rejected for {re.escape(ip)}:", 5, since=mark)
        spoofed = EDGE_SPOOF in relay.logs.text(since=mark)
        ok = status == 401 and logged is not None and not spoofed
        return ok, (f"bad token from {ip} via edge, claiming X-Forwarded-For {EDGE_SPOOF}: HTTP {status} (want 401); "
                    f"relay line naming {ip}: {'found' if logged else 'missing'}; "
                    f"spoofed address in relay log: {'yes' if spoofed else 'no'}")

    def _edge_client_ip(self, edge: EdgeProxy, relay: Relay, stub: AuthStub) -> tuple[bool, str]:
        """Behind a trusted hop, failed auth is keyed on the rightmost untrusted X-Forwarded-For entry:
        here the client-supplied list stands in for an upstream proxy, after a spoofed leftmost entry."""
        ctx = edge.client_context()
        path = f"{edge.profile.prefix}/tunnel"

        def upgrade(client_ip: str, token: str) -> tuple[int, str]:
            # a relay that took the leftmost entry would put every request in EDGE_SPOOF's bucket
            return clients.ws_upgrade("127.0.0.1", edge.port, path, token, ssl_context=ctx,
                                      extra_headers={"X-Forwarded-For": f"{EDGE_SPOOF}, {client_ip}"})

        mark = relay.logs.mark()
        first = upgrade(EDGE_CLIENT, "not-a-jwt")
        logged = relay.logs.wait_for(rf"Tunnel auth rejected for {re.escape(EDGE_CLIENT)}:", 5, since=mark)
        if first[0] != 401 or logged is None:
            return False, (f"bad token from {EDGE_CLIENT} via edge: HTTP {first[0]}; relay line naming it "
                           f"{'found' if logged else 'missing'}: ...{relay.logs.tail(300)!r}")
        cap = int(FAULT_TUNING["RELAY_RATE_IP_CONNECTIONS_PER_MIN"]) + 10
        throttled_at, last = None, first
        for attempt in range(2, cap + 1):
            last = upgrade(EDGE_CLIENT, "not-a-jwt")
            if last[0] == 429:
                throttled_at = attempt
                break
        if throttled_at is None:
            return False, f"no 429 for {EDGE_CLIENT} within {cap} bad-token upgrades via edge; last {last}"
        other = upgrade(EDGE_OTHER_CLIENT, "not-a-jwt")
        valid = upgrade(EDGE_CLIENT, stub.mint(upn=EDGE_IP_USER))
        ok = other[0] == 401 and valid[0] == 101
        return ok, (f"relay logged {EDGE_CLIENT}; 429 after {throttled_at} bad tokens from it via edge; "
                    f"bad token from {EDGE_OTHER_CLIENT}: HTTP {other[0]} (want 401); "
                    f"valid token from {EDGE_CLIENT}: HTTP {valid[0]} (want 101)")

    def _edge_idle(self, edge: EdgeProxy, agent, proxy, ip: str, targets: Targets) -> tuple[bool, str]:
        """No user traffic for idle_timeout + 5 s: heartbeats alone must keep both tunnels open."""
        def sessions():
            return tuple(len(re.findall(RELAY_SESSION, c.logs.text())) for c in (agent, proxy))

        quiet = edge.idle_timeout + 5
        closes, before = edge.idle_closes, sessions()
        time.sleep(quiet)
        closes_after, after = edge.idle_closes, sessions()
        self._open_echo(ip, targets).close()  # raises if the tunnel is gone
        ok = closes_after == closes and after == before
        return ok, (f"quiet for {quiet:.0f}s (edge idle timeout {edge.idle_timeout:.0f}s, heartbeats 10s): "
                    f"edge idle closes {closes}->{closes_after}, relay sessions agent/proxy {before}->{after}; "
                    f"echo round trip ok")

    def _edge_relay_down(self, edge: EdgeProxy, agent, proxy, marks: dict) -> tuple[bool, str]:
        """With the relay stopped, both clients retry through the edge and get its 502, then must recover
        (the reconnect step that follows proves the recovery). The edge's counter says it answered 502;
        each client's own log line says the 502 reached it (a reset would log something else)."""
        paths = ("/ws", "/tunnel")  # as the relay would see them: the edge has stripped any prefix
        before = {p: edge.bad_gateways[p] for p in paths}

        def logged():
            return {c.name: re.search(HANDSHAKE_502, c.logs.text(since=marks[c.name])) is not None
                    for c in (agent, proxy)}

        deadline = time.monotonic() + EDGE_502_WAIT
        while time.monotonic() < deadline and not (all(edge.bad_gateways[p] > before[p] for p in paths)
                                                   and all(logged().values())):
            time.sleep(0.5)
        seen, heard = {p: edge.bad_gateways[p] - before[p] for p in paths}, logged()
        return all(seen.values()) and all(heard.values()), (
            f"502s from the edge while the relay was down: agent (/ws) {seen['/ws']}, proxy (/tunnel) "
            f"{seen['/tunnel']}; logged by the client: agent {heard[agent.name]}, proxy {heard[proxy.name]}; "
            f"within {EDGE_502_WAIT:.0f}s")

    def _edge_dead_link(self, edge: EdgeProxy) -> tuple[bool, str]:
        """Counter-proof: a kept-alive HTTPS connection with no traffic is closed by the edge's idle timer."""
        before = edge.idle_closes
        with clients.tls_connect("127.0.0.1", edge.port, edge.client_context()) as s:
            status, _ = clients.http_get(s, f"127.0.0.1:{edge.port}", f"{edge.profile.prefix}/status",
                                         keep_alive=True)
            start = time.monotonic()
            closed = clients.wait_closed(s, edge.idle_timeout + 5)
            took = time.monotonic() - start
        counted = edge.idle_closes - before
        # the relay's own keep-alive timeout is 75 s: a close this early is the edge's
        ok = status == 200 and closed and took >= edge.idle_timeout - 1 and counted >= 1
        return ok, (f"HTTP {status} kept alive, then {'closed' if closed else 'still open'} after {took:.1f}s "
                    f"of silence (idle timeout {edge.idle_timeout:.0f}s); edge counted {counted} idle close(s)")
```

5. `parse_args`: add these after `--coverage`:

```python
    p.add_argument("--edge", action="store_true",
                   help="clients reach the relay through a TLS reverse proxy (wss://, run CA, X-Forwarded-For)")
    p.add_argument("--edge-profile", choices=sorted(PROFILES),
                   help="edge behaviour: traefik (bare-IP X-Forwarded-For) or arr (ip:port, /netbridge prefix); "
                        "default traefik in source mode, arr in exe mode")
```

and add this after `args = p.parse_args(argv)`:

```python
    if args.edge_profile and not args.edge:
        p.error("--edge-profile needs --edge")
    if args.edge and not args.edge_profile:
        args.edge_profile = EDGE_DEFAULT_PROFILE[args.mode]
```

- [ ] **Step 4: Run the new tests**

Run: `cd e2e && uv run pytest tests/test_journey_edge.py -q`
Expected: all pass.

- [ ] **Step 5: Wire the edge into `_journey`**

Replace the `relay = Relay(...)` line with:

```python
        relay = Relay(logs, a.relay_port, targets.blocked_port, env, image=a.relay_image, cov=self.cov, auth=stub,
                      extra_env=RELAY_ENV if a.edge else None)
```

Replace the block from `agent_link = FaultProxy(...)` through `agent, proxy = self._components(...)` with:

```python
        edge = self._edge_up(relay, stub, env, ip) if a.edge else None
        upstream = ("127.0.0.1", edge.port if edge else relay.port)
        agent_link = FaultProxy(upstream, "agent")
        self.cleanups.append(agent_link.close)
        proxy_link = FaultProxy(upstream, "proxy")
        self.cleanups.append(proxy_link.close)
        for link in (agent_link, proxy_link):
            link.start()
        via = f" -> edge :{edge.port} ({edge.profile.name})" if edge else ""
        self.step("fault_links_up", True, f"agent via :{agent_link.port}, proxy via :{proxy_link.port}{via}")

        agent_url, proxy_url = self._client_urls(agent_link, proxy_link, edge)
        agent, proxy = self._components(agent_url, proxy_url, ip, targets, env)
```

Replace `self._traffic(ip, targets, relay)` with:

```python
        self._traffic(ip, targets, relay)
        if edge:
            self.check("edge_idle_survives", lambda: self._edge_idle(edge, agent, proxy, ip, targets))
            self.check("edge_idle_closes_dead_link", lambda: self._edge_dead_link(edge))
```

Replace `self._reconnect(relay, agent, proxy, ip, targets)` with `self._reconnect(relay, agent, proxy, ip, targets, edge)`. In `_reconnect`, change the signature and replace the fixed `time.sleep(3)` while the relay is down:

```python
    def _reconnect(self, relay: Relay, agent, proxy, ip: str, targets: Targets, edge: EdgeProxy | None = None) -> None:
        marks = {agent.name: agent.logs.mark(), proxy.name: proxy.logs.mark()}
        relay.stop()
        if edge:  # hold the relay down until both clients have met the edge's 502
            self.check("edge_relay_down_502", lambda: self._edge_relay_down(edge, agent, proxy, marks))
        else:
            time.sleep(3)
        relay.start()
        ...  # unchanged
```

- [ ] **Step 6: Update `e2e/README.md`**

Add a row to the mode table:

```
| `… --edge` | as the mode it is added to, but both clients connect over `wss://` through an in-process TLS reverse proxy (the edge) that appends `X-Forwarded-For`, can strip a path prefix and closes idle links; the relay trusts it via `RELAY_TRUSTED_PROXIES` | CI job `e2e-edge` (source, `traefik` profile) and `e2e-windows.yml` (exe, `arr` profile) |
```

After the `--coverage` paragraph, add:

```
Add `--edge` to put the edge in front of the relay. It is generic rather than any particular product, so its
behaviours come from a profile: `--edge-profile traefik` (bare-IP X-Forwarded-For, no prefix; the default in
source mode) or `arr` (`ip:port` like Azure App Service, relay mounted under `/netbridge`; the default in exe
mode). The edge's CA is generated for the run (`<work>/edge/ca.pem`) and handed to the clients through
`NETBRIDGE_CA_BUNDLE`. Verification stays on. The driver's probes, the auth matrix and the pentest suite
still talk to the relay directly.
```

In the Steps line, insert `→ (with --edge) edge_up → edge_appends_peer → edge_client_ip` after `auth_matrix (...)`, `→ (with --edge) edge_idle_survives → edge_idle_closes_dead_link` after `concurrency (20 simultaneous streams)`, and `(with --edge) edge_relay_down_502 →` before `relay_restarted`.

- [ ] **Step 7: Run the e2e unit suite, then the journey locally**

Run: `cd e2e && uv run pytest -q`
Expected: all pass.

Run these from the repo root (Linux). Each takes about 10 min:

```bash
set -o pipefail  # the exit status is the journey's, not tail's
for p in relay netbridge-agent socks-proxy security-tests e2e; do (cd "$p" && uv sync -q); done
uv run --project e2e python -m netbridge_e2e --mode source --edge --work /tmp/nb-e2e-edge 2>&1 | tail -n 60
uv run --project e2e python -m netbridge_e2e --mode source --edge --edge-profile arr --work /tmp/nb-e2e-arr 2>&1 | tail -n 60
uv run --project e2e python -m netbridge_e2e --mode source --work /tmp/nb-e2e-plain 2>&1 | tail -n 15
```

Expected: every step ✓ in all three runs. In the edge runs, the six `edge_*` steps appear and `fault_links_up` names the edge. The plain run shows no `edge_*` step.

If an existing step fails only under `--edge`, find out which hop is at fault before touching anything. Check the edge (with a unit test that reproduces it), the driver, or the product. A product-side cause is a compatibility finding (Global Constraints): record it, stop the task, and report. Never weaken a step to make it pass. Steps that are likely to show such findings:
- `reconnect`, because the edge answers `502` while the relay is down
- `agent_blackhole_detected`, because the edge closes the relay side after 25 s of silence

- [ ] **Step 8: Commit**

```bash
git add e2e/src/netbridge_e2e/journey.py e2e/tests/test_journey_edge.py e2e/README.md
git commit -m "Run the e2e journey behind the TLS edge with --edge"
```

---

### Task 4: CI

**Files:**
- Modify: `.github/workflows/ci.yml`: new job after `e2e-source` (~line 205)
- Modify: `.github/workflows/e2e-windows.yml`: the "E2E journey (installed exes)" step (~line 97) and the header comment

**Interfaces:**
- Consumes: the `--edge` flag from Task 3.
- Produces: the CI job `e2e-edge`, plus a Windows release gate that runs over `wss://`.

Ruling recorded here: `release-relay.yml` stays plain. Its image run proves the default configuration, the one QA runs. The edge path for the same relay code is proven by `e2e-edge` on every PR. Adding `--edge` there is a one-flag follow-up.

- [ ] **Step 1: Add the `e2e-edge` job to `ci.yml`**

Append it after the `e2e-source` job, at the same indentation:

```yaml
  e2e-edge:
    runs-on: ubuntu-latest
    timeout-minutes: 20

    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-python@v7
        with:
          python-version: "3.14"

      - uses: astral-sh/setup-uv@v7

      - name: Install system dependencies for socks-proxy tray
        run: sudo apt-get update && sudo apt-get install -y libgirepository-2.0-dev libcairo2-dev

      - name: Sync components
        run: for p in relay netbridge-agent socks-proxy security-tests e2e; do (cd "$p" && uv sync); done

      - name: Map the e2e target hostname (remote-DNS check)
        run: |
          set -euo pipefail
          ip=$(uv run --project e2e python -m netbridge_e2e.netinfo)
          [ -n "$ip" ] && echo "$ip netbridge-e2e-target" | sudo tee -a /etc/hosts

      # same journey, but both clients go through the TLS edge (traefik profile)
      - name: E2E journey (source mode, behind the edge)
        run: >
          uv run --project e2e python -m netbridge_e2e --mode source --edge
          --target-hostname netbridge-e2e-target --work "$RUNNER_TEMP/e2e"

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: e2e-edge-report
          path: ${{ runner.temp }}/e2e
          if-no-files-found: ignore
```

- [ ] **Step 2: Switch the Windows run to the edge**

In `e2e-windows.yml`, change the journey step to:

```yaml
      # installed exes over wss:// with a verified certificate, as users connect (arr profile: ip:port XFF, /netbridge prefix)
      - name: E2E journey (installed exes, behind the edge)
        run: >
          uv run --project e2e python -m netbridge_e2e --mode exe --edge
          --target-hostname netbridge-e2e-target
          --agent-exe netbridge-agent/dist/netbridge.exe
          --proxy-exe socks-proxy-win/dist/netbridge-socks.exe
          --work "${{ runner.temp }}/e2e"
```

In the header comment, change "local --no-auth relay" to "local relay with auth on, behind a TLS edge". The relay has had auth on since PR #22, so the old wording is stale anyway.

- [ ] **Step 3: Validate the YAML**

Run: `uv run --no-project --with pyyaml python -c "import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]; print('ok')" .github/workflows/ci.yml .github/workflows/e2e-windows.yml`
Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml .github/workflows/e2e-windows.yml
git commit -m "Run the e2e journey behind the edge in CI and on Windows"
```

---

### Task 5: Whole-repo verification

**Files:** none (verification only).

- [ ] **Step 1: Coverage gate**

Run: `scripts/coverage.sh 2>&1 | tail -n 40`
Expected: every component passes its floor (e2e ≥ 79) and diff-cover on new lines is ≥ 80 %. If diff-cover flags `journey.py` or `edgeproxy.py` lines, add tests to the owning task's test file. Do not lower a floor.

- [ ] **Step 2: Confirm product code is untouched**

Run: `git diff --stat 958719b..HEAD -- relay netbridge-agent socks-proxy socks-proxy-win shared`
Expected: no output.

- [ ] **Step 3: Record the local run results**

Write down the outcome of the three Task 3 Step 7 runs (pass/fail, plus the details of the `edge_*` steps) for the PR description. The frozen-exe CA trust is proven by the PR's `windows-exe` job; Python-side trust is already proven on Windows by `test_shared_auth_context_trusts_the_ca_bundle`, which runs in that job's "Test the E2E driver" step. If `agent_connected` or `proxy_connected` fails there with a certificate error in the component log, that is the compatibility finding the spec's first risk anticipates.
