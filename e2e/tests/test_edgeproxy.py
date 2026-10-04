import os
import select
import socket
import ssl
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


class RaggedEnd(socket.socket):
    """A client transport that ends without close_notify: recv raises SSLEOFError where a plain socket returns b""."""

    def recv(self, n, *args):
        data = super().recv(n, *args)
        if not data:
            raise ssl.SSLEOFError("EOF occurred in violation of protocol")
        return data

    def pending(self):
        return 0


def test_ragged_client_end_still_delivers_what_the_edge_queued(edge):
    """Drives the pump directly, so an SSLEOFError escaping it fails the test whatever the timing."""
    a, peer = socket.socketpair()
    client = RaggedEnd(fileno=a.detach())
    up, sink = socket.socketpair()
    payload = os.urandom(4 * 1024 * 1024)  # more than MAX_BUFFERED plus the socket buffers
    got = bytearray()

    def send():
        peer.sendall(payload)
        peer.shutdown(socket.SHUT_WR)  # the client's end arrives behind its data

    def drain():
        time.sleep(0.3)  # meanwhile the edge queues up to MAX_BUFFERED for the upstream
        while chunk := sink.recv(65536):
            got.extend(chunk)

    threads = [threading.Thread(target=f, daemon=True) for f in (send, drain)]
    try:
        for t in threads:
            t.start()
        edge._pump(client, up)  # returns once everything the client sent is delivered
        up.close()  # the sink sees EOF
        for t in threads:
            t.join(5)
        assert len(got) == len(payload) and bytes(got) == payload
    finally:
        for s in (client, peer, up, sink):
            s.close()


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
        try:
            raw.recv(1024)
        except ConnectionResetError:  # Windows resets a socket closed with unread input; POSIX sends EOF
            pass
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
