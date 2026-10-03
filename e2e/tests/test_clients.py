import socket
import struct
import sys
import threading
import time

import pytest

from netbridge_e2e import clients, stack
from netbridge_e2e.authstub import AuthStub
from netbridge_e2e.targets import PAGE, Targets
from tests import fakeproxy


@pytest.fixture
def targets():
    with Targets("127.0.0.1") as t:
        yield t


def test_socks5_http_get(targets):
    proxy = fakeproxy.socks5_proxy()
    try:
        with clients.socks5_connect(proxy.address, "127.0.0.1", targets.http_port) as s:
            assert clients.http_get(s, f"127.0.0.1:{targets.http_port}") == (200, PAGE)
    finally:
        proxy.close()


def test_socks5_refusal_carries_reply_code(targets):
    proxy = fakeproxy.socks5_proxy(fail_code=4)
    try:
        with pytest.raises(clients.ProxyError) as err:
            clients.socks5_connect(proxy.address, "127.0.0.1", targets.echo_port)
        assert err.value.code == 4
    finally:
        proxy.close()


def test_socks5_hung_proxy_times_out():
    srv, address = fakeproxy.silent_server()
    try:
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            clients.socks5_connect(address, "127.0.0.1", 9, timeout=1.0)
        assert time.monotonic() - start < 5
    finally:
        srv.close()


def test_http_connect_echo_large_block(targets):
    proxy = fakeproxy.http_proxy()
    data = bytes(range(256)) * 1024  # 256 KiB: larger than typical socket buffers
    try:
        with clients.http_connect(proxy.address, "127.0.0.1", targets.echo_port) as s:
            assert clients.echo_roundtrip(s, data) == data
    finally:
        proxy.close()


def test_http_connect_refusal_carries_status(targets):
    proxy = fakeproxy.http_proxy(refuse=True)
    try:
        with pytest.raises(clients.ProxyError) as err:
            clients.http_connect(proxy.address, "127.0.0.1", targets.echo_port)
        assert err.value.code == 403
    finally:
        proxy.close()


def test_http_forward_get(targets):
    proxy = fakeproxy.http_proxy()
    try:
        url = f"http://127.0.0.1:{targets.http_port}/"
        assert clients.http_forward_get(proxy.address, url) == (200, PAGE)
    finally:
        proxy.close()


def _pair():
    srv = socket.create_server(("127.0.0.1", 0))
    client = socket.create_connection(srv.getsockname(), timeout=2)
    peer, _ = srv.accept()
    srv.close()
    return client, peer


def test_wait_closed_sees_peer_close():
    client, peer = _pair()
    peer.sendall(b"discarded")
    threading.Timer(0.2, peer.close).start()
    start = time.monotonic()
    try:
        assert clients.wait_closed(client, 2) is True
        assert time.monotonic() - start < 1
    finally:
        client.close()


def test_wait_closed_times_out_while_peer_stays_open():
    client, peer = _pair()
    start = time.monotonic()
    try:
        assert clients.wait_closed(client, 0.3) is False
        assert 0.25 <= time.monotonic() - start < 1
    finally:
        client.close()
        peer.close()


def test_wait_closed_sees_peer_reset():
    client, peer = _pair()
    linger = struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0)  # Windows LINGER is two u_shorts
    peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)  # close() sends RST
    peer.close()
    try:
        assert clients.wait_closed(client, 2) is True
    finally:
        client.close()


# WebSocket test helpers


class _WsServer:
    """Tiny threaded stdlib websocket server for testing."""

    def __init__(self, handler, port=0):
        self.srv = socket.create_server(("127.0.0.1", port), backlog=1)
        self.address = self.srv.getsockname()
        self.handler = handler
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                client, _ = self.srv.accept()
                try:
                    self.handler(client)
                finally:
                    client.close()
            except OSError:
                break

    def close(self):
        self.srv.close()


def _ws_handshake(sock, require_auth=False):
    """Perform WebSocket handshake. Returns True if successful, sends 401 if require_auth and no token."""
    import base64
    import hashlib

    # Read request
    req = bytearray()
    while not req.endswith(b"\r\n\r\n"):
        req += sock.recv(1)
    req = req.decode("iso-8859-1")

    # Parse headers
    headers = {}
    for line in req.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    # Check authorization if required
    if require_auth:
        if "authorization" not in headers or headers["authorization"] != "Bearer valid-token":
            body = b"Missing Authorization header"
            sock.sendall(f"HTTP/1.1 401 Unauthorized\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
            return False

    # Complete handshake
    key = headers.get("sec-websocket-key", "")
    accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    sock.sendall(
        f"HTTP/1.1 101 Switching Protocols\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n".encode()
    )
    return True


def _ws_read_frame(sock):
    """Read a WebSocket frame. Returns (opcode, payload, is_masked)."""
    header = sock.recv(2)
    if len(header) < 2:
        return None, b"", False

    opcode = header[0] & 0x0F
    masked = (header[1] & 0x80) != 0
    payload_len = header[1] & 0x7F

    if payload_len == 126:
        payload_len = struct.unpack("!H", sock.recv(2))[0]
    elif payload_len == 127:
        payload_len = struct.unpack("!Q", sock.recv(8))[0]

    mask_key = sock.recv(4) if masked else None
    payload = bytearray()
    while len(payload) < payload_len:
        chunk = sock.recv(payload_len - len(payload))
        if not chunk:
            break
        payload += chunk

    if masked and mask_key:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return opcode, bytes(payload), masked


def _ws_send_frame(sock, opcode, payload, masked=False):
    """Send a WebSocket frame."""
    header = bytearray([0x80 | opcode])  # FIN=1
    payload_len = len(payload)

    if payload_len <= 125:
        header.append(payload_len)
    elif payload_len <= 65535:
        header.append(126)
        header += struct.pack("!H", payload_len)
    else:
        header.append(127)
        header += struct.pack("!Q", payload_len)

    if masked:
        header[1] |= 0x80
        import os

        mask_key = os.urandom(4)
        header += mask_key
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    sock.sendall(header + payload)


# WebSocket tests


def test_ws_upgrade_success():
    """ws_upgrade returns 101 status for valid handshake."""

    def handler(client):
        _ws_handshake(client)

    server = _WsServer(handler)
    try:
        status, body = clients.ws_upgrade("127.0.0.1", server.address[1], "/ws", None)
        assert status == 101
        assert body == ""
    finally:
        server.close()


def test_ws_upgrade_unauthorized():
    """ws_upgrade returns 401 status and body when auth fails."""

    def handler(client):
        _ws_handshake(client, require_auth=True)

    server = _WsServer(handler)
    try:
        status, body = clients.ws_upgrade("127.0.0.1", server.address[1], "/ws", None)
        assert status == 401
        assert "Missing Authorization header" in body
    finally:
        server.close()


def test_ws_client_small_json():
    """WsClient round-trips small JSON (10 bytes)."""

    def handler(client):
        if not _ws_handshake(client):
            return
        # Echo text frames
        opcode, payload, masked = _ws_read_frame(client)
        assert masked, "Client frames must be masked"
        assert opcode == 1  # text
        _ws_send_frame(client, 1, payload)  # echo unmasked
        # Wait for close
        _ws_read_frame(client)

    server = _WsServer(handler)
    try:
        ws = clients.WsClient.connect("127.0.0.1", server.address[1], "/ws", "valid-token")
        data = {"x": 1}
        ws.send_json(data)
        result = ws.recv_json(timeout=2)
        assert result == data
        ws.close()
    finally:
        server.close()


def test_ws_client_medium_json():
    """WsClient round-trips medium JSON (~300 bytes, 16-bit length)."""

    def handler(client):
        if not _ws_handshake(client):
            return
        opcode, payload, masked = _ws_read_frame(client)
        assert masked, "Client frames must be masked"
        _ws_send_frame(client, 1, payload)
        _ws_read_frame(client)

    server = _WsServer(handler)
    try:
        ws = clients.WsClient.connect("127.0.0.1", server.address[1], "/ws", "valid-token")
        data = {"data": "x" * 250}  # ~260 bytes JSON
        ws.send_json(data)
        result = ws.recv_json(timeout=2)
        assert result == data
        ws.close()
    finally:
        server.close()


def test_ws_client_large_json():
    """WsClient round-trips large JSON (70 KB, 64-bit length)."""

    def handler(client):
        if not _ws_handshake(client):
            return
        opcode, payload, masked = _ws_read_frame(client)
        assert masked, "Client frames must be masked"
        _ws_send_frame(client, 1, payload)
        _ws_read_frame(client)

    server = _WsServer(handler)
    try:
        ws = clients.WsClient.connect("127.0.0.1", server.address[1], "/ws", "valid-token")
        data = {"data": "x" * 70000}  # ~70 KB
        ws.send_json(data)
        result = ws.recv_json(timeout=2)
        assert result == data
        ws.close()
    finally:
        server.close()


def test_ws_client_handles_server_ping():
    """Server ping is answered with pong and skipped in recv_json."""

    def handler(client):
        if not _ws_handshake(client):
            return
        # Send ping first
        _ws_send_frame(client, 9, b"ping-payload")
        # Read pong
        opcode, payload, masked = _ws_read_frame(client)
        assert opcode == 10  # pong
        assert masked, "Client pong must be masked"
        assert payload == b"ping-payload"
        # Send actual message
        _ws_send_frame(client, 1, b'{"ok": true}')
        _ws_read_frame(client)

    server = _WsServer(handler)
    try:
        ws = clients.WsClient.connect("127.0.0.1", server.address[1], "/ws", "valid-token")
        result = ws.recv_json(timeout=2)
        assert result == {"ok": True}
        ws.close()
    finally:
        server.close()


def test_ws_client_close_frame_raises():
    """Server sending close frame causes recv_json to raise."""

    def handler(client):
        if not _ws_handshake(client):
            return
        # Send close frame
        _ws_send_frame(client, 8, b"")

    server = _WsServer(handler)
    try:
        ws = clients.WsClient.connect("127.0.0.1", server.address[1], "/ws", "valid-token")
        with pytest.raises(ConnectionError, match="WebSocket closed"):
            ws.recv_json(timeout=2)
    finally:
        server.close()


def test_ws_client_connect_raises_on_non_101():
    """WsClient.connect raises ClientError on non-101 status."""

    def handler(client):
        _ws_handshake(client, require_auth=True)

    server = _WsServer(handler)
    try:
        with pytest.raises(clients.ClientError) as err:
            clients.WsClient.connect("127.0.0.1", server.address[1], "/ws", None)
        assert err.value.code == 401
        assert "Missing Authorization header" in err.value.args[0]
    finally:
        server.close()


# Integration test against real relay


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_ws_upgrade_against_real_relay(tmp_path):
    """Integration: ws_upgrade works against aiohttp relay (valid token → 101, no token → 401)."""
    import os

    auth = AuthStub(tmp_path)
    auth.start()
    try:
        relay = stack.Relay(tmp_path, _free_port(), blocked_port=1, env=dict(os.environ), auth=auth)
        relay.start()
        try:
            assert relay.wait_ready(30), "Relay did not start"

            # Valid token → 101
            token = auth.mint(upn="test@netbridge.test")
            status, body = clients.ws_upgrade("127.0.0.1", relay.port, "/ws", token)
            assert status == 101
            assert body == ""

            # No token → 401 with body
            status, body = clients.ws_upgrade("127.0.0.1", relay.port, "/ws", None)
            assert status == 401
            assert "Missing Authorization header" in body
        finally:
            relay.stop()
    finally:
        auth.close()


def test_ws_recv_json_deadline_is_overall_not_per_frame(monkeypatch):
    """A relay that only ever pings must not keep recv_json waiting forever."""
    a, b = socket.socketpair()
    try:
        ws = clients.WsClient(a)

        def ping(deadline=None):
            time.sleep(0.05)
            return 9, b""

        monkeypatch.setattr(ws, "_recv_frame", ping)
        monkeypatch.setattr(ws, "_send_frame", lambda *args, **kw: None)
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            ws.recv_json(0.3)
        assert time.monotonic() - start < 1
    finally:
        a.close()
        b.close()


def test_ws_recv_json_deadline_bounds_a_trickled_frame():
    """A frame trickled one byte at a time must not outlive the deadline."""
    class Trickle:
        data = b"\x81\x7e\x00\x64" + b"a" * 100

        def __init__(self):
            self.pos = 0

        def settimeout(self, t):
            pass

        def recv(self, n):
            time.sleep(0.05)
            self.pos += 1
            return self.data[self.pos - 1:self.pos]

    ws = clients.WsClient(Trickle())
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        ws.recv_json(0.3)
    assert time.monotonic() - start < 1
