"""Minimal SOCKS5 / HTTP-proxy clients (stdlib, so no curl-version surprises).

Every socket carries a timeout: a proxy that hangs fails the step instead
of hanging the gate.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
import urllib.parse

Address = tuple[str, int]


class ProxyError(Exception):
    """The proxy refused the request (SOCKS5 reply code / HTTP status, -1 = protocol error)."""

    def __init__(self, code: int, message: str):
        super().__init__(f"{message} (code {code})")
        self.code = code


class ClientError(Exception):
    """WebSocket connection failed (HTTP status, body)."""

    def __init__(self, code: int, message: str):
        super().__init__(f"{message} (code {code})")
        self.code = code


def recv_exact(sock: socket.socket, n: int, deadline: float | None = None) -> bytes:
    """n bytes; with a monotonic `deadline`, every recv gets only the time left."""
    buf = bytearray()
    while len(buf) < n:
        if deadline is not None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("receive deadline passed")
            sock.settimeout(left)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return bytes(buf)


def socks5_connect(proxy: Address, dest_host: str, dest_port: int, timeout: float = 15.0) -> socket.socket:
    """CONNECT with ATYP=domain, so the far side (the agent) resolves the name."""
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise ProxyError(-1, "SOCKS5 no-auth method rejected")
        host = dest_host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + dest_port.to_bytes(2, "big"))
        ver, rep, _rsv, atyp = recv_exact(sock, 4)
        if ver != 5:
            raise ProxyError(-1, f"bad SOCKS version {ver}")
        if rep != 0:
            raise ProxyError(rep, f"SOCKS5 CONNECT {dest_host}:{dest_port} refused")
        addr_len = {1: 4, 4: 16}.get(atyp) or recv_exact(sock, 1)[0]
        recv_exact(sock, addr_len + 2)
        return sock
    except BaseException:
        sock.close()
        raise


def _read_head(sock: socket.socket, deadline: float | None = None) -> tuple[int, dict[str, str]]:
    # byte by byte: never consume tunnel bytes that follow the header
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        head += recv_exact(sock, 1, deadline)
        if len(head) > 65536:
            raise ProxyError(-1, "response header too large")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return status, headers


def _read_response(sock: socket.socket) -> tuple[int, bytes]:
    status, headers = _read_head(sock)
    if "content-length" in headers:
        return status, recv_exact(sock, int(headers["content-length"]))
    body = bytearray()
    while chunk := sock.recv(65536):
        body += chunk
    return status, bytes(body)


def http_connect(proxy: Address, dest_host: str, dest_port: int, timeout: float = 15.0) -> socket.socket:
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        target = f"{dest_host}:{dest_port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        status, _ = _read_head(sock)
        if status != 200:
            raise ProxyError(status, f"HTTP CONNECT {target} refused")
        return sock
    except BaseException:
        sock.close()
        raise


def http_get(sock: socket.socket, host_header: str, path: str = "/") -> tuple[int, bytes]:
    """GET over an already-established tunnel."""
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode())
    return _read_response(sock)


def http_forward_get(proxy: Address, url: str, timeout: float = 15.0) -> tuple[int, bytes]:
    """Plain HTTP proxying: absolute-URI GET sent to the proxy."""
    host_header = urllib.parse.urlsplit(url).netloc
    with socket.create_connection(proxy, timeout=timeout) as sock:
        sock.sendall(f"GET {url} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode())
        return _read_response(sock)


def echo_roundtrip(sock: socket.socket, data: bytes) -> bytes:
    """Send and read back concurrently: large blocks would deadlock otherwise."""
    sender = threading.Thread(target=sock.sendall, args=(data,), daemon=True)
    sender.start()
    got = recv_exact(sock, len(data))
    sender.join()
    return got


def wait_closed(sock: socket.socket, timeout: float) -> bool:
    """True once the peer ends the connection (EOF or error) within timeout; data is discarded."""
    deadline = time.monotonic() + timeout
    while (left := deadline - time.monotonic()) > 0:
        sock.settimeout(min(left, 1.0))
        try:
            if sock.recv(65536) == b"":
                return True
        except socket.timeout:
            continue
        except OSError:
            return True
    return False


def ws_upgrade(host: str, port: int, path: str, token: str | None, timeout: float = 10) -> tuple[int, str]:
    """WebSocket upgrade with `Authorization: Bearer <token>` (none if token is None). Returns (status, body up to 4 KiB); closes the connection."""
    deadline = time.monotonic() + timeout
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        # Generate WebSocket key
        ws_key = base64.b64encode(os.urandom(16)).decode()

        # Build request
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
        ]
        if token:
            headers.append(f"Authorization: Bearer {token}")
        headers.append("")
        headers.append("")

        sock.sendall("\r\n".join(headers).encode())

        # Read response
        status, headers_dict = _read_head(sock, deadline)

        # Read body if present (up to 4 KiB)
        body = ""
        if "content-length" in headers_dict:
            body_len = min(int(headers_dict["content-length"]), 4096)
            if body_len > 0:
                body = recv_exact(sock, body_len, deadline).decode("utf-8", errors="replace")

        return status, body
    finally:
        sock.close()


class WsClient:
    """Minimal WebSocket client (RFC 6455)."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    @classmethod
    def connect(cls, host: str, port: int, path: str, token: str | None, timeout: float = 10) -> "WsClient":
        """Handshake with `Authorization: Bearer <token>` (none if token is None). Raises ClientError on non-101."""
        deadline = time.monotonic() + timeout
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            # Generate WebSocket key
            ws_key = base64.b64encode(os.urandom(16)).decode()

            # Build request
            headers = [
                f"GET {path} HTTP/1.1",
                f"Host: {host}:{port}",
                "Upgrade: websocket",
                "Connection: Upgrade",
                f"Sec-WebSocket-Key: {ws_key}",
                "Sec-WebSocket-Version: 13",
            ]
            if token:
                headers.append(f"Authorization: Bearer {token}")
            headers.append("")
            headers.append("")

            sock.sendall("\r\n".join(headers).encode())

            # Read response
            status, headers_dict = _read_head(sock, deadline)

            if status != 101:
                # Read error body
                body = ""
                if "content-length" in headers_dict:
                    body_len = min(int(headers_dict["content-length"]), 4096)
                    if body_len > 0:
                        body = recv_exact(sock, body_len, deadline).decode("utf-8", errors="replace")
                sock.close()
                raise ClientError(status, body)

            # Verify Sec-WebSocket-Accept
            expected_accept = base64.b64encode(
                hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            actual_accept = headers_dict.get("sec-websocket-accept", "")
            if actual_accept != expected_accept:
                sock.close()
                raise ClientError(-1, f"Invalid Sec-WebSocket-Accept: {actual_accept}")

            sock.settimeout(timeout)  # the handshake deadline must not shrink later sends
            return cls(sock)
        except BaseException:
            sock.close()
            raise

    def send_json(self, obj: dict) -> None:
        """Send JSON as a masked text frame."""
        payload = json.dumps(obj).encode("utf-8")
        self._send_frame(1, payload, masked=True)

    def recv_json(self, timeout: float) -> dict:
        """Receive JSON, skipping pings (auto-ponged). Raises on close frame or after `timeout` overall."""
        deadline = time.monotonic() + timeout
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"no message within {timeout:g}s")
            opcode, payload = self._recv_frame(deadline)
            if opcode == 1:  # text
                return json.loads(payload.decode("utf-8"))
            elif opcode == 8:  # close
                raise ConnectionError("WebSocket closed by server")
            elif opcode == 9:  # ping
                self._send_frame(10, payload, masked=True)  # send pong
                continue
            elif opcode == 10:  # pong
                continue
            else:
                raise ConnectionError(f"Unexpected opcode {opcode}")

    def close(self) -> None:
        """Send close frame and close socket."""
        try:
            self._send_frame(8, b"", masked=True)
        except OSError:
            pass
        self.sock.close()

    def _send_frame(self, opcode: int, payload: bytes, masked: bool = False) -> None:
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
            mask_key = os.urandom(4)
            header += mask_key
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

        self.sock.sendall(header + payload)

    def _read(self, n: int, deadline: float | None) -> bytes:
        return recv_exact(self.sock, n, deadline)

    def _recv_frame(self, deadline: float | None = None) -> tuple[int, bytes]:
        """Receive a WebSocket frame. Returns (opcode, payload)."""
        header = self._read(2, deadline)
        opcode = header[0] & 0x0F
        masked = (header[1] & 0x80) != 0
        payload_len = header[1] & 0x7F

        if payload_len == 126:
            payload_len = struct.unpack("!H", self._read(2, deadline))[0]
        elif payload_len == 127:
            payload_len = struct.unpack("!Q", self._read(8, deadline))[0]

        mask_key = self._read(4, deadline) if masked else None
        payload = self._read(payload_len, deadline) if payload_len > 0 else b""

        if masked and mask_key:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

        return opcode, payload
