"""Minimal SOCKS5 / HTTP-proxy clients (stdlib, so no curl-version surprises).

Every socket carries a timeout: a proxy that hangs fails the step instead
of hanging the gate.
"""
import socket
import threading
import urllib.parse

Address = tuple[str, int]


class ProxyError(Exception):
    """The proxy refused the request (SOCKS5 reply code / HTTP status, -1 = protocol error)."""

    def __init__(self, code: int, message: str):
        super().__init__(f"{message} (code {code})")
        self.code = code


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
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


def _read_head(sock: socket.socket) -> tuple[int, dict[str, str]]:
    # byte by byte: never consume tunnel bytes that follow the header
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        head += recv_exact(sock, 1)
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
