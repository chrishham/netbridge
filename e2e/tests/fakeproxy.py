"""Tiny direct-connect SOCKS5 and HTTP proxies to test the e2e clients."""
import socket
import socketserver
import threading
import urllib.parse


def _pipe(a: socket.socket, b: socket.socket) -> None:
    def copy(src, dst):
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=copy, args=(b, a), daemon=True)
    t.start()
    copy(a, b)
    t.join()


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, handler, **opts):
        super().__init__(("127.0.0.1", 0), handler)
        self.opts = opts
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def address(self):
        return self.server_address

    def close(self):
        self.shutdown()
        self.server_close()


class _Socks5Handler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        _ver, n = _recv_exact(s, 2)
        _recv_exact(s, n)
        s.sendall(b"\x05\x00")
        _ver, _cmd, _rsv, atyp = _recv_exact(s, 4)
        assert atyp == 3, "client must send ATYP=domain"
        host = _recv_exact(s, _recv_exact(s, 1)[0]).decode()
        port = int.from_bytes(_recv_exact(s, 2), "big")
        fail = self.server.opts.get("fail_code")
        if fail:
            s.sendall(bytes([5, fail, 0, 1, 0, 0, 0, 0, 0, 0]))
            return
        up = socket.create_connection((host, port), timeout=10)
        s.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        _pipe(s, up)


class _HttpProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            head += _recv_exact(s, 1)
        method, target, _ = head.decode().split("\r\n")[0].split(" ")
        if method == "CONNECT":
            if self.server.opts.get("refuse"):
                s.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            host, port = target.rsplit(":", 1)
            up = socket.create_connection((host, int(port)), timeout=10)
            s.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            _pipe(s, up)
            return
        url = urllib.parse.urlsplit(target)
        up = socket.create_connection((url.hostname, url.port), timeout=10)
        up.sendall(f"GET {url.path or '/'} HTTP/1.1\r\nHost: {url.netloc}\r\nConnection: close\r\n\r\n".encode())
        _pipe(s, up)


def socks5_proxy(**opts) -> _Server:
    return _Server(_Socks5Handler, **opts)


def http_proxy(**opts) -> _Server:
    return _Server(_HttpProxyHandler, **opts)


def silent_server() -> tuple[socket.socket, tuple[str, int]]:
    """Accepts connections and never answers (a hung proxy)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    return srv, srv.getsockname()
