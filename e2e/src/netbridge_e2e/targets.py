"""Target servers the tunnelled traffic must reach (driver threads)."""
import hashlib
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"netbridge-e2e ok\n"
PAYLOAD_SIZE = 5 * 1024 * 1024
# sha256 counter stream: incompressible and position-dependent, so dropped,
# duplicated or reordered chunks change the digest
PAYLOAD = b"".join(hashlib.sha256(i.to_bytes(8, "big")).digest() for i in range(PAYLOAD_SIZE // 32))
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


class _HttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = {"/": PAGE, "/payload": PAYLOAD}.get(self.path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class _EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class Targets:
    """HTTP server, echo server and a second echo server the relay must block."""

    def __init__(self, host: str):
        self.host = host
        http = ThreadingHTTPServer((host, 0), _HttpHandler)
        http.daemon_threads = True
        self._servers = [http, _EchoServer((host, 0), _EchoHandler), _EchoServer((host, 0), _EchoHandler)]
        self.http_port, self.echo_port, self.blocked_port = (s.server_address[1] for s in self._servers)
        for server in self._servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def close(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
