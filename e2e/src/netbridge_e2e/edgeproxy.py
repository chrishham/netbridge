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
        except (OSError, ValueError, AttributeError):  # OSError includes SSLError; ValueError: a socket
            # close() shut mid-select; AttributeError: close() cleared an SSLSocket mid-call
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
            if room[client] > 0 and client.pending() and not read_wants_write[client]:
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
