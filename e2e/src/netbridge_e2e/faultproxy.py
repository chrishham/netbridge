"""In-process TCP fault injector between a client and the relay.

Runs in the driver (Linux and the Windows runner, no root, no binaries).
Pumps wait with select() so they notice a state change within one tick;
cut() shuts sockets down, which also wakes a blocked sendall().
"""
import select
import socket
import threading

TICK = 0.2


def _close(s: socket.socket) -> None:
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


class _Conn:
    def __init__(self, client: socket.socket, upstream: socket.socket):
        self.client = client
        self.upstream = upstream
        self.state = "open"  # open | blackholed | closed
        self.lock = threading.Lock()
        self.threads: list[threading.Thread] = []

    def kill(self) -> bool:
        with self.lock:
            if self.state == "closed":
                return False
            self.state = "closed"
        _close(self.client)
        _close(self.upstream)
        return True


class FaultProxy:
    def __init__(self, upstream: tuple[str, int], name: str):
        self.upstream = upstream
        self.name = name
        self._lsock = socket.create_server(("127.0.0.1", 0))
        self.port = self._lsock.getsockname()[1]
        self.url = f"ws://127.0.0.1:{self.port}"
        self._lock = threading.Lock()
        self._conns: set[_Conn] = set()
        self._refuse = False
        self._closed = False
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._spawn(self._accept_loop, f"fault-{self.name}-accept", self._threads)

    def _spawn(self, target, name, into, *args) -> None:
        t = threading.Thread(target=target, args=args, name=name, daemon=True)
        t.start()
        into.append(t)

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                ready, _, _ = select.select([self._lsock], [], [], TICK)
                if not ready:
                    continue
                client, _ = self._lsock.accept()
            except (OSError, ValueError):  # ValueError: select on a closed socket (negative fd)
                break
            if self._refuse:  # relay unreachable: the TCP handshake works, then nothing
                _close(client)
                continue
            try:
                up = socket.create_connection(self.upstream, timeout=5)
            except OSError:  # relay down: fail the client at once, like a refused connect
                _close(client)
                continue
            up.settimeout(None)
            conn = _Conn(client, up)
            with self._lock:
                if self._closed:
                    conn.kill()
                    break
                self._conns.add(conn)
            for src, dst in ((client, up), (up, client)):
                self._spawn(self._pump, f"fault-{self.name}-pump", conn.threads, conn, src, dst)

    def _pump(self, conn: _Conn, src: socket.socket, dst: socket.socket) -> None:
        try:
            while conn.state != "closed":
                ready, _, _ = select.select([src], [], [], TICK)
                if not ready:
                    continue
                data = src.recv(65536)
                if not data:
                    break
                if conn.state == "open":  # blackholed: keep draining, forward nothing
                    dst.sendall(data)
        except (OSError, ValueError):  # ValueError: select on a socket closed by cut()
            pass
        finally:
            conn.kill()
            with self._lock:
                self._conns.discard(conn)

    def _live(self) -> list[_Conn]:
        with self._lock:
            return [c for c in self._conns if c.state != "closed"]

    def active(self) -> int:
        return len(self._live())

    def cut(self) -> int:
        return sum(c.kill() for c in self._live())

    def blackhole(self) -> int:
        n = 0
        for c in self._live():
            with c.lock:
                if c.state == "open":
                    c.state = "blackholed"
                    n += 1
        return n

    def refuse(self, on: bool) -> None:
        self._refuse = on

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        _close(self._lsock)
        conns = self._live()
        for c in conns:
            c.kill()
        for t in self._threads + [t for c in conns for t in c.threads]:
            t.join(2)
