import socket
import threading
import time

import pytest

from netbridge_e2e.faultproxy import FaultProxy


@pytest.fixture
def echo_server():
    srv = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=_echo, args=(c,), daemon=True).start()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()
    stop.set()
    srv.close()
    t.join(2)


def _echo(c):
    with c:
        try:
            while data := c.recv(65536):
                c.sendall(data)
        except OSError:
            pass


@pytest.fixture
def fp(echo_server):
    p = FaultProxy(echo_server, "test")
    p.start()
    yield p
    p.close()


def connect(fp):
    s = socket.create_connection(("127.0.0.1", fp.port), timeout=5)
    s.sendall(b"ping")
    assert s.recv(4) == b"ping"
    return s


def wait_until(pred, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def ended(s, timeout=1.0) -> bool:
    s.settimeout(timeout)
    try:
        return s.recv(1) == b""
    except socket.timeout:
        return False
    except OSError:
        return True


def test_url_and_pass_through(fp):
    assert fp.url == f"ws://127.0.0.1:{fp.port}"
    with connect(fp):
        assert wait_until(lambda: fp.active() == 1)


def test_large_transfer_passes(fp):
    data = bytes(range(256)) * 20480  # 5 MiB
    with connect(fp) as s:
        got = bytearray()
        sender = threading.Thread(target=s.sendall, args=(data,))
        sender.start()
        s.settimeout(10)
        while len(got) < len(data):
            got += s.recv(1 << 16)
        sender.join(10)
    assert bytes(got) == data


def test_cut_ends_both_legs_promptly(fp):
    s1, s2 = connect(fp), connect(fp)
    start = time.monotonic()
    assert fp.cut() == 2
    assert ended(s1) and ended(s2)
    assert time.monotonic() - start < 1.5
    assert wait_until(lambda: fp.active() == 0)
    with connect(fp):  # new connections still pass
        pass


def test_blackhole_keeps_sockets_open_but_drops_bytes(fp):
    s = connect(fp)
    assert fp.blackhole() == 1
    s.sendall(b"lost")
    s.settimeout(0.5)
    with pytest.raises(socket.timeout):
        s.recv(4)
    assert fp.active() == 1
    with connect(fp):  # a fresh connection is unaffected
        pass
    s.close()
    assert wait_until(lambda: fp.active() == 0)


def test_refuse_closes_new_connections_until_lifted(fp):
    old = connect(fp)
    fp.refuse(True)
    s = socket.create_connection(("127.0.0.1", fp.port), timeout=5)
    assert ended(s)
    old.sendall(b"ok")  # existing connections unaffected
    assert old.recv(2) == b"ok"
    fp.refuse(False)
    with connect(fp):
        pass
    old.close()


def test_upstream_down_closes_client():
    dead = socket.create_server(("127.0.0.1", 0))
    addr = dead.getsockname()
    dead.close()
    p = FaultProxy(addr, "dead")
    p.start()
    try:
        s = socket.create_connection(("127.0.0.1", p.port), timeout=5)
        assert ended(s, timeout=3)
    finally:
        p.close()


def test_close_is_idempotent_and_stops_threads(echo_server):
    before = threading.active_count()
    p = FaultProxy(echo_server, "t")
    p.start()
    s = connect(p)
    p.close()
    p.close()
    s.close()
    assert wait_until(lambda: threading.active_count() <= before, timeout=3)


def test_close_while_listener_selects(echo_server, monkeypatch):
    import netbridge_e2e.faultproxy as fpmod
    real_select = fpmod.select.select
    entered = threading.Event()

    def spy(r, w, x, timeout):
        entered.set()
        return real_select(r, w, x, timeout)

    monkeypatch.setattr(fpmod.select, "select", spy)
    for _ in range(20):  # close() lands while the accept loop sits in select(); no thread may die
        p = FaultProxy(echo_server, "race")
        errors = []
        threading.excepthook = lambda a: errors.append(a)
        try:
            entered.clear()
            p.start()
            assert entered.wait(2)
            p.close()
            for t in p._threads:
                t.join(2)
        finally:
            threading.excepthook = threading.__excepthook__
        assert not errors


def test_no_thread_starts_after_close(echo_server):
    p = FaultProxy(echo_server, "late")
    p.close()
    ran = threading.Event()
    p._spawn(ran.set, "late-pump", p._threads)  # an accept loop racing close() must not start a pump
    assert not ran.wait(0.2) and p._threads == []


def test_refuse_and_cut_racing_upstream_connect(echo_server, monkeypatch):
    import netbridge_e2e.faultproxy as fpmod
    real_create_connection = socket.create_connection

    def race_create_connection(addr, timeout=None):
        up = real_create_connection(addr, timeout=timeout)
        # refuse(True) + cut() land between upstream connect and registration
        fp.refuse(True)
        fp.cut()
        return up

    monkeypatch.setattr(fpmod.socket, "create_connection", race_create_connection)
    fp = FaultProxy(echo_server, "race")
    fp.start()
    try:
        s = socket.create_connection(("127.0.0.1", fp.port), timeout=5)
        assert ended(s, timeout=2)
        assert wait_until(lambda: fp.active() == 0)
    finally:
        fp.close()

