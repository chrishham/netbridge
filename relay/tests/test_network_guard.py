import socket

import pytest
from pytest_socket import SocketConnectBlockedError


@pytest.mark.filterwarnings("ignore:A test tried to use socket")
def test_non_loopback_connect_is_blocked():
    with socket.socket() as s, pytest.raises(SocketConnectBlockedError):
        s.connect(("192.0.2.1", 80))  # TEST-NET-1: never routable


def test_loopback_connect_still_works():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        with socket.create_connection(server.getsockname(), timeout=5):
            pass
