"""Tests for socks_proxy.__main__ — loopback check."""

from socks_proxy.__main__ import _is_loopback


class TestIsLoopback:
    """Tests for _is_loopback()."""

    def test_ipv4_loopback(self):
        assert _is_loopback("127.0.0.1") is True

    def test_localhost(self):
        assert _is_loopback("localhost") is True

    def test_ipv6_loopback(self):
        assert _is_loopback("::1") is True

    def test_external_ip(self):
        assert _is_loopback("192.168.1.1") is False

    def test_all_interfaces(self):
        assert _is_loopback("0.0.0.0") is False

    def test_empty_string(self):
        assert _is_loopback("") is False
