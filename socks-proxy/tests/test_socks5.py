"""Tests for SOCKS5 protocol handler."""

import asyncio
import socket
import struct

import pytest

from socks_proxy.socks5 import (
    SOCKS5_VERSION,
    AUTH_NO_AUTH,
    AUTH_USERNAME_PASSWORD,
    AUTH_NO_ACCEPTABLE,
    CMD_CONNECT,
    ATYP_IPV4,
    ATYP_DOMAIN,
    REPLY_SUCCESS,
    REPLY_NOT_ALLOWED,
    Socks5Error,
    _handle_greeting,
    _handle_request,
    _send_reply,
)


def _feed_reader(data: bytes) -> asyncio.StreamReader:
    """Create a StreamReader pre-loaded with data."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


class _FakeWriter:
    """Minimal fake asyncio.StreamWriter that captures written bytes."""

    def __init__(self):
        self.buffer = bytearray()

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        pass


class TestConstants:
    """Verify protocol constants match RFC 1928."""

    def test_socks5_version(self):
        assert SOCKS5_VERSION == 0x05

    def test_auth_methods(self):
        assert AUTH_NO_AUTH == 0x00
        assert AUTH_USERNAME_PASSWORD == 0x02
        assert AUTH_NO_ACCEPTABLE == 0xFF

    def test_connect_command(self):
        assert CMD_CONNECT == 0x01

    def test_address_types(self):
        assert ATYP_IPV4 == 0x01
        assert ATYP_DOMAIN == 0x03


class TestHandleGreeting:
    """Tests for _handle_greeting()."""

    @pytest.mark.asyncio
    async def test_no_auth_accepted(self):
        """Client offers NO AUTH, server accepts it."""
        # Greeting: version=5, nmethods=1, methods=[NO_AUTH]
        data = struct.pack("!BB", SOCKS5_VERSION, 1) + bytes([AUTH_NO_AUTH])
        reader = _feed_reader(data)
        writer = _FakeWriter()

        await _handle_greeting(reader, writer, proxy_credentials=None)

        # Server should respond: version=5, method=NO_AUTH
        assert bytes(writer.buffer) == struct.pack("!BB", SOCKS5_VERSION, AUTH_NO_AUTH)

    @pytest.mark.asyncio
    async def test_auth_required_not_offered(self):
        """Client offers only NO AUTH but server requires credentials."""
        data = struct.pack("!BB", SOCKS5_VERSION, 1) + bytes([AUTH_NO_AUTH])
        reader = _feed_reader(data)
        writer = _FakeWriter()

        with pytest.raises(Socks5Error) as exc_info:
            await _handle_greeting(reader, writer, proxy_credentials=("user", "pass"))

        assert exc_info.value.reply_code == REPLY_NOT_ALLOWED
        # Server should have sent NO_ACCEPTABLE
        assert bytes(writer.buffer) == struct.pack("!BB", SOCKS5_VERSION, AUTH_NO_ACCEPTABLE)

    @pytest.mark.asyncio
    async def test_auth_success(self):
        """Client provides correct username/password credentials."""
        # Greeting offering USERNAME_PASSWORD
        greeting = struct.pack("!BB", SOCKS5_VERSION, 1) + bytes([AUTH_USERNAME_PASSWORD])
        # RFC 1929 sub-negotiation: ver=1, ulen=4, user="test", plen=4, pass="pass"
        user = b"test"
        password = b"pass"
        auth = b"\x01" + struct.pack("!B", len(user)) + user + struct.pack("!B", len(password)) + password

        reader = _feed_reader(greeting + auth)
        writer = _FakeWriter()

        await _handle_greeting(reader, writer, proxy_credentials=("test", "pass"))

        # Server selects USERNAME_PASSWORD, then auth success (0x01, 0x00)
        expected = struct.pack("!BB", SOCKS5_VERSION, AUTH_USERNAME_PASSWORD) + b"\x01\x00"
        assert bytes(writer.buffer) == expected


class TestHandleRequest:
    """Tests for _handle_request()."""

    @pytest.mark.asyncio
    async def test_domain_connect(self):
        """CONNECT to a domain name parses correctly."""
        domain = b"example.com"
        port = 443
        data = struct.pack("!BBBB", SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN)
        data += struct.pack("!B", len(domain)) + domain
        data += struct.pack("!H", port)

        reader = _feed_reader(data)
        writer = _FakeWriter()

        host, parsed_port = await _handle_request(reader, writer)
        assert host == "example.com"
        assert parsed_port == 443

    @pytest.mark.asyncio
    async def test_ipv4_connect(self):
        """CONNECT to an IPv4 address parses correctly."""
        ip = "192.168.1.1"
        port = 8080
        data = struct.pack("!BBBB", SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4)
        data += socket.inet_aton(ip)
        data += struct.pack("!H", port)

        reader = _feed_reader(data)
        writer = _FakeWriter()

        host, parsed_port = await _handle_request(reader, writer)
        assert host == "192.168.1.1"
        assert parsed_port == 8080


class TestSendReply:
    """Tests for _send_reply()."""

    @pytest.mark.asyncio
    async def test_success_reply_format(self):
        """Success reply has correct SOCKS5 format."""
        writer = _FakeWriter()
        await _send_reply(writer, REPLY_SUCCESS)

        result = bytes(writer.buffer)
        # VER REP RSV ATYP BND.ADDR(4) BND.PORT(2) = 10 bytes
        assert len(result) == 10
        ver, rep, rsv, atyp = struct.unpack("!BBBB", result[:4])
        assert ver == SOCKS5_VERSION
        assert rep == REPLY_SUCCESS
        assert rsv == 0x00
        assert atyp == ATYP_IPV4
        # Default bind address 0.0.0.0:0
        assert result[4:8] == socket.inet_aton("0.0.0.0")
        assert struct.unpack("!H", result[8:10])[0] == 0

    @pytest.mark.asyncio
    async def test_error_reply_code(self):
        """Error reply code is correctly embedded."""
        writer = _FakeWriter()
        await _send_reply(writer, REPLY_NOT_ALLOWED)

        result = bytes(writer.buffer)
        _, rep, _, _ = struct.unpack("!BBBB", result[:4])
        assert rep == REPLY_NOT_ALLOWED
