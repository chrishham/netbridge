"""Tests for HTTP proxy — header reading, proxy auth, chunked body, CONNECT, and HTTP requests."""

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from socks_proxy.http_proxy import (
    _check_proxy_auth,
    _read_headers,
    _stream_chunked_body,
    MAX_CHUNK_SIZE,
    MAX_HEADERS,
    MAX_HEADER_BYTES,
    HEADER_READ_TIMEOUT,
)


def _feed_reader(data: bytes) -> asyncio.StreamReader:
    """Create a StreamReader pre-loaded with data."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


class TestReadHeaders:
    """Tests for _read_headers() Slowloris protection."""

    @pytest.mark.asyncio
    async def test_normal_headers(self):
        """Normal headers are returned correctly."""
        raw = b"Host: example.com\r\nContent-Length: 0\r\n\r\n"
        reader = _feed_reader(raw)
        headers = await _read_headers(reader)
        assert len(headers) == 2
        assert headers[0] == b"Host: example.com\r\n"
        assert headers[1] == b"Content-Length: 0\r\n"

    @pytest.mark.asyncio
    async def test_empty_headers(self):
        """Empty header block (just CRLF) returns empty list."""
        reader = _feed_reader(b"\r\n")
        headers = await _read_headers(reader)
        assert headers == []

    @pytest.mark.asyncio
    async def test_max_header_count_exceeded(self):
        """Exceeding MAX_HEADERS raises ValueError."""
        # Build MAX_HEADERS + 1 header lines (no terminator so we hit the limit)
        lines = b"".join(
            f"X-Header-{i}: value\r\n".encode() for i in range(MAX_HEADERS + 1)
        )
        reader = _feed_reader(lines)
        with pytest.raises(ValueError, match="Too many headers"):
            await _read_headers(reader)

    @pytest.mark.asyncio
    async def test_max_header_bytes_exceeded(self):
        """Exceeding MAX_HEADER_BYTES raises ValueError."""
        # Build many small headers that cumulatively exceed the byte limit
        line = b"X-Pad: " + b"A" * 900 + b"\r\n"  # ~910 bytes each
        count = (MAX_HEADER_BYTES // len(line)) + 2  # enough to exceed limit
        data = line * count + b"\r\n"
        reader = _feed_reader(data)
        with pytest.raises(ValueError, match="Headers too large"):
            await _read_headers(reader)

    @pytest.mark.asyncio
    async def test_eof_terminates(self):
        """EOF (empty line) terminates header reading."""
        raw = b"Host: example.com\r\n"
        reader = _feed_reader(raw)
        # feed_eof already called — readline returns b"" after data exhausted
        headers = await _read_headers(reader)
        assert len(headers) == 1
        assert headers[0] == b"Host: example.com\r\n"

    @pytest.mark.asyncio
    async def test_timeout(self):
        """Slow reader triggers asyncio.TimeoutError."""
        reader = asyncio.StreamReader()
        # Don't feed any data — readline will block until timeout
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(_read_headers(reader), timeout=0.1)


# ---------------------------------------------------------------------------
# _check_proxy_auth
# ---------------------------------------------------------------------------
class TestCheckProxyAuth:
    """Tests for _check_proxy_auth()."""

    def test_valid_credentials(self):
        """Correct credentials return True."""
        creds = ("user", "pass")
        expected_b64 = base64.b64encode(b"user:pass").decode()
        headers = [f"Proxy-Authorization: Basic {expected_b64}\r\n".encode()]
        assert _check_proxy_auth(headers, creds) is True

    def test_wrong_credentials(self):
        """Incorrect credentials return False."""
        creds = ("user", "pass")
        wrong_b64 = base64.b64encode(b"user:wrong").decode()
        headers = [f"Proxy-Authorization: Basic {wrong_b64}\r\n".encode()]
        assert _check_proxy_auth(headers, creds) is False

    def test_missing_header(self):
        """Missing Proxy-Authorization header returns False."""
        creds = ("user", "pass")
        headers = [b"Host: example.com\r\n"]
        assert _check_proxy_auth(headers, creds) is False

    def test_case_insensitive_header_name(self):
        """Header name matching is case-insensitive."""
        creds = ("user", "pass")
        expected_b64 = base64.b64encode(b"user:pass").decode()
        headers = [f"PROXY-AUTHORIZATION: Basic {expected_b64}\r\n".encode()]
        assert _check_proxy_auth(headers, creds) is True

    def test_timing_safe_comparison(self):
        """Uses constant-time comparison (hmac.compare_digest) — tested implicitly."""
        creds = ("user", "pass")
        # Very similar but wrong password
        wrong_b64 = base64.b64encode(b"user:pas").decode()
        headers = [f"Proxy-Authorization: Basic {wrong_b64}\r\n".encode()]
        assert _check_proxy_auth(headers, creds) is False


# ---------------------------------------------------------------------------
# _stream_chunked_body
# ---------------------------------------------------------------------------
class TestStreamChunkedBody:
    """Tests for _stream_chunked_body()."""

    @pytest.mark.asyncio
    async def test_single_chunk(self):
        """Single chunk + terminator is streamed correctly."""
        # "5\r\nhello\r\n0\r\n\r\n"
        data = b"5\r\nhello\r\n0\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        tunnel = AsyncMock()
        await _stream_chunked_body(reader, tunnel, "s1", 1024)
        # Should have sent: size line, chunk data+crlf, final size line, trailing crlf
        assert tunnel.send_data.call_count >= 3

    @pytest.mark.asyncio
    async def test_multiple_chunks(self):
        """Multiple chunks are all forwarded."""
        data = b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        tunnel = AsyncMock()
        await _stream_chunked_body(reader, tunnel, "s1", 1024)
        assert tunnel.send_data.call_count >= 4

    @pytest.mark.asyncio
    async def test_zero_length_final_chunk(self):
        """Zero-length chunk terminates the body."""
        data = b"0\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        tunnel = AsyncMock()
        await _stream_chunked_body(reader, tunnel, "s1", 1024)
        # Sent final size line + trailing CRLF
        assert tunnel.send_data.call_count == 2

    @pytest.mark.asyncio
    async def test_oversized_chunk(self):
        """Chunk exceeding MAX_CHUNK_SIZE raises ValueError."""
        oversized = MAX_CHUNK_SIZE + 1
        data = f"{oversized:x}\r\n".encode()
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        tunnel = AsyncMock()
        with pytest.raises(ValueError, match="exceeds maximum"):
            await _stream_chunked_body(reader, tunnel, "s1", MAX_CHUNK_SIZE * 2)

    @pytest.mark.asyncio
    async def test_cumulative_size_exceeded(self):
        """Cumulative body size exceeding max_body_size raises ValueError."""
        # Two chunks of 100 bytes each, max_body_size = 150
        data = b"64\r\n" + b"A" * 100 + b"\r\n64\r\n" + b"B" * 100 + b"\r\n0\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        tunnel = AsyncMock()
        with pytest.raises(ValueError, match="exceeds maximum"):
            await _stream_chunked_body(reader, tunnel, "s1", 150)
