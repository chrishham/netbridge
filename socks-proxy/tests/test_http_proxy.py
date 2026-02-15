"""Tests for HTTP proxy header reading (Slowloris protection)."""

import asyncio

import pytest

from socks_proxy.http_proxy import _read_headers, MAX_HEADERS, MAX_HEADER_BYTES, HEADER_READ_TIMEOUT


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
