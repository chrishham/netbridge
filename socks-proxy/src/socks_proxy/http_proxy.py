"""
HTTP Proxy Handler

Implements an HTTP proxy that forwards connections through the network bridge.
Supports:
- HTTP CONNECT method (for HTTPS tunneling)
- HTTP GET/POST/etc (for plain HTTP requests)

This allows tools that don't support SOCKS5 (like Node.js/Undici) to use
the tunnel via standard HTTP_PROXY/HTTPS_PROXY environment variables.
"""

import asyncio
import base64
import hmac
import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from shared_auth import get_int_env

if TYPE_CHECKING:
    from .tunnel import TunnelManager

logger = logging.getLogger(__name__)

# HTTP response templates
HTTP_200_CONNECT = b"HTTP/1.1 200 Connection Established\r\n\r\n"
HTTP_400_BAD_REQUEST = b"HTTP/1.1 400 Bad Request\r\n\r\n"
HTTP_407_PROXY_AUTH = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"NetBridge Proxy\"\r\n\r\n"
HTTP_413_PAYLOAD_TOO_LARGE = b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"
HTTP_502_BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
HTTP_504_TIMEOUT = b"HTTP/1.1 504 Gateway Timeout\r\n\r\n"

# Regex to parse HTTP request line
REQUEST_LINE_RE = re.compile(rb"^([A-Z]+)\s+(\S+)\s+HTTP/(\d\.\d)\r?\n", re.IGNORECASE)

# Maximum chunk size to prevent memory exhaustion (16MB)
MAX_CHUNK_SIZE = 16 * 1024 * 1024

# Maximum total HTTP request body size (default 64MB)
MAX_BODY_SIZE = get_int_env("NETBRIDGE_HTTP_MAX_BODY_BYTES", 64 * 1024 * 1024)

# Streaming chunk size for sending body data through the tunnel
_STREAM_CHUNK_SIZE = 64 * 1024  # 64KB

# Slowloris protection limits
MAX_HEADERS = 100
MAX_HEADER_BYTES = 65536  # 64KB total header size
HEADER_READ_TIMEOUT = 30.0


async def _read_headers(reader: asyncio.StreamReader) -> list[bytes]:
    """Read HTTP headers with limits to prevent Slowloris attacks.

    Raises ValueError if header count or total size exceeds limits.
    """
    headers: list[bytes] = []
    total_bytes = 0

    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=HEADER_READ_TIMEOUT)
        if line in (b"\r\n", b"\n", b""):
            break

        total_bytes += len(line)
        if len(headers) >= MAX_HEADERS:
            raise ValueError(f"Too many headers (>{MAX_HEADERS})")
        if total_bytes > MAX_HEADER_BYTES:
            raise ValueError(f"Headers too large (>{MAX_HEADER_BYTES} bytes)")

        headers.append(line)

    return headers


async def _stream_chunked_body(
    reader: asyncio.StreamReader,
    tunnel: "TunnelManager",
    stream_id: str,
    max_body_size: int,
) -> None:
    """
    Read a chunked transfer-encoded body and stream it through the tunnel.

    Sends chunks incrementally via tunnel.send_data() instead of accumulating
    the entire body in memory. Raises ValueError if cumulative body exceeds
    max_body_size.
    """
    cumulative_bytes = 0

    while True:
        # Read chunk size line (hex size + optional extensions + CRLF)
        size_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
        await tunnel.send_data(stream_id, size_line)

        # Parse chunk size (ignore any chunk extensions after semicolon)
        size_str = size_line.split(b";")[0].strip()
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            break

        if chunk_size == 0:
            # Final chunk - read trailing CRLF
            trailing = await asyncio.wait_for(reader.readline(), timeout=30.0)
            await tunnel.send_data(stream_id, trailing)
            break

        if chunk_size > MAX_CHUNK_SIZE:
            raise ValueError(f"Chunk size {chunk_size} exceeds maximum {MAX_CHUNK_SIZE}")

        cumulative_bytes += chunk_size
        if cumulative_bytes > max_body_size:
            raise ValueError(
                f"Chunked body size {cumulative_bytes} exceeds maximum {max_body_size}"
            )

        # Read chunk data + trailing CRLF
        chunk_data = await asyncio.wait_for(reader.readexactly(chunk_size), timeout=30.0)
        crlf = await asyncio.wait_for(reader.readexactly(2), timeout=30.0)
        await tunnel.send_data(stream_id, chunk_data + crlf)


def _check_proxy_auth(
    headers: list[bytes],
    proxy_credentials: tuple[str, str],
) -> bool:
    """Check Proxy-Authorization header against expected credentials."""
    expected_user, expected_pass = proxy_credentials
    expected = base64.b64encode(
        f"{expected_user}:{expected_pass}".encode()
    ).decode()

    for line in headers:
        if line.lower().startswith(b"proxy-authorization:"):
            value = line.split(b":", 1)[1].strip().decode("utf-8", errors="replace")
            if value.startswith("Basic "):
                return hmac.compare_digest(value[6:].strip(), expected)
    return False


async def handle_http_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tunnel: "TunnelManager",
    proxy_credentials: tuple[str, str] | None = None,
) -> None:
    """
    Handle incoming HTTP proxy connection.

    Supports two modes:
    1. CONNECT method: Establish a tunnel for HTTPS
    2. Other methods: Forward HTTP request through tunnel
    """
    client_addr = writer.get_extra_info("peername")
    stream_id: str | None = None

    try:
        # Read the first line to determine request type
        first_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
        if not first_line:
            return

        match = REQUEST_LINE_RE.match(first_line)
        if not match:
            writer.write(HTTP_400_BAD_REQUEST)
            await writer.drain()
            return

        method = match.group(1).upper()
        target = match.group(2).decode("utf-8", errors="replace")
        http_version = match.group(3).decode("utf-8")

        # For proxy auth, we need to read headers before routing so we
        # can check Proxy-Authorization.  For CONNECT we were already
        # consuming headers inside _handle_connect, so we do it here
        # for both paths when auth is required.
        if proxy_credentials:
            raw_headers = await _read_headers(reader)

            if not _check_proxy_auth(raw_headers, proxy_credentials):
                logger.warning(f"HTTP proxy auth failed from {client_addr}")
                writer.write(HTTP_407_PROXY_AUTH)
                await writer.drain()
                return

            if method == b"CONNECT":
                stream_id = await _handle_connect(
                    reader, writer, tunnel, target, client_addr,
                    headers_already_consumed=True,
                )
            else:
                stream_id = await _handle_http_request(
                    reader, writer, tunnel, method, target, http_version,
                    first_line, client_addr,
                    pre_read_headers=raw_headers,
                )
        else:
            if method == b"CONNECT":
                stream_id = await _handle_connect(
                    reader, writer, tunnel, target, client_addr
                )
            else:
                stream_id = await _handle_http_request(
                    reader, writer, tunnel, method, target, http_version, first_line, client_addr
                )

    except ValueError as e:
        logger.warning(f"HTTP header limit exceeded from {client_addr}: {e}")
        try:
            writer.write(HTTP_400_BAD_REQUEST)
            await writer.drain()
        except Exception:
            pass
    except asyncio.TimeoutError:
        logger.warning(f"HTTP timeout from {client_addr}")
        try:
            writer.write(HTTP_504_TIMEOUT)
            await writer.drain()
        except Exception:
            pass
    except ConnectionResetError:
        logger.warning(f"HTTP connection reset: {client_addr}")
    except Exception as e:
        logger.error(f"HTTP error: {type(e).__name__}: {e}")
        try:
            writer.write(HTTP_502_BAD_GATEWAY)
            await writer.drain()
        except Exception:
            pass
    finally:
        # Clean up stream if created
        if stream_id:
            await tunnel.close_stream(stream_id)

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _handle_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tunnel: "TunnelManager",
    target: str,
    client_addr,
    headers_already_consumed: bool = False,
) -> str | None:
    """
    Handle HTTP CONNECT method (HTTPS tunneling).

    The client sends:
        CONNECT example.com:443 HTTP/1.1
        Host: example.com:443
        ...headers...
        <blank line>

    We:
    1. Read and discard remaining headers
    2. Connect to target through tunnel
    3. Send "200 Connection Established"
    4. Forward raw bytes bidirectionally
    """
    # Parse host:port from target
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            writer.write(HTTP_400_BAD_REQUEST)
            await writer.drain()
            return None
    else:
        # Default to port 443 for CONNECT
        host = target
        port = 443

    # Read remaining headers (until blank line) unless already consumed
    if not headers_already_consumed:
        await _read_headers(reader)

    logger.info(f"HTTP {client_addr} -> CONNECT {host}:{port}")

    # Establish connection through tunnel
    try:
        stream_id = await tunnel.connect(host, port)
    except asyncio.TimeoutError:
        writer.write(HTTP_504_TIMEOUT)
        await writer.drain()
        return None
    except ConnectionError as e:
        logger.warning(f"HTTP connection failed: {e}")
        writer.write(HTTP_502_BAD_GATEWAY)
        await writer.drain()
        return None

    # Send success response
    writer.write(HTTP_200_CONNECT)
    await writer.drain()

    # Forward data bidirectionally
    await tunnel.forward(stream_id, reader, writer)

    return stream_id


async def _handle_http_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tunnel: "TunnelManager",
    method: bytes,
    target: str,
    http_version: str,
    first_line: bytes,
    client_addr,
    pre_read_headers: list[bytes] | None = None,
) -> str | None:
    """
    Handle plain HTTP request (GET, POST, etc.).

    The client sends the full URL:
        GET http://example.com/path HTTP/1.1
        Host: example.com
        ...headers...

    We:
    1. Parse the URL to get host/port/path
    2. Connect to the target
    3. Rewrite request to use relative path
    4. Forward request and response
    """
    # Parse the absolute URL
    parsed = urlparse(target)

    if not parsed.netloc:
        # Not an absolute URL - this is a direct request, not for proxy
        writer.write(HTTP_400_BAD_REQUEST)
        await writer.drain()
        return None

    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    logger.info(f"HTTP {client_addr} -> {method.decode()} {host}:{port}{path}")

    # Connect to target through tunnel
    try:
        stream_id = await tunnel.connect(host, port)
    except asyncio.TimeoutError:
        writer.write(HTTP_504_TIMEOUT)
        await writer.drain()
        return None
    except ConnectionError as e:
        logger.warning(f"HTTP connection failed: {e}")
        writer.write(HTTP_502_BAD_GATEWAY)
        await writer.drain()
        return None

    # Read remaining headers (or use pre-read headers from auth check)
    headers = []
    content_length = 0
    is_chunked = False
    expect_continue = False

    raw_header_lines = pre_read_headers if pre_read_headers is not None else await _read_headers(reader)

    for line in raw_header_lines:
        line_lower = line.lower()
        # Check for Content-Length
        if line_lower.startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                pass
        # Check for Transfer-Encoding: chunked
        elif line_lower.startswith(b"transfer-encoding:"):
            if b"chunked" in line_lower:
                is_chunked = True
        # Check for Expect: 100-continue
        elif line_lower.startswith(b"expect:"):
            if b"100-continue" in line_lower:
                expect_continue = True
        # Skip Proxy-* headers
        if not line_lower.startswith(b"proxy-"):
            headers.append(line)

    # Handle Expect: 100-continue - send 100 Continue before reading body
    if expect_continue:
        writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        await writer.drain()

    # Build the modified request with relative path
    request = f"{method.decode()} {path} HTTP/{http_version}\r\n".encode()
    request += b"".join(headers)
    request += b"\r\n"

    # Send headers through tunnel first
    await tunnel.send_data(stream_id, request)

    # Stream request body if present
    if is_chunked:
        try:
            await _stream_chunked_body(reader, tunnel, stream_id, MAX_BODY_SIZE)
        except ValueError as e:
            logger.warning(f"HTTP body too large: {e}")
            writer.write(HTTP_413_PAYLOAD_TOO_LARGE)
            await writer.drain()
            return stream_id
    elif content_length > 0:
        if content_length > MAX_BODY_SIZE:
            logger.warning(f"HTTP Content-Length {content_length} exceeds limit {MAX_BODY_SIZE}")
            writer.write(HTTP_413_PAYLOAD_TOO_LARGE)
            await writer.drain()
            return stream_id
        # Stream body in chunks instead of reading all at once
        bytes_remaining = content_length
        while bytes_remaining > 0:
            to_read = min(bytes_remaining, _STREAM_CHUNK_SIZE)
            chunk = await asyncio.wait_for(reader.readexactly(to_read), timeout=30.0)
            await tunnel.send_data(stream_id, chunk)
            bytes_remaining -= len(chunk)

    # Forward response back to client
    handler = tunnel.streams.get(stream_id)
    if handler:
        try:
            while True:
                data = await handler.read()
                if data is None:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass

    return stream_id
