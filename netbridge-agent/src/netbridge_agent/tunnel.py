"""
HTTP CONNECT tunneling for proxy connections.

Implements the HTTP CONNECT method to tunnel TCP connections through
an HTTP proxy. This is the standard mechanism used by browsers for
HTTPS through a proxy.
"""

import asyncio
import base64
from typing import Optional


class ProxyConnectionError(Exception):
    """Error connecting through a proxy."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


def parse_proxy_address(proxy: str) -> tuple[str, int]:
    """
    Parse a proxy address string into host and port.

    Args:
        proxy: Proxy address in format "host:port" or "host" (default port 8080)

    Returns:
        Tuple of (host, port)
    """
    if ":" in proxy:
        host, port_str = proxy.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 8080
    else:
        host = proxy
        port = 8080

    return host, port


async def connect_via_proxy(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    proxy_auth: Optional[tuple[str, str]] = None,
    timeout: float = 30.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Connect to target through HTTP proxy using CONNECT method.

    The HTTP CONNECT method creates a tunnel through the proxy:
    1. Open TCP connection to proxy
    2. Send: CONNECT target:port HTTP/1.1
    3. Read: HTTP/1.1 200 Connection Established
    4. Return the tunneled socket for direct communication

    Args:
        proxy_host: Proxy server hostname
        proxy_port: Proxy server port
        target_host: Target hostname to connect to
        target_port: Target port to connect to
        proxy_auth: Optional (username, password) tuple for proxy authentication
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (StreamReader, StreamWriter) for the tunneled connection

    Raises:
        ProxyConnectionError: If proxy connection or CONNECT fails
        asyncio.TimeoutError: If connection times out
    """
    # Connect to the proxy
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port),
            timeout=timeout,
        )
    except OSError as e:
        raise ProxyConnectionError(f"Cannot connect to proxy {proxy_host}:{proxy_port}: {e}")

    try:
        # Build CONNECT request
        connect_request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        connect_request += f"Host: {target_host}:{target_port}\r\n"

        # Add proxy authentication if provided
        if proxy_auth:
            username, password = proxy_auth
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            connect_request += f"Proxy-Authorization: Basic {credentials}\r\n"

        connect_request += "\r\n"

        # Send CONNECT request
        writer.write(connect_request.encode())
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        # Read response (with timeout)
        response_line = await asyncio.wait_for(
            reader.readline(),
            timeout=timeout,
        )

        if not response_line:
            raise ProxyConnectionError("Proxy closed connection without response")

        response_line = response_line.decode("utf-8", errors="replace").strip()

        # Parse HTTP response: "HTTP/1.1 200 Connection established"
        parts = response_line.split(" ", 2)
        if len(parts) < 2:
            raise ProxyConnectionError(f"Invalid proxy response: {response_line}")

        try:
            status_code = int(parts[1])
        except ValueError:
            raise ProxyConnectionError(f"Invalid proxy response: {response_line}")

        # Read remaining headers until empty line
        while True:
            header_line = await asyncio.wait_for(
                reader.readline(),
                timeout=timeout,
            )
            if not header_line or header_line == b"\r\n":
                break

        # Check status code
        if status_code == 200:
            # Tunnel established successfully
            return reader, writer
        elif status_code == 407:
            raise ProxyConnectionError(
                "Proxy authentication required",
                status_code=status_code,
            )
        elif status_code == 403:
            raise ProxyConnectionError(
                f"Proxy denied connection to {target_host}:{target_port}",
                status_code=status_code,
            )
        elif status_code == 502:
            raise ProxyConnectionError(
                f"Proxy cannot reach {target_host}:{target_port} (Bad Gateway)",
                status_code=status_code,
            )
        elif status_code == 504:
            raise ProxyConnectionError(
                f"Proxy timeout reaching {target_host}:{target_port}",
                status_code=status_code,
            )
        else:
            reason = parts[2] if len(parts) > 2 else "Unknown"
            raise ProxyConnectionError(
                f"Proxy returned {status_code}: {reason}",
                status_code=status_code,
            )

    except ProxyConnectionError:
        # Clean up on error
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise
    except asyncio.TimeoutError:
        # Clean up on timeout
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise
    except Exception as e:
        # Clean up on unexpected error
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise ProxyConnectionError(f"Unexpected error: {type(e).__name__}: {e}")
