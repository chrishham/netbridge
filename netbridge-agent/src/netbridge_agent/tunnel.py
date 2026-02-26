"""
HTTP CONNECT tunneling for proxy connections.

Implements the HTTP CONNECT method to tunnel TCP connections through
an HTTP proxy. This is the standard mechanism used by browsers for
HTTPS through a proxy.

Supports transparent NTLM/Negotiate authentication on Windows via SSPI,
as well as Basic auth fallback.
"""

import asyncio
import base64
import logging
import sys
from typing import Optional

logger = logging.getLogger(__name__)


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


async def _send_connect_request(
    writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    auth_header: Optional[str] = None,
    timeout: float = 30.0,
) -> None:
    """Send an HTTP CONNECT request to the proxy.

    Args:
        writer: Stream writer to the proxy
        target_host: Target hostname
        target_port: Target port
        auth_header: Optional Proxy-Authorization header value (full value, e.g. "Basic ...")
        timeout: Write timeout in seconds
    """
    request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
    request += f"Host: {target_host}:{target_port}\r\n"
    if auth_header:
        request += f"Proxy-Authorization: {auth_header}\r\n"
    request += "\r\n"

    writer.write(request.encode())
    await asyncio.wait_for(writer.drain(), timeout=timeout)


async def _read_proxy_response(
    reader: asyncio.StreamReader,
    timeout: float = 30.0,
) -> tuple[int, dict[str, list[str]]]:
    """Read and parse an HTTP response from the proxy.

    Returns:
        Tuple of (status_code, headers) where headers is a dict mapping
        lowercase header names to lists of values (to handle multiple
        Proxy-Authenticate headers).

    Raises:
        ProxyConnectionError: If the response is malformed
    """
    response_line = await asyncio.wait_for(reader.readline(), timeout=timeout)

    if not response_line:
        raise ProxyConnectionError("Proxy closed connection without response")

    response_line = response_line.decode("utf-8", errors="replace").strip()

    # Parse "HTTP/1.1 200 Connection established"
    parts = response_line.split(" ", 2)
    if len(parts) < 2:
        raise ProxyConnectionError(f"Invalid proxy response: {response_line}")

    try:
        status_code = int(parts[1])
    except ValueError:
        raise ProxyConnectionError(f"Invalid proxy response: {response_line}")

    # Read headers until empty line
    headers: dict[str, list[str]] = {}
    while True:
        header_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not header_line or header_line == b"\r\n":
            break
        decoded = header_line.decode("utf-8", errors="replace").strip()
        if ":" in decoded:
            name, value = decoded.split(":", 1)
            name = name.strip().lower()
            value = value.strip()
            headers.setdefault(name, []).append(value)

    return status_code, headers


def _select_auth_scheme(headers: dict[str, list[str]]) -> Optional[str]:
    """Pick the best auth scheme from Proxy-Authenticate headers.

    Prefers Negotiate over NTLM (Negotiate can use Kerberos when available,
    falling back to NTLM automatically).

    Returns:
        "Negotiate", "NTLM", or None if neither is offered.
    """
    auth_headers = headers.get("proxy-authenticate", [])
    schemes = set()
    for value in auth_headers:
        # Header can be "Negotiate" or "Negotiate <token>" or "NTLM"
        scheme = value.split()[0]
        schemes.add(scheme.lower())

    if "negotiate" in schemes:
        return "Negotiate"
    if "ntlm" in schemes:
        return "NTLM"
    return None


def _extract_challenge_token(headers: dict[str, list[str]], scheme: str) -> Optional[str]:
    """Extract the base64 challenge token from Proxy-Authenticate headers.

    Args:
        headers: Response headers dict
        scheme: Auth scheme to look for ("Negotiate" or "NTLM")

    Returns:
        Base64-encoded challenge token, or None if header has no token body.
    """
    auth_headers = headers.get("proxy-authenticate", [])
    for value in auth_headers:
        parts = value.split(None, 1)
        if parts[0].lower() == scheme.lower() and len(parts) > 1:
            return parts[1].strip()
    return None


async def _sspi_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    proxy_host: str,
    scheme: str,
    challenge_headers: dict[str, list[str]],
    timeout: float = 30.0,
) -> tuple[int, dict[str, list[str]]]:
    """Perform SSPI NTLM/Negotiate handshake on the existing connection.

    This implements the multi-step authentication dance:
    1. Generate Type 1 token → send CONNECT with token
    2. Read 407 with Type 2 challenge
    3. Generate Type 3 response token → send CONNECT with token
    4. Read final response (should be 200)

    Args:
        reader: Existing stream reader to the proxy
        writer: Existing stream writer to the proxy
        target_host: Target hostname for CONNECT
        target_port: Target port for CONNECT
        proxy_host: Proxy hostname (used as SPN target)
        scheme: Auth scheme ("Negotiate" or "NTLM")
        challenge_headers: Headers from the initial 407 response (may contain
            a challenge token if the proxy sent one with the first 407)
        timeout: Timeout for each I/O operation

    Returns:
        Tuple of (status_code, headers) from the final response

    Raises:
        ProxyConnectionError: If SSPI operations fail
    """
    from .winauth import SSPIAuth

    spn = f"HTTP/{proxy_host}"
    auth = SSPIAuth(scheme)

    try:
        # Check if the initial 407 already included a challenge token
        # (some proxies send the challenge with the first 407)
        initial_challenge = _extract_challenge_token(challenge_headers, scheme)

        if initial_challenge:
            # Proxy already sent a challenge - generate response directly
            logger.debug("SSPI: proxy sent challenge with initial 407, generating response")
            token = auth.get_response_token(spn, initial_challenge)
        else:
            # Step 1: Generate Type 1 (negotiate) token
            logger.debug("SSPI: generating Type 1 token")
            token = auth.get_initial_token(spn)

        # Send CONNECT with Type 1 (or response) token
        await _send_connect_request(
            writer, target_host, target_port,
            auth_header=f"{scheme} {token}",
            timeout=timeout,
        )
        status, headers = await _read_proxy_response(reader, timeout=timeout)

        if status == 200:
            logger.debug("SSPI: auth completed after first token")
            return status, headers

        if status != 407:
            return status, headers

        # Step 2: Extract Type 2 challenge from the 407 response
        challenge = _extract_challenge_token(headers, scheme)
        if not challenge:
            raise ProxyConnectionError(
                f"Proxy returned 407 without {scheme} challenge token"
            )

        # Step 3: Generate Type 3 (authentication) token
        logger.debug("SSPI: generating Type 3 response token")
        response_token = auth.get_response_token(spn, challenge)

        # Send CONNECT with Type 3 token
        await _send_connect_request(
            writer, target_host, target_port,
            auth_header=f"{scheme} {response_token}",
            timeout=timeout,
        )
        status, headers = await _read_proxy_response(reader, timeout=timeout)
        logger.debug("SSPI: final response status=%d", status)
        return status, headers

    finally:
        auth.close()


def _raise_for_status(
    status_code: int,
    target_host: str,
    target_port: int,
    response_parts: Optional[list[str]] = None,
) -> None:
    """Raise ProxyConnectionError for non-200 status codes.

    Args:
        status_code: HTTP status code from the proxy
        target_host: Target hostname (for error messages)
        target_port: Target port (for error messages)
        response_parts: Split response line parts (for extracting reason phrase)
    """
    if status_code == 200:
        return

    if status_code == 407:
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
        reason = "Unknown"
        if response_parts and len(response_parts) > 2:
            reason = response_parts[2]
        raise ProxyConnectionError(
            f"Proxy returned {status_code}: {reason}",
            status_code=status_code,
        )


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

    Supports:
    - Unauthenticated CONNECT
    - Basic authentication (via proxy_auth credentials)
    - NTLM/Negotiate authentication via Windows SSPI (automatic, no config needed)

    The NTLM/Negotiate flow keeps the TCP connection alive across the
    multi-step handshake, as NTLM is connection-oriented.

    Args:
        proxy_host: Proxy server hostname
        proxy_port: Proxy server port
        target_host: Target hostname to connect to
        target_port: Target port to connect to
        proxy_auth: Optional (username, password) tuple for Basic proxy authentication
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
        # Step 1: Send initial CONNECT (with Basic auth if credentials provided)
        basic_header = None
        if proxy_auth:
            username, password = proxy_auth
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            basic_header = f"Basic {credentials}"

        await _send_connect_request(
            writer, target_host, target_port,
            auth_header=basic_header,
            timeout=timeout,
        )
        status, headers = await _read_proxy_response(reader, timeout=timeout)

        # Step 2: If 200, tunnel is established
        if status == 200:
            return reader, writer

        # Step 3: If 407, try SSPI auth on Windows (Negotiate/NTLM)
        if status == 407 and sys.platform == "win32":
            scheme = _select_auth_scheme(headers)
            if scheme:
                try:
                    logger.info(
                        "Proxy requires auth, attempting SSPI %s for %s:%d",
                        scheme, target_host, target_port,
                    )
                    status, headers = await _sspi_handshake(
                        reader, writer,
                        target_host, target_port,
                        proxy_host, scheme,
                        challenge_headers=headers,
                        timeout=timeout,
                    )
                    if status == 200:
                        logger.info("SSPI %s auth successful", scheme)
                        return reader, writer
                    # Fall through to error handling below
                    logger.warning(
                        "SSPI %s auth failed with status %d", scheme, status
                    )
                except Exception as e:
                    logger.warning("SSPI %s auth error: %s", scheme, e)
                    # Fall through to raise the 407 error

        # Step 4: Raise appropriate error
        _raise_for_status(status, target_host, target_port)

        # _raise_for_status always raises for non-200, but just in case:
        return reader, writer

    except ProxyConnectionError:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise
    except asyncio.TimeoutError:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise
    except Exception as e:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise ProxyConnectionError(f"Unexpected error: {type(e).__name__}: {e}")
