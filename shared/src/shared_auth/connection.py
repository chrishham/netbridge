"""
Connection utilities for Network Bridge.

Contains SSL context, timeout, and connector factory functions
for establishing WebSocket tunnel connections.
"""

import logging
import os
import ssl
from typing import Optional

import aiohttp

from .session import WS_CONNECT_TIMEOUT

logger = logging.getLogger(__name__)


def _get_bool_env(name: str, default: bool) -> bool:
    """Get a boolean from environment variable."""
    value = os.environ.get(name, "").lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


# Default to True for security, allow override via environment
VERIFY_SSL_DEFAULT = _get_bool_env("NETBRIDGE_VERIFY_SSL", True)
ALLOW_INSECURE = _get_bool_env("NETBRIDGE_ALLOW_INSECURE", False)
CA_BUNDLE_DEFAULT = os.environ.get("NETBRIDGE_CA_BUNDLE", "")


def create_tunnel_ssl_context(
    verify: Optional[bool] = None,
    ca_bundle: Optional[str] = None,
) -> ssl.SSLContext:
    """
    Create an SSL context for tunnel connections.

    Args:
        verify: Whether to verify SSL certificates. If None, uses
                NETBRIDGE_VERIFY_SSL environment variable (default: True).
        ca_bundle: Path to a custom CA certificate file. If None, uses
                   NETBRIDGE_CA_BUNDLE environment variable. Use this
                   instead of disabling verification when behind a
                   TLS-intercepting proxy.

    Returns:
        ssl.SSLContext configured for tunnel connections.

    Note:
        Disabling verification requires both NETBRIDGE_VERIFY_SSL=false and
        NETBRIDGE_ALLOW_INSECURE=1. If ALLOW_INSECURE is not set, the request
        to disable verification is ignored and a warning is logged.
    """
    if verify is None:
        verify = VERIFY_SSL_DEFAULT

    ssl_ctx = ssl.create_default_context()

    if not verify:
        if ALLOW_INSECURE:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            logger.warning(
                "TLS certificate verification is DISABLED. "
                "Connections are vulnerable to interception. "
                "Use --ca-bundle or NETBRIDGE_CA_BUNDLE for a safer alternative."
            )
        else:
            logger.warning(
                "NETBRIDGE_VERIFY_SSL=false ignored: "
                "set NETBRIDGE_ALLOW_INSECURE=1 to confirm"
            )

    # Load custom CA bundle if specified
    effective_ca_bundle = ca_bundle or CA_BUNDLE_DEFAULT
    if effective_ca_bundle:
        ssl_ctx.load_verify_locations(cafile=effective_ca_bundle)

    return ssl_ctx


def create_tunnel_timeout(
    connect_timeout: float = WS_CONNECT_TIMEOUT,
) -> aiohttp.ClientTimeout:
    """
    Create a ClientTimeout for tunnel connections.

    Args:
        connect_timeout: Timeout for connection establishment in seconds

    Returns:
        aiohttp.ClientTimeout configured for long-lived WebSocket connections
    """
    return aiohttp.ClientTimeout(
        total=None,  # No total timeout (connection stays open)
        connect=connect_timeout,
        sock_connect=connect_timeout,
    )


def create_tunnel_connector(
    ssl_context: Optional[ssl.SSLContext] = None,
    verify_ssl: Optional[bool] = None,
    ca_bundle: Optional[str] = None,
) -> aiohttp.TCPConnector:
    """
    Create a TCPConnector for tunnel connections.

    Args:
        ssl_context: Optional SSL context. If None, creates one.
        verify_ssl: Whether to verify SSL certificates. Passed to
                    create_tunnel_ssl_context if ssl_context is None.
        ca_bundle: Path to a custom CA certificate file. Passed to
                   create_tunnel_ssl_context if ssl_context is None.

    Returns:
        aiohttp.TCPConnector configured for tunnel connections
    """
    if ssl_context is None:
        ssl_context = create_tunnel_ssl_context(
            verify=verify_ssl, ca_bundle=ca_bundle
        )
    return aiohttp.TCPConnector(ssl=ssl_context)


def build_auth_headers(
    session_id: str,
    auth_token: Optional[str] = None,
) -> dict[str, str]:
    """
    Build HTTP headers for tunnel authentication.

    Args:
        session_id: Unique session identifier
        auth_token: Optional Bearer token for authentication

    Returns:
        Dictionary of headers to include in WebSocket connection
    """
    headers = {
        "X-Session-ID": session_id,
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    return headers
