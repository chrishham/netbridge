"""
Network Bridge SOCKS5 & HTTP Proxy

A local proxy server that tunnels connections through the bridge relay.
Run this on your laptop to browse internal sites through the network bridge.

Provides two proxy protocols:
- SOCKS5 (port 1080): For browsers, curl --socks5, kubectl with HTTPS_PROXY=socks5://...
- HTTP (port 3128): For Node.js, npm, git, go, and tools that need HTTP_PROXY

Authentication:
- Uses Azure CLI credentials (az login)
- No app registration required
"""

import asyncio
import argparse
import logging
import os
import signal
import sys

from . import __version__
from .socks5 import handle_socks5_client
from .http_proxy import handle_http_client
from .tunnel import TunnelManager, normalize_relay_url
from .auth import get_arm_token, check_az_login, get_user_identity, check_token_expiration

# Default relay hostname (normalize_relay_url in tunnel.py appends /tunnel)
DEFAULT_RELAY_URL = "your-relay-host.example.com"
DEFAULT_SOCKS_PORT = 1080
DEFAULT_HTTP_PORT = 3128
DEFAULT_HOST = "127.0.0.1"

logger = logging.getLogger(__name__)


def _is_loopback(host: str) -> bool:
    """Check if a bind address is loopback-only."""
    return host in ("127.0.0.1", "localhost", "::1")


async def run_server(
    host: str,
    socks_port: int,
    http_port: int | None,
    relay_url: str,
    auth_token: str | None,
    token_refresh_callback=None,
    verify_ssl: bool | None = None,
    proxy_credentials: tuple[str, str] | None = None,
    ca_bundle: str | None = None,
) -> None:
    """Run the SOCKS5 and HTTP proxy servers."""
    # Create and start tunnel manager with auth token
    tunnel = TunnelManager(
        relay_url,
        auth_token=auth_token,
        token_refresh_callback=token_refresh_callback,
        verify_ssl=verify_ssl,
        ca_bundle=ca_bundle,
    )

    try:
        await tunnel.start()
    except ConnectionError as e:
        logger.error(f"Failed to connect to relay: {e}")
        logger.info("Make sure the relay is running and your bridge agent is connected")
        return

    # Create SOCKS5 client handler
    async def socks5_handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        await handle_socks5_client(reader, writer, tunnel, proxy_credentials)

    # Create HTTP client handler
    async def http_handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        await handle_http_client(reader, writer, tunnel, proxy_credentials)

    # Start SOCKS5 server
    socks_server = await asyncio.start_server(socks5_handler, host, socks_port)
    socks_addrs = ", ".join(str(sock.getsockname()) for sock in socks_server.sockets)
    logger.info(f"SOCKS5 proxy listening on {socks_addrs}")

    # Start HTTP proxy server if enabled
    http_server = None
    if http_port is not None:
        http_server = await asyncio.start_server(http_handler, host, http_port)
        http_addrs = ", ".join(str(sock.getsockname()) for sock in http_server.sockets)
        logger.info(f"HTTP proxy listening on {http_addrs}")

    logger.info("")
    logger.info("=" * 60)
    logger.info("PROXY CONFIGURATION")
    logger.info("=" * 60)
    logger.info("")
    logger.info("SOCKS5 Proxy (browsers, curl --socks5):")
    logger.info(f"  Host: {host}  Port: {socks_port}")
    logger.info("")
    logger.info("  Firefox: Settings -> Network Settings -> Manual proxy")
    logger.info(f"           SOCKS Host: {host}, Port: {socks_port}, SOCKS v5")
    logger.info("           Check 'Proxy DNS when using SOCKS v5'")
    logger.info("")
    if http_port is not None:
        logger.info("HTTP Proxy (Node.js, npm, git, go, Claude Code):")
        logger.info(f"  Host: {host}  Port: {http_port}")
        logger.info("")
        logger.info("  PowerShell:")
        logger.info(f'    $env:HTTP_PROXY="http://{host}:{http_port}"')
        logger.info(f'    $env:HTTPS_PROXY="http://{host}:{http_port}"')
        logger.info("")
        logger.info("  Bash/Zsh:")
        logger.info(f'    export HTTP_PROXY="http://{host}:{http_port}"')
        logger.info(f'    export HTTPS_PROXY="http://{host}:{http_port}"')
        logger.info("")
    logger.info("kubectl/helm (can use either):")
    logger.info(f"  SOCKS5: export HTTPS_PROXY=socks5://{host}:{socks_port}")
    if http_port is not None:
        logger.info(f"  HTTP:   export HTTPS_PROXY=http://{host}:{http_port}")
    logger.info("")
    logger.info("=" * 60)
    logger.info("")

    # Handle shutdown gracefully
    stop_event = asyncio.Event()

    def signal_handler():
        logger.info("Shutting down...")
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            # KeyboardInterrupt will be caught below instead
            pass

    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        # Happens on Windows when Ctrl+C is pressed
        pass
    finally:
        # Force close servers immediately without waiting for connections
        socks_server.close()
        if http_server:
            http_server.close()
        await tunnel.stop()


def main():
    """Entry point for the SOCKS5 & HTTP proxy."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="SOCKS5 & HTTP proxy for Network Bridge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netbridge-proxy                         # SOCKS5 on :1080, HTTP on :3128
  netbridge-proxy --port 8080             # SOCKS5 on :8080, HTTP on :3128
  netbridge-proxy --http-port 8888        # SOCKS5 on :1080, HTTP on :8888
  netbridge-proxy --no-http               # SOCKS5 only, no HTTP proxy
  netbridge-proxy --relay custom.example.com
  netbridge-proxy --no-auth               # Disable authentication (local testing)

Environment variables for HTTP proxy clients:
  PowerShell:  $env:HTTP_PROXY="http://127.0.0.1:3128"
               $env:HTTPS_PROXY="http://127.0.0.1:3128"

  Bash/Zsh:    export HTTP_PROXY="http://127.0.0.1:3128"
               export HTTPS_PROXY="http://127.0.0.1:3128"
        """,
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Host to bind to (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_SOCKS_PORT,
        help=f"SOCKS5 port to bind to (default: {DEFAULT_SOCKS_PORT})",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=DEFAULT_HTTP_PORT,
        help=f"HTTP proxy port to bind to (default: {DEFAULT_HTTP_PORT})",
    )
    parser.add_argument(
        "--no-http",
        action="store_true",
        help="Disable HTTP proxy (SOCKS5 only)",
    )
    parser.add_argument(
        "--relay",
        default=DEFAULT_RELAY_URL,
        help=f"Relay hostname or WebSocket URL (default: {DEFAULT_RELAY_URL})",
    )
    parser.add_argument(
        "--token",
        help="ARM access token (use if az cli not available). "
             "Can also be set via NETBRIDGE_TOKEN env var.",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable authentication (for local testing only)",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow binding to non-loopback addresses. Requires --proxy-auth.",
    )
    parser.add_argument(
        "--proxy-auth",
        metavar="USER:PASS",
        help="Require client authentication (user:pass) for SOCKS5 and HTTP proxy. Required when --allow-remote is used.",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="INSECURE: Disable SSL certificate verification. Only use as a last resort when behind a TLS-intercepting proxy. This makes connections vulnerable to man-in-the-middle attacks.",
    )
    parser.add_argument(
        "--ca-bundle",
        metavar="FILE",
        help="Path to a custom CA certificate file for SSL verification. "
             "Use this instead of --no-verify-ssl when behind a TLS-intercepting proxy.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Enforce loopback-only binding unless --allow-remote is set
    if not _is_loopback(args.host) and not args.allow_remote:
        logger.error(
            f"Binding to non-loopback address ({args.host}) requires "
            "--allow-remote flag"
        )
        sys.exit(1)

    # --allow-remote requires --proxy-auth for client authentication
    if args.allow_remote and not args.proxy_auth:
        logger.error("--allow-remote requires --proxy-auth USER:PASS")
        sys.exit(1)

    if args.allow_remote and args.proxy_auth:
        logger.warning("=" * 60)
        logger.warning("SECURITY WARNING: Proxy credentials sent WITHOUT TLS")
        logger.warning("Clients connecting remotely will transmit credentials in cleartext.")
        logger.warning("For production use, place this proxy behind a TLS-terminating")
        logger.warning("reverse proxy (e.g., stunnel, nginx, or HAProxy).")
        logger.warning("=" * 60)

    # Parse proxy auth credentials
    proxy_credentials: tuple[str, str] | None = None
    if args.proxy_auth:
        if ":" not in args.proxy_auth:
            logger.error("--proxy-auth must be in USER:PASS format")
            sys.exit(1)
        user, password = args.proxy_auth.split(":", 1)
        proxy_credentials = (user, password)

    logger.info("")
    logger.info("=" * 60)
    logger.info(f"NetBridge Proxy v{__version__} (SOCKS5 + HTTP)")
    logger.info("=" * 60)
    logger.info("")
    logger.info(f"Connecting to relay: {normalize_relay_url(args.relay)}")

    # Guard --no-verify-ssl: require NETBRIDGE_ALLOW_INSECURE=1
    if args.no_verify_ssl:
        allow_insecure = os.environ.get(
            "NETBRIDGE_ALLOW_INSECURE", ""
        ).lower() in ("1", "true", "yes")
        if not allow_insecure:
            logger.error(
                "--no-verify-ssl requires NETBRIDGE_ALLOW_INSECURE=1 "
                "environment variable. Consider using --ca-bundle instead."
            )
            sys.exit(1)

    # Guard --no-auth: require explicit opt-in and loopback binding
    if args.no_auth:
        allow_no_auth = os.environ.get(
            "NETBRIDGE_ALLOW_NO_AUTH", ""
        ).lower() in ("1", "true", "yes")
        if not allow_no_auth:
            logger.error(
                "--no-auth requires NETBRIDGE_ALLOW_NO_AUTH=true "
                "environment variable"
            )
            sys.exit(1)

        if not _is_loopback(args.host):
            logger.error(
                "--no-auth cannot be used with non-loopback bind address "
                f"({args.host})"
            )
            logger.error("Use --host 127.0.0.1 or remove --no-auth")
            sys.exit(1)

    # Get auth token
    if not args.token:
        env_token = os.environ.get("NETBRIDGE_TOKEN")
        if env_token:
            args.token = env_token
            logger.info("Using token from NETBRIDGE_TOKEN environment variable")

    auth_token = None
    if args.token:
        # Token provided directly - validate it
        auth_token = args.token
        logger.info("Using provided token")
        is_valid, token_msg = check_token_expiration(auth_token)
        if not is_valid:
            logger.error(token_msg)
            logger.info("")
            logger.info("TIP: Get a fresh token:")
            logger.info("  az account get-access-token --resource https://management.azure.com --query accessToken -o tsv")
            return
        logger.info(token_msg)
    elif not args.no_auth:
        # Get token from az cli
        logger.info("Authenticating with Azure CLI...")
        logged_in, message = check_az_login()
        if not logged_in:
            logger.error(message)
            return

        logger.info(message)

        try:
            auth_token = get_arm_token()
            # Validate the token we just got
            is_valid, token_msg = check_token_expiration(auth_token)
            if not is_valid:
                logger.error(token_msg)
                logger.error("This shouldn't happen with a fresh token. Try 'az login' again.")
                return
            user = get_user_identity() or "unknown"
            logger.info(f"Authenticated as: {user}")
            logger.info(token_msg)
        except RuntimeError as e:
            logger.error(f"Authentication failed: {e}")
            return
    else:
        logger.warning("Authentication disabled")

    # Token refresh callback for reconnection (only if using az cli, not manual token)
    token_refresh = get_arm_token if (not args.no_auth and not args.token) else None

    # Determine HTTP proxy port (None if disabled)
    http_port = None if args.no_http else args.http_port

    # Determine SSL verification (None = use env var default)
    verify_ssl = False if args.no_verify_ssl else None

    try:
        asyncio.run(run_server(
            args.host,
            args.port,
            http_port,
            args.relay,
            auth_token,
            token_refresh,
            verify_ssl=verify_ssl,
            proxy_credentials=proxy_credentials,
            ca_bundle=args.ca_bundle,
        ))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    logger.info("Goodbye!")


if __name__ == "__main__":
    main()
