"""
Agent core - WebSocket connection and TCP tunneling logic.

This module provides the run_agent() function that can be called from the app
with callbacks for status changes. It wraps the existing async_main logic.
"""

import asyncio
import base64
import ipaddress
import json
import logging
import signal
import socket
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse

import aiohttp

from .config import Config, normalize_relay_url, redact_proxy_url
from .tunnel import ProxyAuthRejected
from .auth import (
    get_arm_token,
    check_az_login,
    get_user_identity,
    check_token_expiration,
    get_token_remaining_seconds,
    get_session_id,
    TokenHolder,
    create_tunnel_ssl_context,
    create_tunnel_timeout,
    create_tunnel_connector,
    build_auth_headers,
    RECONNECT_DELAY,
    RECONNECT_DELAY_MAX,
    RECONNECT_BACKOFF_FACTOR,
    HEARTBEAT_INTERVAL,
    CLIENT_HEARTBEAT_INTERVAL,
    IDLE_STREAM_TIMEOUT,
    STALLED_STREAM_CLEANUP_INTERVAL,
    MAX_ACTIVE_STREAMS,
    WS_CONNECT_TIMEOUT,
    MAX_AUTH_FAILURES,
    TOKEN_REFRESH_CHECK_INTERVAL,
    TOKEN_REFRESH_THRESHOLD,
)


logger = logging.getLogger(__name__)

# Constants
TCP_BUFFER_SIZE = 65536
CLEANUP_INTERVAL = STALLED_STREAM_CLEANUP_INTERVAL
STATS_INTERVAL = 60
READ_TIMEOUT = 300
WRITE_TIMEOUT = 30
CONNECTION_LIVENESS_TIMEOUT = 135
APP_HEARTBEAT_INTERVAL = 30
MAX_CONCURRENT_CONNECTIONS = 50
HEALTHY_CONNECTION_THRESHOLD = 60  # seconds — reset backoff if connection lasted this long

# Maximum size for incoming tcp_data payloads (1MB decoded)
MAX_TCP_DATA_SIZE = 1 * 1024 * 1024
# Base64 encodes 3 bytes as 4 chars, so max base64 length for MAX_TCP_DATA_SIZE
_MAX_TCP_DATA_B64_LEN = MAX_TCP_DATA_SIZE * 4 // 3 + 4


# Loopback ranges — blocked by default, can be allowed via allow_loopback config
_LOOPBACK_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

# Link-local ranges are always blocked (agent-local SSRF protection)
_LINK_LOCAL_RANGES = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

# RFC 1918 private ranges, only blocked when allow_private_destinations is False
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


MAX_STREAM_ID_LENGTH = 128


def valid_stream_id(value) -> bool:
    """A stream id is a non-empty str of at most MAX_STREAM_ID_LENGTH chars."""
    return isinstance(value, str) and 0 < len(value) <= MAX_STREAM_ID_LENGTH


def valid_connect_fields(host, port) -> str | None:
    """Return None if host/port are well-formed, else the error text."""
    if not isinstance(host, str) or not host:
        return "Invalid host or port"
    if type(port) is not int or not (1 <= port <= 65535):
        return "Invalid host or port"
    return None


def decode_tcp_payload(value) -> bytes | None:
    """Strictly decode a tcp_data payload; None unless a valid base64 str."""
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except ValueError:  # binascii.Error is a ValueError
        return None


def _normalize_ip(addr):
    """Map an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its IPv4Address.

    Applied before every policy check so ::ffff:127.0.0.1 cannot bypass
    loopback/link-local/private/CIDR rules written for IPv4.
    """
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _normalize_network(net):
    """Rewrite an IPv4-mapped IPv6 network (::ffff:a.b.c.d/N, N >= 96) as IPv4.

    Addresses are normalised to IPv4, and an IPv4Address is never in an
    IPv6Network, so CIDR entries written in mapped form must be rewritten too.
    """
    if (isinstance(net, ipaddress.IPv6Network) and net.prefixlen >= 96
            and net.network_address.ipv4_mapped is not None):
        return ipaddress.ip_network(
            f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    return net


DNS_TIMEOUT = 10.0


class DnsError(OSError):
    """Hostname resolution failed or timed out."""


async def resolve_destination(
    host: str, port: int, timeout: float | None = None,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve host once, bounded, to a deduplicated normalised address list.

    An IP literal is returned as-is (normalised) without any DNS lookup.
    """
    bare_host = host.strip("[]") if host.startswith("[") else host
    try:
        return [_normalize_ip(ipaddress.ip_address(bare_host))]
    except ValueError:
        pass
    limit = timeout if timeout is not None else DNS_TIMEOUT
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(bare_host, port, type=socket.SOCK_STREAM), limit)
    except asyncio.TimeoutError:
        raise DnsError(f"DNS resolution timed out for {host}") from None
    except (OSError, UnicodeError) as e:
        raise DnsError(str(e)) from e
    result: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        try:
            ip = _normalize_ip(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
        if ip not in result:
            result.append(ip)
    return result


async def select_destinations(
    host: str,
    port: int,
    *,
    allowed_destinations: list[str] | None = None,
    denied_destinations: list[str] | None = None,
    allow_private: bool = True,
    allow_loopback: bool = False,
    resolved: list,
) -> tuple[list, str]:
    """Apply the destination policy to already-resolved addresses.

    Loopback (127/8, ::1) and link-local (169.254/16, fe80::/10) are blocked
    by default to prevent SSRF against the agent machine itself. Set
    allow_loopback=True to permit loopback destinations.

    RFC 1918 private ranges are only blocked when allow_private is False.

    A blocked-range hit on ANY address denies the whole destination. The
    deny-CIDR and allowlist rules filter the list. Returns
    (addresses_to_dial, "") or ([], reason).
    """
    bare_host = host.strip("[]") if host.startswith("[") else host
    try:
        host_ip = ipaddress.ip_address(bare_host)
    except ValueError:
        host_ip = None
    resolved_ips = list(resolved)

    # Block link-local (always)
    for ip in resolved_ips:
        for net in _LINK_LOCAL_RANGES:
            if ip in net:
                return [], f"Destination {host} is in a blocked range ({net})"

    # Block loopback (unless allow_loopback is True)
    if not allow_loopback:
        for ip in resolved_ips:
            for net in _LOOPBACK_RANGES:
                if ip in net:
                    return [], f"Destination {host} is in a blocked range ({net})"

    # Check RFC 1918 private ranges (only when allow_private is False)
    if not allow_private:
        for ip in resolved_ips:
            for net in _PRIVATE_RANGES:
                if ip in net:
                    return [], f"Destination {host} is in a private/reserved range ({net})"

    ips = resolved_ips
    # Check denied destinations list (filters; hostname pattern denies)
    if denied_destinations:
        deny_nets = []
        for entry in denied_destinations:
            try:
                deny_nets.append(_normalize_network(ipaddress.ip_network(entry, strict=False)))
            except ValueError:
                if host_ip is None and bare_host.lower() == entry.lower():
                    return [], f"Destination {host} is denied"
        kept = [ip for ip in ips if not any(ip in n for n in deny_nets)]
        if ips and not kept:
            net = next(n for n in deny_nets if ips[0] in n)
            return [], f"Destination {host} is denied (matches {net})"
        ips = kept

    # Check allowed destinations list (if configured, only matches pass)
    if allowed_destinations:
        allow_nets = []
        host_pattern_match = False
        for entry in allowed_destinations:
            try:
                allow_nets.append(_normalize_network(ipaddress.ip_network(entry, strict=False)))
            except ValueError:
                if host_ip is None and bare_host.lower() == entry.lower():
                    host_pattern_match = True
        if not host_pattern_match:
            ips = [ip for ip in ips if any(ip in n for n in allow_nets)]
            if not ips:
                return [], f"Destination {host} is not in the allowed destinations list"

    return ips, ""


async def validate_destination(
    host: str,
    port: int,
    allowed_destinations: list[str] | None = None,
    denied_destinations: list[str] | None = None,
    allow_private: bool = True,
    allow_loopback: bool = False,
    resolved: list | None = None,
) -> tuple[bool, str]:
    """Compatibility wrapper: resolve (unless given) and apply the policy.

    Returns (allowed, reason). A DNS failure counts as no addresses.
    """
    if resolved is None:
        try:
            resolved = await resolve_destination(host, port)
        except DnsError:
            resolved = []
    _ips, err = await select_destinations(
        host, port,
        allowed_destinations=allowed_destinations,
        denied_destinations=denied_destinations,
        allow_private=allow_private,
        allow_loopback=allow_loopback,
        resolved=resolved,
    )
    return err == "", err


# Type for status callback
StatusCallback = Callable[[bool, bool], None]  # (connected, auth_required)
SessionInfoCallback = Callable[[str], None]


@dataclass
class StreamInfo:
    """Information about an active TCP stream."""
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    forward_task: Optional[asyncio.Task]
    host: str
    port: int
    created_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def is_idle(self, timeout: float) -> bool:
        return time.monotonic() - self.last_activity > timeout

    def age(self) -> float:
        return time.monotonic() - self.created_at


class AgentState:
    """Holds mutable state for the agent."""

    def __init__(self):
        self.active_streams: dict[str, StreamInfo] = {}
        self.pending_connections: dict[str, asyncio.Task] = {}
        self._lock: Optional[asyncio.Lock] = None
        self.passthrough_proxy_auth: Optional[tuple[str, str]] = None
        self.passthrough_auth_rejected: bool = False
        self.on_proxy_auth_rejected: Optional[Callable[[], None]] = None
        self.allow_private_destinations: bool = True
        self.allow_loopback: bool = False
        self.allowed_destinations: list[str] = []
        self.denied_destinations: list[str] = []
        self.get_intercept_server: Optional[Callable] = None

    def get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock


def get_system_proxy() -> Optional[str]:
    """Get HTTPS proxy from system settings."""
    proxies = urllib.request.getproxies()
    return proxies.get("https") or proxies.get("http")


def get_proxy_auth_header(proxy_url: Optional[str], cli_user: Optional[str], cli_pass: Optional[str]) -> Optional[str]:
    """Get proxy authentication as an encoded Proxy-Authorization header value."""
    if cli_user:
        return aiohttp.encode_basic_auth(cli_user, cli_pass or "")
    if proxy_url:
        parsed = urlparse(proxy_url)
        if parsed.username:
            return aiohttp.encode_basic_auth(parsed.username, parsed.password or "")
    return None


async def _dial_addresses(addresses: list, port: int, timeout: float):
    """Try each validated address in order within one overall deadline."""
    deadline = time.monotonic() + timeout
    last_exc: BaseException = asyncio.TimeoutError()
    for ip in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(str(ip), port), timeout=remaining)
        except (OSError, asyncio.TimeoutError) as e:
            last_exc = e
    raise last_exc


async def open_tcp_connection(
    host: str,
    port: int,
    timeout: float = 30.0,
    proxy_auth: Optional[tuple[str, str]] = None,
    addresses: Optional[list] = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP connection to the target host.

    With addresses (already validated), dial only those, in order, within
    the overall timeout; host is then used for logging only.
    """
    proxy = None

    if sys.platform == "win32":
        try:
            from .winproxy import get_proxy_for_url_safe
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}/"
            proxy = get_proxy_for_url_safe(url)
            if proxy:
                logger.info(f"Proxy for {host}:{port}: {redact_proxy_url(proxy)}")
        except ImportError:
            pass

    if proxy:
        from .tunnel import connect_via_proxy, parse_proxy_address
        proxy_host, proxy_port = parse_proxy_address(proxy)
        reader, writer = await connect_via_proxy(
            proxy_host, proxy_port, host, port, proxy_auth, timeout
        )
    elif addresses is not None:
        reader, writer = await _dial_addresses(addresses, port, timeout)
    else:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )

    # Enable TCP keepalive
    sock = writer.get_extra_info("socket")
    if sock:
        raw_sock = getattr(sock, "_sock", sock)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if sys.platform == "win32":
            SIO_KEEPALIVE_VALS = 0x98000004
            raw_sock.ioctl(SIO_KEEPALIVE_VALS, (1, 60_000, 15_000))

    return reader, writer


async def send_to_relay(ws, message: dict, timeout: float = WRITE_TIMEOUT, silent: bool = False) -> bool:
    """Send a message to the relay with timeout protection."""
    if ws.closed:
        return False
    try:
        await asyncio.wait_for(ws.send_str(json.dumps(message)), timeout=timeout)
        return True
    except asyncio.TimeoutError:
        if not silent:
            logger.warning(f"Relay send timeout for {message.get('type', 'unknown')}")
        return False
    except Exception as e:
        if not silent:
            logger.warning(f"Relay send error: {type(e).__name__}: {e}")
        return False


async def close_stream(state: AgentState, stream_id: str, timeout: float = 2.0) -> None:
    """Close and clean up a TCP stream."""
    lock = state.get_lock()
    async with lock:
        pending = state.pending_connections.pop(stream_id, None)
        stream = state.active_streams.pop(stream_id, None)

    if pending is not None and not pending.done():
        pending.cancel()
        # asyncio.wait never raises the task's own CancelledError, so an
        # outer cancellation of this coroutine still propagates.
        await asyncio.wait([pending], timeout=timeout)

    if not stream:
        return

    if stream.forward_task and not stream.forward_task.done():
        stream.forward_task.cancel()
        try:
            await asyncio.wait_for(stream.forward_task, timeout=timeout)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    try:
        stream.writer.close()
        await asyncio.wait_for(stream.writer.wait_closed(), timeout=timeout)
    except (asyncio.TimeoutError, Exception):
        pass


async def close_all_streams(state: AgentState, timeout: float = 5.0) -> None:
    """Close all active TCP streams and pending connections."""
    lock = state.get_lock()
    tasks_to_cancel = []
    stream_ids = []

    async with lock:
        if state.pending_connections:
            logger.info(f"Cancelling {len(state.pending_connections)} pending connections...")
            for task in state.pending_connections.values():
                if not task.done():
                    task.cancel()
                    tasks_to_cancel.append(task)
            state.pending_connections.clear()

        if state.active_streams:
            stream_ids = list(state.active_streams.keys())
            logger.info(f"Closing {len(stream_ids)} active streams...")
            for stream in state.active_streams.values():
                if stream.forward_task and not stream.forward_task.done():
                    stream.forward_task.cancel()
                    tasks_to_cancel.append(stream.forward_task)

    if tasks_to_cancel:
        done, pending = await asyncio.wait(tasks_to_cancel, timeout=timeout)
        if pending:
            logger.warning(f"{len(pending)} tasks did not complete in time")

    for stream_id in stream_ids:
        await close_stream(state, stream_id, timeout=1.0)


async def forward_tcp_to_ws(state: AgentState, stream_id: str, reader: asyncio.StreamReader, ws) -> None:
    """Forward data from TCP socket to WebSocket."""
    lock = state.get_lock()

    try:
        while True:
            try:
                data = await asyncio.wait_for(reader.read(TCP_BUFFER_SIZE), timeout=READ_TIMEOUT)
            except asyncio.TimeoutError:
                logger.debug(f"Read timeout: {stream_id}")
                break

            if not data:
                break

            async with lock:
                stream = state.active_streams.get(stream_id)
                if stream:
                    stream.touch()

            success = await send_to_relay(ws, {
                "type": "tcp_data",
                "stream_id": stream_id,
                "data": base64.b64encode(data).decode("ascii"),
            })
            if not success:
                break

    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.debug(f"Forward error {stream_id}: {e}")
    finally:
        await send_to_relay(ws, {
            "type": "tcp_close",
            "stream_id": stream_id,
            "reason": "server_closed",
        }, silent=True)
        await close_stream(state, stream_id)


async def handle_tcp_connect(state: AgentState, ws, request: dict) -> None:
    """Handle TCP connect request."""
    stream_id = request.get("stream_id")
    host = request.get("host")
    port = request.get("port")

    if not valid_stream_id(stream_id):
        logger.warning("tcp_connect with invalid stream_id, dropping")
        return
    err = valid_connect_fields(host, port)
    if err:
        logger.warning(f"tcp_connect {stream_id[:8]}: {err}")
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": err,
        })
        return

    # Before any reply: a rejection for a reused id would make the relay tear
    # down the stream that already owns it.
    if stream_id in state.pending_connections or stream_id in state.active_streams:
        logger.warning(f"tcp_connect {stream_id[:8]}: stream id already in use, ignoring")
        return

    lock = state.get_lock()
    async with lock:
        pending_count = len(state.pending_connections)
        active_count = len(state.active_streams)

    if pending_count >= MAX_CONCURRENT_CONNECTIONS:
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": "Too many pending connections",
        })
        return

    if active_count >= MAX_ACTIVE_STREAMS:
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": "Too many active streams",
        })
        return

    # Intercept magic hostnames
    intercepted = False
    from .intercept import is_magic_hostname
    if is_magic_hostname(host):
        if not state.get_intercept_server:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": "Intercept server is not configured",
            })
            return
        server = state.get_intercept_server()
        if not server:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": "Intercept server is not running",
            })
            return
        intercept_port = server.port_for(host)
        if intercept_port is None:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": f"Service {host} is not available",
            })
            return
        port = intercept_port
        host = "127.0.0.1"
        intercepted = True
        logger.info(
            "Intercept: %s -> %s:%s via 127.0.0.1:%d",
            stream_id[:8], request.get("host"), request.get("port"), port,
        )

    logger.info(f"Connect: {stream_id[:8]} -> {host}:{port}")

    async def do_connect():
        writer = None
        forward_task = None
        registered = False
        try:
            addresses = None
            # Intercepted connections route to our own in-process server,
            # so they skip resolution and validation.
            if not intercepted:
                resolved = await resolve_destination(host, port)
                addresses, dest_reason = await select_destinations(
                    host, port,
                    allowed_destinations=state.allowed_destinations,
                    denied_destinations=state.denied_destinations,
                    allow_private=state.allow_private_destinations,
                    allow_loopback=state.allow_loopback,
                    resolved=resolved,
                )
                if dest_reason or not addresses:
                    logger.warning(
                        f"Destination denied: {stream_id[:8]} -> {host}:{port}: "
                        f"{dest_reason or 'no usable addresses'}")
                    await send_to_relay(ws, {
                        "type": "tcp_connect_result",
                        "stream_id": stream_id,
                        "success": False,
                        "error": f"Destination {host}:{port} is not allowed",
                    })
                    return
            # Skip Basic auth if creds were already rejected this run, to
            # avoid AD account lockout from repeated bad-password attempts.
            proxy_auth = (
                None if state.passthrough_auth_rejected
                else state.passthrough_proxy_auth
            )
            reader, writer = await open_tcp_connection(
                host, port, timeout=30.0, proxy_auth=proxy_auth,
                addresses=addresses,
            )

            forward_task = asyncio.create_task(
                forward_tcp_to_ws(state, stream_id, reader, ws)
            )

            async with lock:
                state.active_streams[stream_id] = StreamInfo(
                    reader=reader,
                    writer=writer,
                    forward_task=forward_task,
                    host=host,
                    port=port,
                )
                registered = True

            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": True,
            })
            logger.info(f"Connected: {stream_id[:8]} -> {host}:{port}")

        except asyncio.CancelledError:
            # Cancelled by tcp_close or session cleanup: release anything
            # acquired but not yet owned by active_streams, then re-raise.
            if not registered:
                if forward_task is not None:
                    forward_task.cancel()
                if writer is not None:
                    try:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                    except Exception:
                        pass
            raise
        except ProxyAuthRejected as e:
            # Disable cached creds in-memory after a single failure so the
            # next request does not retry and risk an AD lockout. The user
            # must update credentials via the tray to re-enable Basic auth.
            if not state.passthrough_auth_rejected:
                state.passthrough_auth_rejected = True
                logger.error(
                    "Stored proxy credentials rejected by the corporate "
                    "proxy. Basic auth disabled for this session — update "
                    "credentials via the NetBridge tray to re-enable."
                )
                if state.on_proxy_auth_rejected:
                    try:
                        state.on_proxy_auth_rejected()
                    except Exception:
                        logger.exception("on_proxy_auth_rejected callback failed")
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": str(e),
            }, silent=True)
            logger.warning(f"Failed: {stream_id[:8]} -> {host}:{port}: {type(e).__name__}: {e}")
        except Exception as e:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": str(e) or type(e).__name__,
            }, silent=True)
            logger.warning(f"Failed: {stream_id[:8]} -> {host}:{port}: {type(e).__name__}: {e}")

    # No await between this check and the registration below, so it is atomic
    # on the loop; a reused id would orphan the first task and its socket.
    if stream_id in state.pending_connections or stream_id in state.active_streams:
        logger.warning(f"tcp_connect {stream_id[:8]}: stream id already in use, ignoring")
        return

    task = asyncio.create_task(do_connect())
    # Register synchronously so the task is in the table before it can
    # finish; the done callback also covers a task cancelled before its
    # first step (its body, and any finally in it, would never run).
    state.pending_connections[stream_id] = task

    def _forget(t: asyncio.Task) -> None:
        if state.pending_connections.get(stream_id) is t:
            del state.pending_connections[stream_id]

    task.add_done_callback(_forget)


async def handle_tcp_data(state: AgentState, request: dict) -> None:
    """Handle incoming TCP data from client."""
    stream_id = request.get("stream_id")
    data_b64 = request.get("data", "")

    if not valid_stream_id(stream_id):
        logger.warning("tcp_data with invalid stream_id, dropping")
        return

    # Guard against oversized payloads
    if isinstance(data_b64, str) and len(data_b64) > _MAX_TCP_DATA_B64_LEN:
        logger.warning(
            f"Oversized tcp_data ({len(data_b64)} chars) for stream "
            f"{stream_id[:8]}, dropping"
        )
        return

    payload = decode_tcp_payload(data_b64)
    if payload is None:
        logger.warning(f"tcp_data with invalid payload for {stream_id[:8]}, closing stream")
        await close_stream(state, stream_id)
        return

    lock = state.get_lock()
    async with lock:
        stream = state.active_streams.get(stream_id)

    if not stream:
        return

    stream.touch()

    try:
        stream.writer.write(payload)
        await stream.writer.drain()
    except Exception as e:
        logger.debug(f"Write error {stream_id}: {e}")
        await close_stream(state, stream_id)


async def handle_tcp_close(state: AgentState, request: dict) -> None:
    """Handle TCP close request from client."""
    stream_id = request.get("stream_id")
    reason = request.get("reason", "unknown")
    if not valid_stream_id(stream_id):
        logger.warning("tcp_close with invalid stream_id, dropping")
        return
    logger.info(f"Closed: {stream_id[:8]} ({reason})")
    await close_stream(state, stream_id)


async def handle_message(state: AgentState, ws, msg: str) -> None:
    """Handle incoming message from relay."""
    try:
        request = json.loads(msg)
        if not isinstance(request, dict):
            logger.warning("Ignoring non-object JSON message")
            return
        msg_type = request.get("type")

        if msg_type == "tcp_connect":
            await handle_tcp_connect(state, ws, request)
        elif msg_type == "tcp_data":
            await handle_tcp_data(state, request)
        elif msg_type == "tcp_close":
            await handle_tcp_close(state, request)
    except json.JSONDecodeError:
        logger.warning("Invalid JSON message received")


async def cleanup_idle_streams(state: AgentState, stop_event: asyncio.Event) -> None:
    """Periodically clean up idle streams."""
    lock = state.get_lock()

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=CLEANUP_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass

        now = time.monotonic()
        idle_streams = []

        async with lock:
            for stream_id, stream in list(state.active_streams.items()):
                if stream.is_idle(IDLE_STREAM_TIMEOUT):
                    idle_streams.append((stream_id, stream))

        for stream_id, stream in idle_streams:
            logger.debug(f"Closing idle stream: {stream_id}")
            await close_stream(state, stream_id)


async def heartbeat_sender(ws, stop_event: asyncio.Event, liveness_tracker: dict) -> None:
    """Send periodic heartbeat messages."""
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=APP_HEARTBEAT_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass

        if ws.closed:
            break

        idle_time = time.monotonic() - liveness_tracker["last_message_time"]
        success = await send_to_relay(ws, {"type": "heartbeat"}, silent=True)
        if not success:
            logger.warning("Heartbeat send failed")
            break


async def token_refresh_loop(token_holder: TokenHolder, stop_event: asyncio.Event) -> None:
    """Proactively refresh token before it expires."""
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=TOKEN_REFRESH_CHECK_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass

        token = token_holder.get()
        if not token or not token_holder.refresh_callback:
            continue

        remaining = get_token_remaining_seconds(token)
        if remaining is None:
            continue

        if remaining < TOKEN_REFRESH_THRESHOLD:
            logger.info(f"Token expires in {int(remaining)}s, refreshing...")
            loop = asyncio.get_running_loop()
            try:
                success = await asyncio.wait_for(
                    loop.run_in_executor(None, token_holder.refresh),
                    timeout=60.0,
                )
                if success:
                    logger.info("Token refreshed successfully")
                else:
                    logger.warning("Token refresh failed")
            except asyncio.TimeoutError:
                logger.warning("Token refresh timed out")


async def connect_and_run(
    state: AgentState,
    relay_url: str,
    proxy: Optional[str],
    proxy_auth_header: Optional[str],
    auth_token: Optional[str],
    stop_event: asyncio.Event,
    on_status_change: Optional[StatusCallback],
    on_session_info: Optional[SessionInfoCallback],
) -> tuple[bool, float]:
    """Establish WebSocket connection and process messages.

    Returns (intentional_stop, connection_duration_seconds).
    """
    connector = create_tunnel_connector()
    session_id = get_session_id()
    headers = build_auth_headers(session_id, auth_token)
    timeout = create_tunnel_timeout()
    proxy_headers = {"Proxy-Authorization": proxy_auth_header} if proxy_auth_header else None

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async with session.ws_connect(
            relay_url,
            proxy=proxy,
            proxy_headers=proxy_headers,
            heartbeat=CLIENT_HEARTBEAT_INTERVAL,
            headers=headers,
        ) as ws:
            # Wait for registration
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=10.0)
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except ValueError:
                        data = None
                    if not isinstance(data, dict):
                        logger.warning("Malformed registration frame from relay")
                        return False, 0.0
                    if data.get("type") == "registered":
                        logger.info(f"Connected to relay (session: {session_id})")
                        connected_at = time.monotonic()
                        if on_status_change:
                            on_status_change(True, False)
                        if on_session_info:
                            on_session_info(session_id)
                    else:
                        logger.warning(f"Unexpected first message: {data.get('type')}")
                        return False, 0.0
                else:
                    logger.warning(f"Unexpected message type: {msg.type}")
                    return False, 0.0
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for registration")
                return False, 0.0

            liveness_tracker = {"last_message_time": time.monotonic()}
            heartbeat_task = asyncio.create_task(
                heartbeat_sender(ws, stop_event, liveness_tracker)
            )

            try:
                while not stop_event.is_set():
                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=1.0)
                    except asyncio.TimeoutError:
                        idle_time = time.monotonic() - liveness_tracker["last_message_time"]
                        if idle_time > CONNECTION_LIVENESS_TIMEOUT:
                            logger.warning(f"No messages for {int(idle_time)}s, assuming dead")
                            break
                        continue

                    liveness_tracker["last_message_time"] = time.monotonic()

                    if msg.type == aiohttp.WSMsgType.TEXT:
                        try:
                            data = json.loads(msg.data)
                            if isinstance(data, dict) and data.get("type") == "heartbeat_ack":
                                continue
                        except json.JSONDecodeError:
                            pass
                        await handle_message(state, ws, msg.data)
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        logger.error(f"WebSocket error: {ws.exception()}")
                        break
                    elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSE):
                        logger.info("Connection closed by server")
                        break

                return stop_event.is_set(), time.monotonic() - connected_at

            finally:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass

                if not ws.closed:
                    try:
                        await asyncio.wait_for(ws.close(), timeout=2.0)
                    except Exception:
                        pass

                await close_all_streams(state)


def _initial_auth() -> tuple[Optional[str], Optional[str]]:
    """Check az login and fetch an ARM token.

    Returns:
        (token, None) on success, (None, error_message) on failure.
    """
    logged_in, message = check_az_login()
    if not logged_in:
        return None, message
    logger.info(message)

    try:
        auth_token = get_arm_token()
        is_valid, token_msg = check_token_expiration(auth_token)
        if not is_valid:
            return None, token_msg

        user = get_user_identity() or "unknown"
        logger.info(f"Authenticated as: {user}")
        return auth_token, None
    except RuntimeError as e:
        return None, str(e)


async def run_agent(
    relay_url: str,
    stop_event: asyncio.Event,
    on_status_change: Optional[StatusCallback] = None,
    on_session_info: Optional[SessionInfoCallback] = None,
    on_proxy_auth_rejected: Optional[Callable[[], None]] = None,
    get_intercept_server: Optional[Callable] = None,
) -> None:
    """Main agent loop with reconnection logic.

    Args:
        relay_url: WebSocket URL of the relay server
        stop_event: Event to signal shutdown
        on_status_change: Callback for status changes (connected, auth_required)
        on_session_info: Callback for session info updates
        on_proxy_auth_rejected: Called once when stored proxy creds are
            rejected by the corporate proxy (so the UI can prompt the user
            to update them).
        get_intercept_server: Callback returning the InterceptServer instance.
    """
    relay_url = normalize_relay_url(relay_url)
    state = AgentState()
    state.on_proxy_auth_rejected = on_proxy_auth_rejected
    state.get_intercept_server = get_intercept_server

    # Apply destination filtering config
    config = Config.load()
    state.allow_private_destinations = config.allow_private_destinations
    state.allow_loopback = config.allow_loopback
    state.allowed_destinations = config.allowed_destinations
    state.denied_destinations = config.denied_destinations

    # Load passthrough proxy credentials (used as fallback when SSPI fails or
    # the corporate proxy demands Basic auth)
    try:
        from .credstore import load_proxy_credentials
        creds = load_proxy_credentials()
        if creds:
            state.passthrough_proxy_auth = creds
            logger.info(f"Passthrough proxy auth loaded for user: {creds[0]}")
    except Exception as e:
        logger.warning(f"Failed to load passthrough proxy creds: {e}")

    # Get authentication. Retry with backoff rather than giving up: a failure
    # here is often transient (az CLI timing out on a slow host, network not
    # up yet at logon), and returning would leave the process alive but
    # permanently disconnected. Once the user runs 'az login', the next
    # attempt picks it up.
    auth_token = None
    token_refresh = get_arm_token
    auth_delay = RECONNECT_DELAY
    loop = asyncio.get_running_loop()

    while not stop_event.is_set():
        logger.info("Authenticating with Azure CLI...")
        # az CLI calls block for up to AZ_CLI_TIMEOUT; keep them off the
        # event loop so the intercept server stays responsive.
        auth_token, error = await loop.run_in_executor(None, _initial_auth)
        if auth_token:
            break

        logger.error(f"Auth failed: {error}")
        if on_status_change:
            on_status_change(False, True)
        logger.info(f"Retrying authentication in {auth_delay}s...")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=auth_delay)
        except asyncio.TimeoutError:
            pass
        auth_delay = min(auth_delay * RECONNECT_BACKOFF_FACTOR, RECONNECT_DELAY_MAX)

    if not auth_token:
        return

    # Get proxy settings
    proxy = get_system_proxy()
    if proxy:
        logger.info(f"Relay proxy: {redact_proxy_url(proxy)}")
    proxy_auth_header = get_proxy_auth_header(proxy, None, None)

    # Token holder for refresh
    token_holder = TokenHolder(auth_token, token_refresh)

    # Start background tasks
    cleanup_task = asyncio.create_task(cleanup_idle_streams(state, stop_event))
    refresh_task = asyncio.create_task(token_refresh_loop(token_holder, stop_event))

    current_delay = RECONNECT_DELAY

    try:
        while not stop_event.is_set():
            # Check token before connecting
            current_token = token_holder.get()
            if current_token:
                is_valid, token_msg = check_token_expiration(current_token)
                if not is_valid:
                    logger.warning(token_msg)
                    if token_holder.refresh():
                        logger.info("Token refreshed")
                    else:
                        token_holder.failure_count += 1
                        if token_holder.failure_count >= MAX_AUTH_FAILURES:
                            logger.error("Max auth failures reached")
                            if on_status_change:
                                on_status_change(False, True)
                            break

            try:
                if on_status_change:
                    on_status_change(False, False)  # Connecting

                intentional_stop, duration = await connect_and_run(
                    state, relay_url, proxy, proxy_auth_header,
                    token_holder.get(), stop_event,
                    on_status_change, on_session_info,
                )

                if stop_event.is_set():
                    break

                if intentional_stop or duration > 0:
                    # Successfully registered with relay — reset auth failure count
                    token_holder.failure_count = 0
                if intentional_stop:
                    current_delay = RECONNECT_DELAY
                elif duration >= HEALTHY_CONNECTION_THRESHOLD:
                    # Connection was alive long enough — not a connect failure
                    current_delay = RECONNECT_DELAY

            except aiohttp.WSServerHandshakeError as e:
                logger.error(f"Handshake failed: {e.status} {e.message}")
                if e.status == 401:
                    token_holder.failure_count += 1
                    if token_holder.failure_count >= MAX_AUTH_FAILURES:
                        logger.error("Max auth failures reached")
                        if on_status_change:
                            on_status_change(False, True)
                        break
                    if token_holder.refresh():
                        logger.info("Token refreshed after 401")
                elif e.status == 403:
                    logger.error("Access forbidden")
                    if on_status_change:
                        on_status_change(False, True)
                    break

            except aiohttp.ClientError as e:
                logger.error(f"Connection error: {e}")

            except Exception as e:
                logger.error(f"Unexpected error: {e}")

            if not stop_event.is_set():
                if on_status_change:
                    on_status_change(False, False)
                logger.info(f"Reconnecting in {current_delay}s...")
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=current_delay)
                except asyncio.TimeoutError:
                    pass
                current_delay = min(current_delay * RECONNECT_BACKOFF_FACTOR, RECONNECT_DELAY_MAX)

    finally:
        cleanup_task.cancel()
        refresh_task.cancel()
        for task in (cleanup_task, refresh_task):
            try:
                await task
            except asyncio.CancelledError:
                pass

        await close_all_streams(state, timeout=3.0)
        logger.info("Agent stopped")
