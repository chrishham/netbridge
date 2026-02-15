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
TCP_BUFFER_SIZE = 8192
CLEANUP_INTERVAL = STALLED_STREAM_CLEANUP_INTERVAL
STATS_INTERVAL = 60
READ_TIMEOUT = 300
WRITE_TIMEOUT = 30
CONNECTION_LIVENESS_TIMEOUT = 90
APP_HEARTBEAT_INTERVAL = 30
MAX_CONCURRENT_CONNECTIONS = 50

# Maximum size for incoming tcp_data payloads (1MB decoded)
MAX_TCP_DATA_SIZE = 1 * 1024 * 1024
# Base64 encodes 3 bytes as 4 chars, so max base64 length for MAX_TCP_DATA_SIZE
_MAX_TCP_DATA_B64_LEN = MAX_TCP_DATA_SIZE * 4 // 3 + 4


# Loopback and link-local ranges are always blocked (agent-local SSRF protection)
_ALWAYS_BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

# RFC 1918 private ranges, only blocked when allow_private_destinations is False
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


async def validate_destination(
    host: str,
    port: int,
    allowed_destinations: list[str] | None = None,
    denied_destinations: list[str] | None = None,
    allow_private: bool = True,
) -> tuple[bool, str]:
    """Validate a destination against blocked ranges and optional lists.

    Loopback (127/8, ::1) and link-local (169.254/16, fe80::/10) are always
    blocked to prevent SSRF against the agent machine itself.

    RFC 1918 private ranges (10/8, 172.16/12, 192.168/16) are only blocked
    when allow_private is False. When True (default), private ranges are
    allowed for corporate/VDI environments.

    Returns (allowed, reason).
    """
    # Strip IPv6 brackets (e.g. [::1] -> ::1)
    bare_host = host.strip("[]") if host.startswith("[") else host

    try:
        host_ip = ipaddress.ip_address(bare_host)
    except ValueError:
        host_ip = None

    # Collect all IPs to check against CIDR rules
    resolved_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    if host_ip is not None:
        resolved_ips.append(host_ip)
    else:
        # Resolve hostname to IP addresses for CIDR checking
        try:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(bare_host, None)
            for _family, _type, _proto, _canonname, sockaddr in infos:
                try:
                    resolved_ips.append(ipaddress.ip_address(sockaddr[0]))
                except ValueError:
                    pass
        except (OSError, UnicodeError):
            pass  # DNS failure — fall through to hostname pattern checks

    # Always block loopback and link-local (agent-local SSRF protection)
    for ip in resolved_ips:
        for net in _ALWAYS_BLOCKED_RANGES:
            if ip in net:
                return False, f"Destination {host} is in a blocked range ({net})"

    # Check RFC 1918 private ranges (only when allow_private is False)
    if not allow_private:
        for ip in resolved_ips:
            for net in _PRIVATE_RANGES:
                if ip in net:
                    return False, f"Destination {host} is in a private/reserved range ({net})"

    # Check denied destinations list
    if denied_destinations:
        for entry in denied_destinations:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                for ip in resolved_ips:
                    if ip in net:
                        return False, f"Destination {host} is denied (matches {net})"
            except ValueError:
                # Treat as hostname pattern
                if host_ip is None and bare_host.lower() == entry.lower():
                    return False, f"Destination {host} is denied"

    # Check allowed destinations list (if configured, only allow matches)
    if allowed_destinations:
        for entry in allowed_destinations:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                for ip in resolved_ips:
                    if ip in net:
                        return True, ""
            except ValueError:
                if host_ip is None and bare_host.lower() == entry.lower():
                    return True, ""
        return False, f"Destination {host} is not in the allowed destinations list"

    return True, ""


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
        self.allow_private_destinations: bool = True
        self.allowed_destinations: list[str] = []
        self.denied_destinations: list[str] = []

    def get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock


def get_system_proxy() -> Optional[str]:
    """Get HTTPS proxy from system settings."""
    proxies = urllib.request.getproxies()
    return proxies.get("https") or proxies.get("http")


def get_proxy_auth(proxy_url: Optional[str], cli_user: Optional[str], cli_pass: Optional[str]) -> Optional[aiohttp.BasicAuth]:
    """Get proxy authentication."""
    if cli_user:
        return aiohttp.BasicAuth(cli_user, cli_pass or "")
    if proxy_url:
        parsed = urlparse(proxy_url)
        if parsed.username:
            return aiohttp.BasicAuth(parsed.username, parsed.password or "")
    return None


async def open_tcp_connection(
    host: str,
    port: int,
    timeout: float = 30.0,
    proxy_auth: Optional[tuple[str, str]] = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP connection to the target host."""
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
        stream = state.active_streams.pop(stream_id, None)

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

    # Validate destination against private ranges and config lists
    dest_allowed, dest_reason = await validate_destination(
        host, port, state.allowed_destinations, state.denied_destinations,
        allow_private=state.allow_private_destinations
    )
    if not dest_allowed:
        logger.warning(f"Destination denied: {stream_id[:8]} -> {host}:{port}: {dest_reason}")
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": f"Destination {host}:{port} is not allowed",
        })
        return

    logger.info(f"Connect: {stream_id[:8]} -> {host}:{port}")

    async def do_connect():
        try:
            reader, writer = await open_tcp_connection(
                host, port, timeout=30.0, proxy_auth=state.passthrough_proxy_auth
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

            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": True,
            })
            logger.info(f"Connected: {stream_id[:8]} -> {host}:{port}")

        except Exception as e:
            await send_to_relay(ws, {
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": str(e),
            }, silent=True)
            logger.warning(f"Failed: {stream_id[:8]} -> {host}:{port}: {e}")
        finally:
            async with lock:
                state.pending_connections.pop(stream_id, None)

    task = asyncio.create_task(do_connect())
    async with lock:
        state.pending_connections[stream_id] = task


async def handle_tcp_data(state: AgentState, request: dict) -> None:
    """Handle incoming TCP data from client."""
    stream_id = request.get("stream_id")
    data_b64 = request.get("data", "")

    # Guard against oversized payloads
    if len(data_b64) > _MAX_TCP_DATA_B64_LEN:
        logger.warning(
            f"Oversized tcp_data ({len(data_b64)} chars) for stream "
            f"{stream_id[:8] if stream_id else '?'}, dropping"
        )
        return

    lock = state.get_lock()
    async with lock:
        stream = state.active_streams.get(stream_id)

    if not stream:
        return

    stream.touch()

    try:
        data = base64.b64decode(data_b64)
        stream.writer.write(data)
        await stream.writer.drain()
    except Exception as e:
        logger.debug(f"Write error {stream_id}: {e}")
        await close_stream(state, stream_id)


async def handle_tcp_close(state: AgentState, request: dict) -> None:
    """Handle TCP close request from client."""
    stream_id = request.get("stream_id")
    reason = request.get("reason", "unknown")
    logger.info(f"Closed: {stream_id[:8]} ({reason})")
    await close_stream(state, stream_id)


async def handle_message(state: AgentState, ws, msg: str) -> None:
    """Handle incoming message from relay."""
    try:
        request = json.loads(msg)
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
            loop = asyncio.get_event_loop()
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
    proxy_auth: Optional[aiohttp.BasicAuth],
    auth_token: Optional[str],
    stop_event: asyncio.Event,
    on_status_change: Optional[StatusCallback],
    on_session_info: Optional[SessionInfoCallback],
) -> bool:
    """Establish WebSocket connection and process messages.

    Returns True if connection was successful and ended normally.
    """
    connector = create_tunnel_connector()
    session_id = get_session_id()
    headers = build_auth_headers(session_id, auth_token)
    timeout = create_tunnel_timeout()

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async with session.ws_connect(
            relay_url,
            proxy=proxy,
            proxy_auth=proxy_auth,
            heartbeat=HEARTBEAT_INTERVAL,
            headers=headers,
        ) as ws:
            # Wait for registration
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=10.0)
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    if data.get("type") == "registered":
                        logger.info(f"Connected to relay (session: {session_id})")
                        if on_status_change:
                            on_status_change(True, False)
                        if on_session_info:
                            on_session_info(session_id)
                    else:
                        logger.warning(f"Unexpected first message: {data.get('type')}")
                        return False
                else:
                    logger.warning(f"Unexpected message type: {msg.type}")
                    return False
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for registration")
                return False

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
                            if data.get("type") == "heartbeat_ack":
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

                return stop_event.is_set()  # True if we stopped intentionally

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


async def run_agent(
    relay_url: str,
    stop_event: asyncio.Event,
    on_status_change: Optional[StatusCallback] = None,
    on_session_info: Optional[SessionInfoCallback] = None,
) -> None:
    """Main agent loop with reconnection logic.

    Args:
        relay_url: WebSocket URL of the relay server
        stop_event: Event to signal shutdown
        on_status_change: Callback for status changes (connected, auth_required)
        on_session_info: Callback for session info updates
    """
    relay_url = normalize_relay_url(relay_url)
    state = AgentState()

    # Apply destination filtering config
    config = Config.load()
    state.allow_private_destinations = config.allow_private_destinations
    state.allowed_destinations = config.allowed_destinations
    state.denied_destinations = config.denied_destinations

    # Get authentication
    auth_token = None
    token_refresh = None

    logger.info("Authenticating with Azure CLI...")
    logged_in, message = check_az_login()
    if not logged_in:
        logger.error(f"Auth failed: {message}")
        if on_status_change:
            on_status_change(False, True)
        return

    logger.info(message)

    try:
        auth_token = get_arm_token()
        is_valid, token_msg = check_token_expiration(auth_token)
        if not is_valid:
            logger.error(token_msg)
            if on_status_change:
                on_status_change(False, True)
            return

        user = get_user_identity() or "unknown"
        logger.info(f"Authenticated as: {user}")
        token_refresh = get_arm_token
    except RuntimeError as e:
        logger.error(f"Auth failed: {e}")
        if on_status_change:
            on_status_change(False, True)
        return

    # Get proxy settings
    proxy = get_system_proxy()
    if proxy:
        logger.info(f"Relay proxy: {redact_proxy_url(proxy)}")
    proxy_auth = get_proxy_auth(proxy, None, None)

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

                success = await connect_and_run(
                    state, relay_url, proxy, proxy_auth,
                    token_holder.get(), stop_event,
                    on_status_change, on_session_info,
                )

                if stop_event.is_set():
                    break

                if success:
                    token_holder.failure_count = 0
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
