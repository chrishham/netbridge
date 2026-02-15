"""
Network Bridge Relay Server

Accepts:
- WebSocket connections from bridge agents (/ws)
- WebSocket connections from SOCKS5 proxy clients (/tunnel)

Bridges TCP connections from client -> bridge agent -> corporate network.

All traffic is routed through the bridge agent, which uses Windows system
proxy settings (PAC file) to determine whether to connect directly or
through the corporate proxy.

Authentication:
- Uses Azure AD ARM tokens (from `az login`)
- Routes connections by user identity (alice@example.com -> alice's agent)
"""

import asyncio
import base64
import fnmatch
import ipaddress
import json
import logging
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Any, TypedDict

from aiohttp import web, WSMsgType
from aiolimiter import AsyncLimiter

from . import __version__
from .auth import validate_token, extract_bearer_token, TokenValidationError

def _is_loopback(host: str) -> bool:
    """Check if a bind address is loopback-only."""
    return host in ("127.0.0.1", "localhost", "::1")


def _get_int_env(name: str, default: int) -> int:
    """Get an integer from environment variable, with fallback to default."""
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


# Maximum hostname length per RFC 1035
MAX_HOSTNAME_LENGTH = 255

# Regex for basic hostname validation (allows IP addresses and hostnames)
# Matches: hostnames, IPv4, IPv6 (with optional brackets)
_HOSTNAME_PATTERN = re.compile(
    r"^("
    r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"  # subdomain labels
    r"[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"  # final label
    r"|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"  # IPv4
    r"|"
    r"\[?[a-fA-F0-9:]+\]?"  # IPv6
    r")$"
)


def validate_tcp_connect_params(host: Any, port: Any) -> tuple[bool, str]:
    """
    Validate host and port parameters for tcp_connect.

    Args:
        host: The host parameter from the request
        port: The port parameter from the request

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Validate host type
    if not isinstance(host, str):
        return False, "Host must be a string"

    # Validate host length
    if not host or len(host) > MAX_HOSTNAME_LENGTH:
        return False, f"Host length must be 1-{MAX_HOSTNAME_LENGTH} characters"

    # Validate host format (basic check)
    if not _HOSTNAME_PATTERN.match(host):
        return False, "Invalid host format"

    # Validate port type
    if not isinstance(port, int):
        return False, "Port must be an integer"

    # Validate port range
    if not (1 <= port <= 65535):
        return False, "Port must be in range 1-65535"

    return True, ""


# Heartbeat and cleanup constants - configurable via environment variables
HEARTBEAT_INTERVAL = _get_int_env("RELAY_HEARTBEAT_INTERVAL", 30)  # seconds - ping interval
STREAM_TIMEOUT = _get_int_env("RELAY_STREAM_TIMEOUT", 120)  # seconds - idle stream timeout
STREAM_CLEANUP_INTERVAL = _get_int_env("RELAY_CLEANUP_INTERVAL", 30)  # seconds - cleanup frequency

# Rate limiting constants - configurable via environment variables
RATE_LIMIT_CONNECTIONS_PER_MIN = _get_int_env("RELAY_RATE_CONNECTIONS_PER_MIN", 10)
RATE_LIMIT_MESSAGES_PER_SEC = _get_int_env("RELAY_RATE_MESSAGES_PER_SEC", 100)
RATE_LIMIT_STREAMS_PER_MIN = _get_int_env("RELAY_RATE_STREAMS_PER_MIN", 50)

# Maximum active streams across all users
MAX_ACTIVE_STREAMS = _get_int_env("RELAY_MAX_ACTIVE_STREAMS", 500)

# Maximum WebSocket message size (1MB default)
MAX_MESSAGE_SIZE = _get_int_env("RELAY_MAX_MESSAGE_SIZE", 1 * 1024 * 1024)

# Per-IP connection rate limiting (pre-auth, before user identity is known)
RATE_LIMIT_IP_PER_MIN = _get_int_env("RELAY_RATE_IP_CONNECTIONS_PER_MIN", 30)

# Global bandwidth limiter (0 = disabled)
GLOBAL_BANDWIDTH_LIMIT_MBPS = _get_int_env("RELAY_GLOBAL_BANDWIDTH_LIMIT_MBPS", 0)


def _parse_blocked_ports(env_value: str) -> set[int]:
    """Parse comma-separated port list from environment variable."""
    if not env_value:
        return set()
    ports = set()
    for part in env_value.split(","):
        part = part.strip()
        if part.isdigit():
            port = int(part)
            if 1 <= port <= 65535:
                ports.add(port)
    return ports


# Blocked destination ports - comma-separated list (e.g., "3389,22,5900,5901")
# Common dangerous ports: 3389=RDP, 22=SSH, 5900-5901=VNC
BLOCKED_PORTS: set[int] = _parse_blocked_ports(
    os.environ.get("RELAY_BLOCKED_PORTS", "")
)

def _parse_destination_list(env_var: str) -> tuple[list[ipaddress.IPv4Network | ipaddress.IPv6Network], list[str]]:
    """Parse a destination allow/deny list from an environment variable.

    Returns (cidr_list, hostname_patterns) where hostname_patterns are
    lowercase glob patterns for fnmatch.
    """
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return [], []

    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    patterns: list[str] = []

    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            cidrs.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # Not a valid CIDR — treat as hostname glob pattern
            patterns.append(entry.lower())

    return cidrs, patterns


_DENIED_CIDRS, _DENIED_PATTERNS = _parse_destination_list("RELAY_DENIED_DESTINATIONS")
_ALLOWED_CIDRS, _ALLOWED_PATTERNS = _parse_destination_list("RELAY_ALLOWED_DESTINATIONS")

# Whether an allowlist is configured (when True, only matching destinations pass)
_HAS_ALLOWLIST = bool(_ALLOWED_CIDRS or _ALLOWED_PATTERNS)


async def _check_destination_allowed(host: str) -> tuple[bool, str]:
    """Check whether a destination host is allowed by deny/allow lists.

    Returns (allowed, reason). When allowed is False, reason explains why.
    Order: deny list checked first, then allow list, then default allow.

    For hostname destinations, DNS resolution is performed so that CIDR
    rules are checked against all resolved IP addresses (prevents DNS
    rebinding / SSRF bypass).
    """
    # If no lists configured, allow everything (current default behaviour)
    if not _DENIED_CIDRS and not _DENIED_PATTERNS and not _HAS_ALLOWLIST:
        return True, ""

    # Strip IPv6 brackets (e.g. [::1] -> ::1)
    bare_host = host.strip("[]") if host.startswith("[") else host

    # Try to parse as IP address
    host_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        host_ip = ipaddress.ip_address(bare_host)
    except ValueError:
        pass

    # Collect all IPs to check against CIDR rules
    resolved_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    if host_ip is not None:
        resolved_ips.append(host_ip)
    else:
        # Resolve hostname to IP addresses for CIDR checking
        if _DENIED_CIDRS or (_HAS_ALLOWLIST and _ALLOWED_CIDRS):
            try:
                loop = asyncio.get_running_loop()
                infos = await loop.getaddrinfo(bare_host, None)
                for family, _type, _proto, _canonname, sockaddr in infos:
                    try:
                        resolved_ips.append(ipaddress.ip_address(sockaddr[0]))
                    except ValueError:
                        pass
            except (OSError, UnicodeError):
                pass  # DNS failure — fall through to hostname pattern checks

    # --- Deny list (checked first — deny wins) ---
    # Check resolved IPs against denied CIDRs
    for ip in resolved_ips:
        for net in _DENIED_CIDRS:
            if ip in net:
                return False, f"Destination {host} is denied (resolves to {ip}, matches {net})"

    # Check hostname against denied patterns
    if host_ip is None:
        host_lower = bare_host.lower()
        for pattern in _DENIED_PATTERNS:
            if fnmatch.fnmatch(host_lower, pattern):
                return False, f"Destination {host} is denied (matches {pattern})"

    # --- Allow list (only enforced when configured) ---
    if _HAS_ALLOWLIST:
        # Check resolved IPs against allowed CIDRs
        for ip in resolved_ips:
            for net in _ALLOWED_CIDRS:
                if ip in net:
                    return True, ""

        # Check hostname against allowed patterns
        if host_ip is None:
            host_lower = bare_host.lower()
            for pattern in _ALLOWED_PATTERNS:
                if fnmatch.fnmatch(host_lower, pattern):
                    return True, ""

        # Not in allowlist
        return False, f"Destination {host} is not in the allowed destinations list"

    # No allowlist configured — default allow
    return True, ""


# Per-user rate limiters (created on demand, cleaned up when stale)
_user_connection_limiters: dict[str, _TimedLimiter] = {}
_user_message_limiters: dict[str, _TimedLimiter] = {}
_user_stream_limiters: dict[str, _TimedLimiter] = {}


def _get_connection_limiter(user_email: str) -> AsyncLimiter:
    """Get or create connection rate limiter for a user."""
    entry = _user_connection_limiters.get(user_email)
    if entry is None:
        entry = _TimedLimiter(
            limiter=AsyncLimiter(RATE_LIMIT_CONNECTIONS_PER_MIN, 60)
        )
        _user_connection_limiters[user_email] = entry
    entry.last_used = time.monotonic()
    return entry.limiter


def _get_message_limiter(user_email: str) -> AsyncLimiter:
    """Get or create message rate limiter for a user."""
    entry = _user_message_limiters.get(user_email)
    if entry is None:
        entry = _TimedLimiter(
            limiter=AsyncLimiter(RATE_LIMIT_MESSAGES_PER_SEC, 1)
        )
        _user_message_limiters[user_email] = entry
    entry.last_used = time.monotonic()
    return entry.limiter


def _get_stream_limiter(user_email: str) -> AsyncLimiter:
    """Get or create stream creation rate limiter for a user."""
    entry = _user_stream_limiters.get(user_email)
    if entry is None:
        entry = _TimedLimiter(
            limiter=AsyncLimiter(RATE_LIMIT_STREAMS_PER_MIN, 60)
        )
        _user_stream_limiters[user_email] = entry
    entry.last_used = time.monotonic()
    return entry.limiter


# Per-IP rate limiting (applied before authentication)
@dataclass
class _TimedLimiter:
    """Rate limiter with last-used timestamp for cleanup."""
    limiter: AsyncLimiter
    last_used: float = field(default_factory=time.monotonic)


_ip_limiters: dict[str, _TimedLimiter] = {}


def _get_ip_limiter(ip: str) -> _TimedLimiter:
    """Get or create per-IP connection rate limiter."""
    if ip not in _ip_limiters:
        _ip_limiters[ip] = _TimedLimiter(
            limiter=AsyncLimiter(RATE_LIMIT_IP_PER_MIN, 60)
        )
    entry = _ip_limiters[ip]
    entry.last_used = time.monotonic()
    return entry


# Global bandwidth limiter (optional, disabled by default)
_global_bandwidth_limiter: AsyncLimiter | None = None
_bytes_per_sec = 0
if GLOBAL_BANDWIDTH_LIMIT_MBPS > 0:
    _bytes_per_sec = GLOBAL_BANDWIDTH_LIMIT_MBPS * 1024 * 1024 // 8
    _global_bandwidth_limiter = AsyncLimiter(_bytes_per_sec, 1)


class _JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        })


def _configure_logging() -> None:
    """Set up root logging based on RELAY_LOG_FORMAT env var.

    ``json`` (default) — structured JSON lines suitable for log aggregators.
    ``text`` — human-readable ``[LEVEL] message`` format.
    """
    log_format = os.environ.get("RELAY_LOG_FORMAT", "text").lower()

    handler = logging.StreamHandler()
    if log_format == "text":
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    else:
        handler.setFormatter(_JSONFormatter())

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)


_configure_logging()
logger = logging.getLogger(__name__)

# Silence noisy third-party loggers
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# Whether to require authentication (disabled with --no-auth or NO_AUTH env var)
REQUIRE_AUTH = True

# Lock to protect shared dictionary access (prevents race conditions)
_state_lock = asyncio.Lock()

# Connected bridge agents keyed by user identity (email)
# user_email -> WebSocketResponse
bridge_agents: dict[str, web.WebSocketResponse] = {}

class StreamInfo(TypedDict):
    user_email: str
    tunnel_key: str
    tunnel_ws: web.WebSocketResponse
    created_at: float
    last_activity: float


# TCP tunnel state
# stream_id -> StreamInfo
tcp_streams: dict[str, StreamInfo] = {}

# Connected tunnel clients (SOCKS5 proxies) keyed by user identity
# user_email -> WebSocketResponse
tunnel_clients: dict[str, web.WebSocketResponse] = {}


async def safe_ws_send(ws: web.WebSocketResponse, message: str, silent: bool = False) -> bool:
    """
    Send a message to a WebSocket with error handling.

    Args:
        ws: WebSocket to send to
        message: JSON string message to send
        silent: If True, suppress error logging (used during cleanup)

    Returns:
        True if successful, False if send failed
    """
    if ws.closed:
        return False
    try:
        await ws.send_str(message)
        return True
    except Exception as e:
        if not silent:
            logger.warning(f"WebSocket send failed: {type(e).__name__}: {e}")
        return False


async def cleanup_stale_streams(app: web.Application) -> None:
    """Background task to clean up stale/idle streams."""
    while True:
        try:
            await asyncio.sleep(STREAM_CLEANUP_INTERVAL)
        except asyncio.CancelledError:
            break

        now = time.monotonic()
        stale_tcp = []

        # Find stale streams under lock
        async with _state_lock:
            for stream_id, data in tcp_streams.items():
                last_activity = data.get("last_activity", data.get("created_at", now))
                if now - last_activity > STREAM_TIMEOUT:
                    stale_tcp.append((stream_id, data))

        # Clean up stale streams (outside lock)
        for stream_id, data in stale_tcp:
            # Notify both ends
            tunnel_ws = data.get("tunnel_ws")
            user_email = data.get("user_email")

            async with _state_lock:
                tcp_streams.pop(stream_id, None)
                agent_ws = bridge_agents.get(user_email) if user_email else None

            close_msg = json.dumps({
                "type": "tcp_close",
                "stream_id": stream_id,
                "reason": "idle_timeout",
            })
            if tunnel_ws:
                await safe_ws_send(tunnel_ws, close_msg, silent=True)
            if agent_ws:
                await safe_ws_send(agent_ws, close_msg, silent=True)

        # Clean up stale per-IP rate limiters (idle > 5 minutes)
        stale_ips = [
            ip for ip, entry in _ip_limiters.items()
            if now - entry.last_used > 300
        ]
        for ip in stale_ips:
            del _ip_limiters[ip]

        # Clean up stale per-user rate limiters (idle > 5 minutes)
        for limiter_dict in (
            _user_connection_limiters,
            _user_message_limiters,
            _user_stream_limiters,
        ):
            stale_users = [
                user for user, entry in limiter_dict.items()
                if now - entry.last_used > 300
            ]
            for user in stale_users:
                del limiter_dict[user]


async def start_cleanup_task(app: web.Application) -> None:
    """Start the background cleanup task when app starts."""
    app["cleanup_task"] = asyncio.create_task(cleanup_stale_streams(app))


async def stop_cleanup_task(app: web.Application) -> None:
    """Stop the background cleanup task when app shuts down."""
    task = app.get("cleanup_task")
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def authenticate_request(request: web.Request) -> tuple[bool, str]:
    """
    Authenticate a request using Azure AD ARM token.

    Returns:
        Tuple of (success, user_email_or_error)
    """
    if not REQUIRE_AUTH:
        # No auth required - use a default identity
        return True, "anonymous@local"

    auth_header = request.headers.get("Authorization", "")
    token = extract_bearer_token(auth_header)

    if not token:
        return False, "Missing Authorization header"

    try:
        user_email = await validate_token(token)
        return True, user_email
    except TokenValidationError as e:
        return False, str(e)


async def handle_websocket(request: web.Request) -> web.WebSocketResponse:
    """Handle WebSocket connection from bridge agent."""
    # Per-IP rate limit (before authentication to block floods early)
    client_ip = request.remote or "unknown"
    ip_entry = _get_ip_limiter(client_ip)
    if not ip_entry.limiter.has_capacity():
        logger.warning(f"Per-IP rate limit exceeded for {client_ip}")
        return web.Response(status=429, text="Too many requests from this IP")
    await ip_entry.limiter.acquire()

    # Authenticate first
    success, result = await authenticate_request(request)
    if not success:
        logger.warning(f"Agent auth rejected for {client_ip}: {result}")
        return web.Response(status=401, text=result)

    user_email = result

    # Rate limit connections (non-blocking check)
    limiter = _get_connection_limiter(user_email)
    if not limiter.has_capacity():
        logger.warning(f"Connection rate limit exceeded for agent {user_email}")
        return web.Response(status=429, text="Too many connection attempts")
    await limiter.acquire()

    ws = web.WebSocketResponse(heartbeat=HEARTBEAT_INTERVAL, max_msg_size=MAX_MESSAGE_SIZE)
    if not ws.can_prepare(request):
        return web.Response(status=400, text="WebSocket upgrade required")
    await ws.prepare(request)

    # Check if user already has an agent connected (under lock)
    async with _state_lock:
        if user_email in bridge_agents:
            old_ws = bridge_agents[user_email]
            if not old_ws.closed:
                logger.warning(f"Replacing existing agent for {user_email}")
                await old_ws.close()

        bridge_agents[user_email] = ws

    # Send registration confirmation so agent knows it's fully registered
    await safe_ws_send(ws, json.dumps({"type": "registered", "user": user_email}))

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                # Check message size before parsing
                if len(msg.data) > MAX_MESSAGE_SIZE:
                    logger.warning(
                        f"Oversized message ({len(msg.data)} bytes) from agent "
                        f"{user_email}, dropping"
                    )
                    continue

                try:
                    response = json.loads(msg.data)
                    msg_type = response.get("type")

                    # Respond to heartbeat with ack (immune to proxy interference)
                    if msg_type == "heartbeat":
                        await safe_ws_send(ws, json.dumps({"type": "heartbeat_ack"}))
                        continue

                    if msg_type in ("tcp_connect_result", "tcp_data", "tcp_close"):
                        # TCP tunnel message - forward to tunnel client
                        stream_id = response.get("stream_id")

                        # Get stream data under lock and update activity
                        async with _state_lock:
                            stream_data = tcp_streams.get(stream_id)
                            # Verify stream ownership - agent can only
                            # forward data for its own streams
                            if stream_data and stream_data.get("user_email") != user_email:
                                logger.warning(
                                    f"Stream {stream_id} ownership denied "
                                    f"for agent {user_email}"
                                )
                                stream_data = None
                            tunnel_ws = stream_data.get("tunnel_ws") if stream_data else None
                            if stream_data and msg_type == "tcp_data":
                                stream_data["last_activity"] = time.monotonic()

                        if tunnel_ws:
                            # Apply global bandwidth limit if enabled
                            if _global_bandwidth_limiter and msg_type == "tcp_data":
                                await _global_bandwidth_limiter.acquire(
                                    min(len(msg.data), _bytes_per_sec)
                                )
                            await safe_ws_send(tunnel_ws, msg.data)

                            # Clean up closed streams
                            if msg_type == "tcp_close":
                                async with _state_lock:
                                    tcp_streams.pop(stream_id, None)

                    else:
                        # Log unknown message types for debugging
                        if msg_type and msg_type != "heartbeat":
                            logger.warning(
                                f"Unknown message type '{msg_type}' from agent {user_email}"
                            )

                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON from agent {user_email}")
            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error from {user_email}: {ws.exception()}")
    finally:
        # Collect streams to remove and their tunnel WebSockets for notification
        streams_to_notify: list[tuple[str, web.WebSocketResponse]] = []

        async with _state_lock:
            # Find streams associated with this agent
            streams_to_remove = [
                sid for sid, data in tcp_streams.items()
                if data.get("user_email") == user_email
            ]

            # Collect tunnel WebSockets to notify before removing streams
            for sid in streams_to_remove:
                stream_data = tcp_streams.pop(sid, None)
                if stream_data:
                    tunnel_ws = stream_data.get("tunnel_ws")
                    if tunnel_ws:
                        streams_to_notify.append((sid, tunnel_ws))

            # Only remove if this is still the current agent for this user
            if bridge_agents.get(user_email) is ws:
                del bridge_agents[user_email]

        # Notify tunnel clients about closed streams (outside lock)
        for sid, tunnel_ws in streams_to_notify:
            await safe_ws_send(tunnel_ws, json.dumps({
                "type": "tcp_close",
                "stream_id": sid,
                "reason": "agent_disconnected",
            }), silent=True)

    return ws


async def _handle_tcp_connect(
    ws: web.WebSocketResponse,
    data: dict,
    tunnel_key: str,
    user_email: str,
    stream_limiter: AsyncLimiter,
    raw_msg: str,
) -> None:
    """Handle a tcp_connect message from a tunnel client."""
    stream_id = data.get("stream_id")
    host = data.get("host", "")
    port = data.get("port", 0)

    # Validate host and port parameters
    is_valid, error_msg = validate_tcp_connect_params(host, port)
    if not is_valid:
        logger.warning(f"Invalid tcp_connect from {tunnel_key}: {error_msg}")
        await safe_ws_send(
            ws,
            json.dumps({
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": error_msg,
            }),
        )
        return

    # Rate limit stream creation (non-blocking check)
    if not stream_limiter.has_capacity():
        logger.warning(f"Stream rate limit exceeded for {tunnel_key}")
        await safe_ws_send(
            ws,
            json.dumps({
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": "Rate limit exceeded for stream creation",
            }),
        )
        return
    await stream_limiter.acquire()

    # Check blocked ports
    if BLOCKED_PORTS and port in BLOCKED_PORTS:
        logger.warning(f"Blocked port {port} requested by {tunnel_key}")
        await safe_ws_send(
            ws,
            json.dumps({
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": f"Port {port} is not allowed",
            }),
        )
        return

    # Check destination allow/deny lists
    dest_allowed, dest_reason = await _check_destination_allowed(host)
    if not dest_allowed:
        logger.warning(f"Destination denied for {tunnel_key}: {dest_reason}")
        await safe_ws_send(
            ws,
            json.dumps({
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": f"Destination {host} is not allowed",
            }),
        )
        return

    # Route all traffic through bridge agent
    async with _state_lock:
        # Check max streams limit
        if len(tcp_streams) >= MAX_ACTIVE_STREAMS:
            await safe_ws_send(
                ws,
                json.dumps({
                    "type": "tcp_connect_result",
                    "stream_id": stream_id,
                    "success": False,
                    "error": "Maximum stream limit reached",
                }),
            )
            return

        agent_ws = bridge_agents.get(user_email)
        if not agent_ws:
            await safe_ws_send(ws, json.dumps({
                "type": "tcp_connect_result",
                "stream_id": stream_id,
                "success": False,
                "error": "No bridge agent available",
            }))
            return

        # Reject if stream_id already exists
        if stream_id in tcp_streams:
            logger.warning(
                f"Stream ID collision for {stream_id} from {tunnel_key}"
            )
            await safe_ws_send(
                ws,
                json.dumps({
                    "type": "tcp_connect_result",
                    "stream_id": stream_id,
                    "success": False,
                    "error": "Stream ID collision",
                }),
            )
            return

        # Track this stream
        now = time.monotonic()
        tcp_streams[stream_id] = {
            "user_email": user_email,
            "tunnel_key": tunnel_key,
            "tunnel_ws": ws,
            "created_at": now,
            "last_activity": now,
        }

    # Forward to agent (outside lock)
    await safe_ws_send(agent_ws, raw_msg)


async def _handle_tcp_data(data: dict, tunnel_key: str, raw_msg: str) -> None:
    """Handle a tcp_data message from a tunnel client."""
    stream_id = data.get("stream_id")

    # Get stream info under lock and update activity
    async with _state_lock:
        tcp_data = tcp_streams.get(stream_id)
        if tcp_data:
            # Verify ownership before processing
            if tcp_data.get("tunnel_key") != tunnel_key:
                logger.warning(
                    f"Stream {stream_id} access denied for {tunnel_key}"
                )
                tcp_data = None  # Block access
            else:
                tcp_data["last_activity"] = time.monotonic()

    if tcp_data:
        # Apply global bandwidth limit if enabled
        if _global_bandwidth_limiter:
            await _global_bandwidth_limiter.acquire(
                min(len(raw_msg), _bytes_per_sec)
            )
        # Forward data to bridge agent
        stream_user = tcp_data.get("user_email")
        async with _state_lock:
            agent_ws = bridge_agents.get(stream_user)
        if agent_ws:
            await safe_ws_send(agent_ws, raw_msg)


async def _handle_tcp_close(data: dict, tunnel_key: str, raw_msg: str) -> None:
    """Handle a tcp_close message from a tunnel client."""
    stream_id = data.get("stream_id")

    # Get stream info under lock with ownership check
    async with _state_lock:
        tcp_data = tcp_streams.get(stream_id)
        # Only allow close if we own the stream
        if tcp_data and tcp_data.get("tunnel_key") == tunnel_key:
            tcp_data = tcp_streams.pop(stream_id, None)
        else:
            if tcp_data:
                logger.warning(
                    f"Stream {stream_id} close denied for {tunnel_key}"
                )
            tcp_data = None

    if tcp_data:
        # Forward close to bridge agent
        stream_user = tcp_data.get("user_email")
        async with _state_lock:
            agent_ws = bridge_agents.get(stream_user)
        if agent_ws:
            await safe_ws_send(agent_ws, raw_msg)


async def handle_tunnel(request: web.Request) -> web.WebSocketResponse:
    """Handle WebSocket from SOCKS5 proxy for TCP tunneling."""
    # Per-IP rate limit (before authentication to block floods early)
    client_ip = request.remote or "unknown"
    ip_entry = _get_ip_limiter(client_ip)
    if not ip_entry.limiter.has_capacity():
        logger.warning(f"Per-IP rate limit exceeded for {client_ip}")
        return web.Response(status=429, text="Too many requests from this IP")
    await ip_entry.limiter.acquire()

    # Authenticate first
    success, result = await authenticate_request(request)
    if not success:
        logger.warning(f"Tunnel auth rejected for {client_ip}: {result}")
        return web.Response(status=401, text=result)

    user_email = result

    # Rate limit connections (non-blocking check)
    limiter = _get_connection_limiter(user_email)
    if not limiter.has_capacity():
        logger.warning(f"Connection rate limit exceeded for tunnel {user_email}")
        return web.Response(status=429, text="Too many connection attempts")
    await limiter.acquire()

    # Generate secure server-side session ID (ignore client-provided X-Session-ID)
    # This prevents session hijacking where attacker could guess/reuse session IDs
    session_id = secrets.token_urlsafe(16)
    tunnel_key = f"{user_email}:{session_id}"

    ws = web.WebSocketResponse(heartbeat=HEARTBEAT_INTERVAL, max_msg_size=MAX_MESSAGE_SIZE)
    if not ws.can_prepare(request):
        return web.Response(status=400, text="WebSocket upgrade required")
    await ws.prepare(request)

    # Check if this specific session already has a tunnel client connected (under lock)
    async with _state_lock:
        if tunnel_key in tunnel_clients:
            old_ws = tunnel_clients[tunnel_key]
            if not old_ws.closed:
                logger.warning(f"Replacing existing tunnel client for {tunnel_key}")
                await old_ws.close()

        tunnel_clients[tunnel_key] = ws

    # Get rate limiters for this user
    message_limiter = _get_message_limiter(user_email)
    stream_limiter = _get_stream_limiter(user_email)

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                # Check message size before parsing
                if len(msg.data) > MAX_MESSAGE_SIZE:
                    logger.warning(
                        f"Oversized message ({len(msg.data)} bytes) from tunnel "
                        f"{tunnel_key}, dropping"
                    )
                    continue

                # Rate limit messages (non-blocking check, skip if exceeded)
                if not message_limiter.has_capacity():
                    logger.warning(f"Message rate limit exceeded for {tunnel_key}")
                    continue
                await message_limiter.acquire()

                try:
                    data = json.loads(msg.data)
                    msg_type = data.get("type")

                    if msg_type == "tcp_connect":
                        await _handle_tcp_connect(ws, data, tunnel_key, user_email, stream_limiter, msg.data)
                    elif msg_type == "tcp_data":
                        await _handle_tcp_data(data, tunnel_key, msg.data)
                    elif msg_type == "tcp_close":
                        await _handle_tcp_close(data, tunnel_key, msg.data)
                    elif msg_type:
                        logger.warning(
                            f"Unknown message type '{msg_type}' from {tunnel_key}"
                        )

                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON from tunnel client {tunnel_key}")

            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error from tunnel client {tunnel_key}: {ws.exception()}")

    finally:
        # Collect data for cleanup under lock
        streams_to_notify: list[tuple[str, web.WebSocketResponse]] = []

        async with _state_lock:
            # Clean up all streams from this tunnel client (by tunnel_key)
            streams_to_remove = [
                sid for sid, data in tcp_streams.items()
                if data.get("tunnel_key") == tunnel_key
            ]
            for sid in streams_to_remove:
                stream_data = tcp_streams.pop(sid, None)
                if stream_data:
                    stream_user = stream_data.get("user_email")
                    agent_ws = bridge_agents.get(stream_user)
                    if agent_ws:
                        streams_to_notify.append((sid, agent_ws))

            # Only remove if this is still the current tunnel client for this session
            if tunnel_clients.get(tunnel_key) is ws:
                del tunnel_clients[tunnel_key]

        # Notify agents about closed streams (outside lock)
        for sid, agent_ws in streams_to_notify:
            await safe_ws_send(agent_ws, json.dumps({
                "type": "tcp_close",
                "stream_id": sid,
                "reason": "tunnel_client_disconnected",
            }), silent=True)

    return ws


async def handle_status(request: web.Request) -> web.Response:
    """Return relay status.

    Unauthenticated requests get a minimal response.
    Authenticated requests get operational counts.
    """
    # Always-safe response
    info: dict = {
        "status": "ok",
        "auth_required": REQUIRE_AUTH,
    }

    # Add operational counts only for authenticated callers
    authenticated, _ = await authenticate_request(request)
    if authenticated:
        info["agents"] = len(bridge_agents)
        info["tunnel_clients"] = len(tunnel_clients)
        info["active_streams"] = len(tcp_streams)

    return web.json_response(info)


def create_app() -> web.Application:
    """Create the aiohttp application."""
    app = web.Application()
    app.router.add_get("/ws", handle_websocket)
    app.router.add_get("/tunnel", handle_tunnel)
    app.router.add_get("/status", handle_status)
    app.router.add_get("/", handle_status)

    # Register cleanup task lifecycle hooks
    app.on_startup.append(start_cleanup_task)
    app.on_cleanup.append(stop_cleanup_task)

    return app


def main():
    """Entry point for the relay server."""
    global REQUIRE_AUTH

    import argparse

    parser = argparse.ArgumentParser(description="Network Bridge Relay Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable authentication (for local testing only)"
    )
    args = parser.parse_args()

    # Startup banner
    logger.info("=" * 50)
    logger.info(f"Network Bridge Relay Server v{__version__}")
    logger.info("=" * 50)

    # Check environment variable too
    no_auth_requested = (
        args.no_auth
        or os.environ.get("NO_AUTH", "").lower() in ("1", "true", "yes")
    )
    if no_auth_requested:
        # Require explicit opt-in via environment variable
        allow_no_auth = os.environ.get(
            "NETBRIDGE_ALLOW_NO_AUTH", ""
        ).lower() in ("1", "true", "yes")
        if not allow_no_auth:
            logger.error(
                "--no-auth requires NETBRIDGE_ALLOW_NO_AUTH=true "
                "environment variable"
            )
            sys.exit(1)

        # Refuse non-loopback binding with authentication disabled
        if not _is_loopback(args.host):
            logger.error(
                "--no-auth cannot be used with non-loopback bind address "
                f"({args.host})"
            )
            logger.error("Use --host 127.0.0.1 or remove --no-auth")
            sys.exit(1)

        REQUIRE_AUTH = False
        logger.warning("=" * 50)
        logger.warning("SECURITY WARNING: Authentication is DISABLED")
        logger.warning("Anyone can connect without credentials!")
        logger.warning("Do NOT use --no-auth or NO_AUTH in production!")
        logger.warning("=" * 50)
    else:
        REQUIRE_AUTH = True
        logger.info("Authentication: Azure AD ARM tokens")

        try:
            from shared_auth.validate import get_allowed_tenant_ids
            tenant_ids = get_allowed_tenant_ids()
            logger.info(f"Allowed tenants: {len(tenant_ids)} configured")
        except RuntimeError as e:
            logger.error(f"Configuration error: {e}")
            logger.error("Set NETBRIDGE_ALLOWED_TENANTS to a comma-separated list of Azure AD tenant IDs")
            sys.exit(1)

    logger.info("Routing: all traffic via bridge agent")

    # Log destination filtering rules
    denied_count = len(_DENIED_CIDRS) + len(_DENIED_PATTERNS)
    allowed_count = len(_ALLOWED_CIDRS) + len(_ALLOWED_PATTERNS)
    if denied_count:
        logger.info(f"Denied destinations: {denied_count} rule(s) loaded")
    if allowed_count:
        logger.info(f"Allowed destinations: {allowed_count} rule(s) loaded")
    if not denied_count and not allowed_count:
        logger.info("Destination filtering: disabled (all destinations allowed)")

    logger.info(f"Listening on {args.host}:{args.port}")
    logger.info(f"Agent endpoint: /ws")
    logger.info(f"Tunnel endpoint: /tunnel")
    logger.info("=" * 50)
    logger.info("Relay is ready to accept connections")

    app = create_app()

    # Use AppRunner to configure max header sizes for large Azure AD tokens
    # Users with many group memberships can have tokens >12KB (default limit is 8190)
    asyncio.run(run_app_with_large_headers(app, args.host, args.port))


async def run_app_with_large_headers(app: web.Application, host: str, port: int):
    """Run the app with increased header size limits for large Azure AD tokens."""
    # Increase max_line_size and max_field_size to 32KB to accommodate large tokens
    # (users with many Azure AD group memberships can have tokens >12KB)
    runner = web.AppRunner(
        app,
        access_log=None,       # Disable HTTP access logging
        max_line_size=32768,   # 32KB (default is 8190)
        max_field_size=32768,  # 32KB (default is 8190)
    )
    await runner.setup()

    site = web.TCPSite(runner, host, port)
    await site.start()

    # Run until interrupted
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        logger.info("Relay server shutting down...")
        await runner.cleanup()
        logger.info("Relay server stopped. Goodbye!")


if __name__ == "__main__":
    main()
