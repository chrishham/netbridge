"""
WebSocket Tunnel Manager

Manages the WebSocket connection to the relay and multiplexes
TCP streams over it.
"""

import asyncio
import base64
import inspect
import logging
import secrets
from typing import Callable, Optional

import aiohttp
from aiohttp import ClientSession, ClientWebSocketResponse, WSMsgType

# Use orjson for faster JSON serialization if available
try:
    import orjson
    def _json_dumps(obj: dict) -> str:
        return orjson.dumps(obj).decode('utf-8')
    def _json_loads(s: str) -> dict:
        return orjson.loads(s)
except ImportError:
    import json
    _json_dumps = json.dumps
    _json_loads = json.loads

logger = logging.getLogger(__name__)


def normalize_relay_url(relay: str, path: str = "/tunnel") -> str:
    """Normalize a relay hostname or URL to a full WebSocket URL.

    Accepts: bare hostname, hostname with scheme, or full URL with path.
    """
    relay = relay.strip().rstrip("/")
    # Already a full URL with path
    if relay.startswith(("ws://", "wss://")) and "/" in relay.split("//", 1)[1]:
        return relay
    # Has scheme but no path
    if relay.startswith(("ws://", "wss://")):
        return relay + path
    # Bare hostname
    return f"wss://{relay}{path}"


# Buffer sizes for performance
READ_BUFFER_SIZE = 65536  # 64KB - matches typical TCP window size
WRITE_BUFFER_HIGH_WATER = 65536  # Drain when write buffer exceeds this

# Relay error text returned when the user's bridge agent (VDI) is not connected.
# The WebSocket to the relay is healthy in this case, but the tunnel is not
# usable end to end, so we surface it as a distinct status.
NO_AGENT_ERROR_MARKER = "no bridge agent"

# Errors the relay produces on its own, before a request ever reaches the
# agent. These say nothing about whether the VDI is reachable.
RELAY_SIDE_ERROR_MARKERS = (
    "is not allowed",
    "rate limit",
    "maximum stream limit",
    "stream id collision",
    "invalid",
    "too many concurrent streams",
)

# Probe destination used to verify the VDI end of the tunnel. This is a magic
# hostname the agent answers itself, so a probe never opens a connection to a
# real internal service. Overridable via config for relays whose destination
# allow list rejects it.
DEFAULT_PROBE_TARGET = ("netbridge-exec", 80)

# How often to re-probe the agent while it is down, with backoff (seconds)
AGENT_PROBE_INTERVAL = 15
AGENT_PROBE_INTERVAL_MAX = 120
AGENT_PROBE_BACKOFF_FACTOR = 2
AGENT_PROBE_TIMEOUT = 10.0


from .stream import StreamHandler
from .auth import (
    check_token_expiration,
    get_token_remaining_seconds,
    get_session_id,
    TokenRefreshCallback,
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
    MAX_CONCURRENT_STREAMS,
    WS_CONNECT_TIMEOUT,
    MAX_AUTH_FAILURES,
    TOKEN_REFRESH_CHECK_INTERVAL,
    TOKEN_REFRESH_THRESHOLD,
)


class TunnelConnectError(ConnectionError):
    """A connect failure reported by the relay, carrying the relay's message.

    Distinct from local failures (socket closed, no relay connection) so that
    health checks only draw conclusions from answers that actually came back
    through the tunnel.
    """


def _accepted_kwargs(callback: Callable) -> Optional[set[str]]:
    """Keyword arguments *callback* accepts, or None if it takes anything."""
    try:
        params = inspect.signature(callback).parameters.values()
    except (TypeError, ValueError):
        return None  # Not introspectable, pass everything and let it decide

    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params):
        return None

    return {
        p.name for p in params
        if p.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
    }


def classify_connect_error(error: str) -> Optional[bool]:
    """Decide what a failed tunnel connect says about the bridge agent.

    Returns:
        False if the relay told us no agent is connected,
        True if the answer could only have come from the agent itself,
        None if the relay rejected the request before involving the agent.
    """
    lowered = error.lower()

    if NO_AGENT_ERROR_MARKER in lowered:
        return False

    if any(marker in lowered for marker in RELAY_SIDE_ERROR_MARKERS):
        return None

    # Anything else (connection refused, DNS failure, timeouts at the far end)
    # means the agent processed the request, so the VDI is reachable.
    return True


class TunnelManager:
    """Manages WebSocket tunnel to relay for TCP stream multiplexing."""

    def __init__(
        self,
        relay_url: str,
        auth_token: Optional[str] = None,
        token_refresh_callback: Optional[TokenRefreshCallback] = None,
        verify_ssl: Optional[bool] = None,
        ca_bundle: Optional[str] = None,
        on_status_change: Optional[Callable] = None,
        probe_target: Optional[tuple[str, int]] = None,
    ):
        """
        Initialize tunnel manager.

        Args:
            relay_url: Relay hostname or WebSocket URL (e.g., relay.example.com)
            auth_token: Optional ARM access token for authentication
            token_refresh_callback: Optional callback to refresh the token on 401 errors
            verify_ssl: Whether to verify SSL certificates. Defaults to NETBRIDGE_VERIFY_SSL
                        env var (True if not set). Only disable as a last resort when behind
                        a TLS-intercepting proxy — this weakens connection security.
            ca_bundle: Path to a custom CA certificate file. Use this instead of
                       disabling verification when behind a TLS-intercepting proxy.
            on_status_change: Optional callback(connected, auth_required,
                              permanent_failure, agent_available) called when
                              tunnel connectivity changes. agent_available is
                              True/False once we know whether the bridge agent
                              (VDI) is reachable, None while unknown.
            probe_target: Optional (host, port) used to check that the tunnel
                          works end to end. Defaults to a magic hostname the
                          agent answers itself.
        """
        self.relay_url = normalize_relay_url(relay_url)
        self.auth_token = auth_token
        self._token_refresh_callback = token_refresh_callback
        self._verify_ssl = verify_ssl
        self._ca_bundle = ca_bundle
        self._on_status_change = on_status_change
        self._status_callback_kwargs: Optional[set[str]] = None
        self._status_callback_seen: Optional[Callable] = None
        self.session_id = get_session_id()
        self.session: Optional[ClientSession] = None
        self.ws: Optional[ClientWebSocketResponse] = None
        self.streams: dict[str, StreamHandler] = {}
        self._receive_task: Optional[asyncio.Task] = None
        self._connection_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._token_refresh_task: Optional[asyncio.Task] = None
        self._connected = asyncio.Event()
        self._stopping = False
        self._auth_failure_count = 0
        self._permanent_failure = False  # Set when we should stop retrying
        self._lock = asyncio.Lock()
        self._stream_semaphore = asyncio.Semaphore(MAX_CONCURRENT_STREAMS)
        # End-to-end health: None = unknown (nothing tried yet), True/False =
        # observed from real connect attempts through the tunnel.
        self._agent_available: Optional[bool] = None
        self._probe_target: Optional[tuple[str, int]] = None
        self._probe_target_override = probe_target
        self._agent_probe_task: Optional[asyncio.Task] = None
        self._probe_now = asyncio.Event()

    def _release_semaphore_for_stream(self, handler: StreamHandler) -> None:
        """Safely release semaphore slot for a stream, preventing double-release."""
        if not handler.semaphore_released:
            handler.semaphore_released = True
            self._stream_semaphore.release()

    @property
    def agent_available(self) -> Optional[bool]:
        """Whether the bridge agent (VDI) is reachable, None if not yet known."""
        return self._agent_available

    def _notify_status(self, connected: bool, auth_required: bool = False,
                       permanent_failure: bool = False) -> None:
        callback = self._on_status_change
        if not callback:
            return

        if callback is not self._status_callback_seen:
            self._status_callback_seen = callback
            self._status_callback_kwargs = _accepted_kwargs(callback)

        kwargs = {
            "connected": connected,
            "auth_required": auth_required,
            "permanent_failure": permanent_failure,
            "agent_available": self._agent_available,
        }
        # Drop anything the callback cannot accept, so a caller written against
        # an older signature still gets its status updates
        if self._status_callback_kwargs is not None:
            kwargs = {
                k: v for k, v in kwargs.items()
                if k in self._status_callback_kwargs
            }

        try:
            callback(**kwargs)
        except Exception:
            logger.debug("Status callback failed", exc_info=True)

    def _set_agent_available(self, available: bool, reason: str = "") -> None:
        """Record observed end-to-end health and notify on change."""
        if self._agent_available == available:
            return

        self._agent_available = available
        if available:
            logger.info("Bridge agent reachable - tunnel is working end to end")
        else:
            logger.warning(
                f"Bridge agent not reachable{f' ({reason})' if reason else ''} - "
                "connections through the tunnel will fail"
            )
            # Start watching for it to come back
            self._probe_now.set()

        self._notify_status(connected=self._connected.is_set())

    async def start(self) -> None:
        """Connect to the relay and start the connection manager."""
        self._stopping = False
        self._permanent_failure = False
        self._auth_failure_count = 0

        # Create SSL context, connector, and timeout using shared utilities
        connector = create_tunnel_connector(
            verify_ssl=self._verify_ssl, ca_bundle=self._ca_bundle
        )
        timeout = create_tunnel_timeout()
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)

        # Initial connection with retry (handles cold-starting relay)
        delay = RECONNECT_DELAY
        while True:
            try:
                await self._connect()
                break  # Connected successfully
            except ConnectionError as e:
                error_str = str(e)
                if "(403)" in error_str:
                    raise  # Forbidden — no point retrying
                if "(401)" in error_str or "Token invalid" in error_str:
                    self._auth_failure_count += 1
                    if self._auth_failure_count >= MAX_AUTH_FAILURES:
                        raise  # Give up after repeated auth failures
                    # Try refreshing the token
                    if self._token_refresh_callback:
                        try:
                            new_token = self._token_refresh_callback()
                            if new_token:
                                self.auth_token = new_token
                                logger.info("Token refreshed after auth failure")
                        except RuntimeError as refresh_err:
                            logger.error(f"Token refresh failed: {refresh_err}")
                logger.warning(f"Initial connection failed: {e}")
                logger.info(f"Retrying in {delay}s...")
                await asyncio.sleep(delay)
                delay = min(delay * RECONNECT_BACKOFF_FACTOR, RECONNECT_DELAY_MAX)

        # Start connection manager for automatic reconnection
        self._connection_task = asyncio.create_task(self._connection_loop())

        # Start cleanup task for stalled/idle streams
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        # Probes the VDI immediately, then watches for it coming back if it
        # goes away. Runs as a task because probe results are only delivered
        # once the receive loop above is running.
        self._agent_probe_task = asyncio.create_task(self._agent_probe_loop())

        # Start proactive token refresh task (if using az cli)
        if self._token_refresh_callback:
            self._token_refresh_task = asyncio.create_task(self._token_refresh_loop())

    async def _connect(self) -> None:
        """Establish WebSocket connection to relay."""
        # Pre-check token expiration before attempting connection
        if self.auth_token:
            is_valid, token_msg = check_token_expiration(self.auth_token)
            if not is_valid:
                raise ConnectionError(f"Token invalid: {token_msg}", 401)

        # Build headers with auth token and session ID
        headers = build_auth_headers(self.session_id, self.auth_token)

        try:
            self.ws = await self.session.ws_connect(
                self.relay_url,
                headers=headers,
                heartbeat=HEARTBEAT_INTERVAL,
            )
            self._connected.set()
            self._auth_failure_count = 0  # Reset on successful connection
            logger.info(f"Connected to relay (session: {self.session_id})")
        except aiohttp.WSServerHandshakeError as e:
            self._connected.clear()
            if e.status == 401:
                raise ConnectionError(f"Authentication failed (401): {e.message}", 401) from e
            elif e.status == 403:
                raise ConnectionError(f"Access forbidden (403): {e.message}", 403) from e
            else:
                raise ConnectionError(f"WebSocket handshake failed ({e.status}): {e.message}") from e
        except asyncio.TimeoutError:
            self._connected.clear()
            raise ConnectionError(f"Connection timed out after {WS_CONNECT_TIMEOUT}s") from None
        except aiohttp.ClientError as e:
            self._connected.clear()
            error_msg = str(e)
            if "Cannot connect to host" in error_msg:
                raise ConnectionError(f"Cannot reach relay server: {self.relay_url}") from e
            raise ConnectionError(f"Connection failed: {e}") from e
        except Exception as e:
            self._connected.clear()
            raise ConnectionError(f"Failed to connect to relay: {e}") from e

    async def _connection_loop(self) -> None:
        """Manage connection lifecycle with automatic reconnection."""
        while not self._stopping and not self._permanent_failure:
            try:
                # Run receive loop until disconnected
                await self._receive_loop()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Connection error: {type(e).__name__}: {e}")

            if self._stopping or self._permanent_failure:
                break

            # Connection lost - clean up and reconnect
            self._connected.clear()
            self._notify_status(connected=False)
            if self.ws and not self.ws.closed:
                await self.ws.close()
            self.ws = None

            logger.info(f"Reconnecting in {RECONNECT_DELAY}s...")
            await asyncio.sleep(RECONNECT_DELAY)

            try:
                await self._connect()
                self._notify_status(connected=True)
                # The VDI may have changed state while we were away. The probe
                # loop does the work: this loop has to get back to receiving.
                self._probe_now.set()
            except ConnectionError as e:
                error_str = str(e)
                logger.error(f"Reconnection failed: {e}")

                # Handle auth errors (401)
                if "(401)" in error_str or "Token invalid" in error_str:
                    self._auth_failure_count += 1
                    self._notify_status(connected=False, auth_required=True)
                    if self._auth_failure_count >= MAX_AUTH_FAILURES:
                        logger.error(f"{MAX_AUTH_FAILURES} consecutive auth failures. Giving up.")
                        logger.error("Run 'az login' to re-authenticate, then restart.")
                        self._permanent_failure = True
                        break

                    # Try to refresh token
                    if self._token_refresh_callback:
                        try:
                            logger.info("Refreshing auth token...")
                            new_token = self._token_refresh_callback()
                            if new_token:
                                self.auth_token = new_token
                                logger.info("Token refreshed successfully")
                        except RuntimeError as refresh_err:
                            logger.error(f"Token refresh failed: {refresh_err}")
                    else:
                        logger.error("Cannot refresh token. Restart with fresh credentials.")
                        self._permanent_failure = True
                        break

                # Handle forbidden errors (403) - no point retrying
                elif "(403)" in error_str:
                    logger.error("Access forbidden. Your account may not have permission.")
                    self._permanent_failure = True
                    self._notify_status(connected=False, permanent_failure=True)
                    break

    def _probe_candidates(self) -> list[tuple[str, int]]:
        """Destinations to try when probing the agent, best first."""
        candidates: list[tuple[str, int]] = []
        if self._probe_target_override:
            candidates.append(self._probe_target_override)
        candidates.append(DEFAULT_PROBE_TARGET)
        # A destination we have already exchanged results for is guaranteed to
        # pass the relay's checks, so it is the most reliable fallback.
        if self._probe_target and self._probe_target not in candidates:
            candidates.append(self._probe_target)
        return candidates

    async def _attempt_probe(self, host: str, port: int) -> Optional[bool]:
        """Probe one destination. Returns the same evidence as the classifier."""
        stream_id = None
        try:
            stream_id = await self.connect(host, port, timeout=AGENT_PROBE_TIMEOUT)
            return True
        except asyncio.TimeoutError:
            logger.debug(f"Agent probe to {host}:{port} timed out")
            return None
        except TunnelConnectError as e:
            return classify_connect_error(str(e))
        except ConnectionError as e:
            # Local failure (no relay connection, send failed): tells us
            # nothing about the far end
            logger.debug(f"Agent probe could not be sent: {e}")
            return None
        finally:
            if stream_id:
                # We only wanted the connect result, not the data path
                await self.close_stream(stream_id)

    async def probe_agent(self) -> Optional[bool]:
        """Check whether the VDI end of the tunnel is reachable.

        Tries probe destinations until one gives a conclusive answer, so a
        relay that rejects the default probe target does not leave us guessing.
        """
        if not self._connected.is_set() or self._stopping:
            return None

        for host, port in self._probe_candidates():
            evidence = await self._attempt_probe(host, port)
            if evidence is not None:
                self._set_agent_available(evidence, reason=f"probe {host}:{port}")
                return evidence

        logger.debug("Agent probe inconclusive, leaving status unchanged")
        return None

    async def _wait_before_next_probe(self, timeout: Optional[float]) -> None:
        """Sleep until the next probe is due, waking early if one is requested."""
        self._probe_now.clear()
        try:
            await asyncio.wait_for(self._probe_now.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    async def _agent_probe_loop(self) -> None:
        """Keep the reported status in step with real end-to-end reachability.

        Probes once as soon as the tunnel is up, then only works when there is
        something to find out: while the agent is down (to notice it return),
        or when a reconnect or a failed connection asks for a recheck.
        """
        wait: Optional[float] = 0.0
        backoff = AGENT_PROBE_INTERVAL

        while not self._stopping and not self._permanent_failure:
            try:
                if wait != 0.0:
                    await self._wait_before_next_probe(wait)

                if self._stopping:
                    break

                if not self._connected.is_set():
                    wait = AGENT_PROBE_INTERVAL
                    continue

                await self.probe_agent()

                if self._agent_available is False:
                    wait = backoff
                    backoff = min(
                        backoff * AGENT_PROBE_BACKOFF_FACTOR,
                        AGENT_PROBE_INTERVAL_MAX,
                    )
                else:
                    # Healthy or unknown: nothing to poll for, wait to be woken
                    backoff = AGENT_PROBE_INTERVAL
                    wait = None

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Agent probe loop error: {type(e).__name__}: {e}")
                wait = AGENT_PROBE_INTERVAL

    async def _cleanup_loop(self) -> None:
        """Periodically clean up stalled and idle streams."""
        while not self._stopping:
            try:
                await asyncio.sleep(STALLED_STREAM_CLEANUP_INTERVAL)

                streams_to_close = []
                async with self._lock:
                    for stream_id, handler in list(self.streams.items()):
                        # Check for stalled streams (queue full, can't accept data)
                        if handler.stalled:
                            logger.info(f"Closing stalled stream {stream_id}")
                            streams_to_close.append(stream_id)
                        # Check for idle streams
                        elif handler.is_idle(IDLE_STREAM_TIMEOUT):
                            logger.info(f"Closing idle stream {stream_id}")
                            streams_to_close.append(stream_id)

                # Close outside the lock to avoid deadlock
                for stream_id in streams_to_close:
                    await self.close_stream(stream_id)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {type(e).__name__}: {e}")

    async def _token_refresh_loop(self) -> None:
        """Proactively refresh token before it expires."""
        while not self._stopping and not self._permanent_failure:
            try:
                await asyncio.sleep(TOKEN_REFRESH_CHECK_INTERVAL)

                if not self.auth_token or not self._token_refresh_callback:
                    continue

                # Check remaining token validity
                remaining = get_token_remaining_seconds(self.auth_token)
                if remaining is None:
                    continue

                # Refresh if less than threshold remaining
                if remaining < TOKEN_REFRESH_THRESHOLD:
                    logger.info(f"Token expires in {int(remaining)}s, refreshing proactively...")
                    try:
                        new_token = self._token_refresh_callback()
                        if new_token:
                            self.auth_token = new_token
                            self._auth_failure_count = 0
                            remaining = get_token_remaining_seconds(new_token)
                            if remaining:
                                logger.info(f"Token refreshed, valid for {int(remaining // 60)} more minutes")
                            else:
                                logger.info("Token refreshed successfully")
                    except RuntimeError as e:
                        logger.error(f"Proactive token refresh failed: {e}")
                        # Don't treat this as auth failure - we still have some time

                if self._verify_ssl is False:
                    from shared_auth.connection import ALLOW_INSECURE
                    if ALLOW_INSECURE:
                        logger.warning(
                            "REMINDER: TLS certificate verification is DISABLED. "
                            "Connections are vulnerable to interception."
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Token refresh loop error: {type(e).__name__}: {e}")

    async def stop(self) -> None:
        """Disconnect from relay and clean up."""
        self._stopping = True
        self._connected.clear()

        # Close websocket first - this causes receive loop to exit naturally
        if self.ws and not self.ws.closed:
            try:
                await asyncio.wait_for(self.ws.close(), timeout=2.0)
            except (asyncio.TimeoutError, Exception):
                pass
            self.ws = None

        # Cancel background tasks with timeout
        tasks_to_cancel = [
            t for t in [self._cleanup_task, self._connection_task, self._receive_task,
                        self._token_refresh_task, self._agent_probe_task]
            if t is not None
        ]
        for task in tasks_to_cancel:
            task.cancel()

        if tasks_to_cancel:
            await asyncio.wait(tasks_to_cancel, timeout=2.0)

        self._cleanup_task = None
        self._connection_task = None
        self._receive_task = None
        self._token_refresh_task = None
        self._agent_probe_task = None

        # Close all streams - collect under lock, close outside to avoid deadlock
        async with self._lock:
            handlers_to_close = list(self.streams.values())
            self.streams.clear()

        for handler in handlers_to_close:
            await handler.close()
            self._release_semaphore_for_stream(handler)

        if self.session:
            try:
                await asyncio.wait_for(self.session.close(), timeout=2.0)
            except (asyncio.TimeoutError, Exception):
                pass
            self.session = None

        logger.info("Disconnected from relay")

    async def connect(self, host: str, port: int, timeout: float = 30.0) -> str:
        """
        Request a TCP connection through the tunnel.

        Args:
            host: Target hostname
            port: Target port
            timeout: Connection timeout in seconds

        Returns:
            Stream ID for the new connection

        Raises:
            ConnectionError: If connection fails
            asyncio.TimeoutError: If connection times out
        """
        if not self._connected.is_set():
            raise ConnectionError("Not connected to relay")

        # Acquire semaphore to limit concurrent streams
        try:
            await asyncio.wait_for(
                self._stream_semaphore.acquire(),
                timeout=5.0  # Don't wait too long for a slot
            )
        except asyncio.TimeoutError:
            raise ConnectionError(
                f"Too many concurrent streams (max {MAX_CONCURRENT_STREAMS})"
            )

        stream_id = secrets.token_urlsafe(16)
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        handler = StreamHandler(stream_id=stream_id, connect_future=future)

        # IMPORTANT: Register stream BEFORE sending request to avoid race condition
        # where relay responds before we've registered the handler
        async with self._lock:
            self.streams[stream_id] = handler

        # Send connect request
        request = {
            "type": "tcp_connect",
            "stream_id": stream_id,
            "host": host,
            "port": port,
        }

        try:
            await self.ws.send_str(_json_dumps(request))
        except Exception as e:
            # Failed to send - clean up
            async with self._lock:
                self.streams.pop(stream_id, None)
            self._release_semaphore_for_stream(handler)
            raise ConnectionError(f"Failed to send connect request: {e}")

        # Wait for response
        try:
            result = await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            async with self._lock:
                self.streams.pop(stream_id, None)
            self._release_semaphore_for_stream(handler)
            raise

        if not result.get("success"):
            async with self._lock:
                self.streams.pop(stream_id, None)
            self._release_semaphore_for_stream(handler)
            error = result.get("error", "Unknown error")
            evidence = classify_connect_error(error)
            if evidence is not None:
                # This destination got past every relay-side check, so it is a
                # usable target for future probes.
                self._probe_target = (host, port)
                self._set_agent_available(evidence, reason=error)
            raise TunnelConnectError(error)

        # A completed connect means the agent handled it end to end
        self._set_agent_available(True)

        return stream_id

    async def close_stream(self, stream_id: str) -> None:
        """Close a stream and notify the remote end."""
        async with self._lock:
            handler = self.streams.pop(stream_id, None)

        if handler:
            await handler.close()
            # Safely release semaphore slot (prevents double-release)
            self._release_semaphore_for_stream(handler)

        # Notify relay
        if self.ws and not self.ws.closed:
            try:
                await self.ws.send_str(_json_dumps({
                    "type": "tcp_close",
                    "stream_id": stream_id,
                    "reason": "client_closed",
                }))
            except Exception:
                pass

    async def send_data(self, stream_id: str, data: bytes) -> None:
        """Send data to the remote end through a stream."""
        if not self.ws or self.ws.closed:
            raise ConnectionError("WebSocket is closed")

        message = {
            "type": "tcp_data",
            "stream_id": stream_id,
            "data": base64.b64encode(data).decode("ascii"),
        }
        await self.ws.send_str(_json_dumps(message))

    async def forward(
        self,
        stream_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Bidirectional forwarding between local socket and tunnel stream.

        Args:
            stream_id: Stream ID for the tunnel
            reader: Local socket reader (from SOCKS client)
            writer: Local socket writer (to SOCKS client)
        """
        handler = self.streams.get(stream_id)
        if not handler:
            return

        async def local_to_tunnel():
            """Forward data from local client to tunnel."""
            try:
                while True:
                    # Use larger buffer for better throughput
                    data = await reader.read(READ_BUFFER_SIZE)
                    if not data:
                        break
                    await self.send_data(stream_id, data)
            except (ConnectionError, asyncio.CancelledError):
                pass
            except Exception as e:
                logger.error(f"local->tunnel error: {type(e).__name__}: {e}")
            finally:
                # Signal close to remote
                await self.close_stream(stream_id)

        async def tunnel_to_local():
            """Forward data from tunnel to local client."""
            try:
                transport = writer.transport
                while True:
                    data = await handler.read()
                    if data is None:
                        break
                    writer.write(data)
                    # Only drain when buffer is getting large (reduces syscalls)
                    if transport.get_write_buffer_size() > WRITE_BUFFER_HIGH_WATER:
                        await writer.drain()
                # Final drain to flush remaining data
                await writer.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            except Exception as e:
                logger.error(f"tunnel->local error: {type(e).__name__}: {e}")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        # Run both directions concurrently
        await asyncio.gather(
            local_to_tunnel(),
            tunnel_to_local(),
            return_exceptions=True,
        )

    async def _receive_loop(self) -> None:
        """Process incoming WebSocket messages."""
        if self.ws is None:
            return
        try:
            async for msg in self.ws:
                if msg.type == WSMsgType.TEXT:
                    await self._handle_message(_json_loads(msg.data))
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {self.ws.exception()}")
                    break
                elif msg.type == WSMsgType.CLOSED:
                    logger.warning("Connection lost")
                    break
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Receive loop error: {type(e).__name__}: {e}")
        finally:
            # Close all streams on disconnect - they can't survive reconnection
            # Collect handlers under lock, then close outside to avoid holding lock
            # during potentially slow close operations (prevents deadlock)
            async with self._lock:
                handlers_to_close = list(self.streams.values())
                self.streams.clear()

            # Close handlers and release semaphores outside the lock
            for handler in handlers_to_close:
                await handler.close()
                self._release_semaphore_for_stream(handler)

    async def _handle_message(self, data: dict) -> None:
        """Handle incoming WebSocket message."""
        msg_type = data.get("type")
        stream_id = data.get("stream_id")

        if not stream_id:
            return

        handler = self.streams.get(stream_id)
        if not handler:
            return

        if msg_type == "tcp_connect_result":
            # Connection response
            if not handler.connect_future.done():
                handler.connect_future.set_result(data)

        elif msg_type == "tcp_data":
            # Data from remote
            raw_data = base64.b64decode(data.get("data", ""))
            if not await handler.receive_data(raw_data):
                # Stream is stalled or closed, will be cleaned up by cleanup loop
                pass

        elif msg_type == "tcp_close":
            # Stream closed by remote
            await handler.close()
            async with self._lock:
                removed = self.streams.pop(stream_id, None)
            if removed:
                self._release_semaphore_for_stream(handler)
