"""
WebSocket Tunnel Manager

Manages the WebSocket connection to the relay and multiplexes
TCP streams over it.
"""

import asyncio
import base64
import logging
import secrets
from typing import Optional

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


class TunnelManager:
    """Manages WebSocket tunnel to relay for TCP stream multiplexing."""

    def __init__(
        self,
        relay_url: str,
        auth_token: Optional[str] = None,
        token_refresh_callback: Optional[TokenRefreshCallback] = None,
        verify_ssl: Optional[bool] = None,
        ca_bundle: Optional[str] = None,
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
        """
        self.relay_url = normalize_relay_url(relay_url)
        self.auth_token = auth_token
        self._token_refresh_callback = token_refresh_callback
        self._verify_ssl = verify_ssl
        self._ca_bundle = ca_bundle
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

    def _release_semaphore_for_stream(self, handler: StreamHandler) -> None:
        """Safely release semaphore slot for a stream, preventing double-release."""
        if not handler.semaphore_released:
            handler.semaphore_released = True
            self._stream_semaphore.release()

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
            if self.ws and not self.ws.closed:
                await self.ws.close()
            self.ws = None

            logger.info(f"Reconnecting in {RECONNECT_DELAY}s...")
            await asyncio.sleep(RECONNECT_DELAY)

            try:
                await self._connect()
            except ConnectionError as e:
                error_str = str(e)
                logger.error(f"Reconnection failed: {e}")

                # Handle auth errors (401)
                if "(401)" in error_str or "Token invalid" in error_str:
                    self._auth_failure_count += 1
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
                    break

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
            t for t in [self._cleanup_task, self._connection_task, self._receive_task, self._token_refresh_task]
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
            raise ConnectionError(error)

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
