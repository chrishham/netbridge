"""
Legacy agent implementation.

This module contains the original console-only agent logic for backwards compatibility.
It's used when running with --legacy flag.
"""

import asyncio
import base64
from datetime import datetime
import json
import signal
import socket
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Optional
import aiohttp

from .config import redact_proxy_url
from .agent import validate_destination
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

TCP_BUFFER_SIZE = 8192
CLEANUP_INTERVAL = STALLED_STREAM_CLEANUP_INTERVAL
STATS_INTERVAL = 60
READ_TIMEOUT = 300
WRITE_TIMEOUT = 30
CONNECTION_LIVENESS_TIMEOUT = 90
APP_HEARTBEAT_INTERVAL = 30


def ts() -> str:
    """Return current timestamp string for log messages."""
    return datetime.now().strftime("%H:%M:%S")


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
            print(f"[{ts()}] [*] Token expires in {int(remaining)}s, refreshing proactively...")
            loop = asyncio.get_event_loop()
            try:
                success = await asyncio.wait_for(
                    loop.run_in_executor(None, token_holder.refresh),
                    timeout=60.0,
                )
            except asyncio.TimeoutError:
                print(f"[{ts()}] [!] Token refresh timed out (az CLI took >60s)")
                continue

            if success:
                new_remaining = get_token_remaining_seconds(token_holder.get())
                if new_remaining:
                    print(f"[{ts()}] [*] Token refreshed, valid for {int(new_remaining // 60)} more minutes")
                else:
                    print(f"[{ts()}] [*] Token refreshed successfully")
            else:
                print(f"[{ts()}] [!] Proactive token refresh failed")


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


active_streams: dict[str, StreamInfo] = {}
pending_connections: dict[str, asyncio.Task] = {}
_streams_lock: Optional[asyncio.Lock] = None
_stop_event: Optional[asyncio.Event] = None
_passthrough_proxy_auth: Optional[tuple[str, str]] = None
MAX_CONCURRENT_CONNECTIONS = 50


def _get_streams_lock() -> asyncio.Lock:
    global _streams_lock
    if _streams_lock is None:
        _streams_lock = asyncio.Lock()
    return _streams_lock


def get_system_proxy() -> str | None:
    proxies = urllib.request.getproxies()
    return proxies.get("https") or proxies.get("http")


def get_proxy_auth(proxy_url: str | None, cli_user: str | None, cli_pass: str | None) -> aiohttp.BasicAuth | None:
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
    proxy_auth: tuple[str, str] | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    proxy = None

    if sys.platform == "win32":
        try:
            from .winproxy import get_proxy_for_url_safe
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}/"
            proxy = get_proxy_for_url_safe(url)
            if proxy:
                print(f"[{ts()}] [TCP] Proxy for {host}:{port}: {redact_proxy_url(proxy)}")
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

    sock = writer.get_extra_info("socket")
    if sock:
        raw_sock = getattr(sock, "_sock", sock)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if sys.platform == "win32":
            SIO_KEEPALIVE_VALS = 0x98000004
            raw_sock.ioctl(SIO_KEEPALIVE_VALS, (1, 60_000, 15_000))

    return reader, writer


async def send_to_relay(ws, message: dict, timeout: float = WRITE_TIMEOUT, silent: bool = False) -> bool:
    if ws.closed:
        return False
    try:
        await asyncio.wait_for(ws.send_str(json.dumps(message)), timeout=timeout)
        return True
    except asyncio.TimeoutError:
        if not silent:
            print(f"[{ts()}] [!] Relay send timeout for {message.get('type', 'unknown')}")
        return False
    except Exception as e:
        if not silent:
            print(f"[{ts()}] [!] Relay send error: {type(e).__name__}: {e}")
        return False


async def _do_tcp_connect(ws, stream_id: str, host: str, port: int) -> None:
    lock = _get_streams_lock()

    try:
        reader, writer = await open_tcp_connection(
            host, port, timeout=30.0, proxy_auth=_passthrough_proxy_auth
        )

        forward_task = asyncio.create_task(
            forward_tcp_to_ws(stream_id, reader, ws)
        )

        async with lock:
            active_streams[stream_id] = StreamInfo(
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

        print(f"[{ts()}] [TCP] Connected: {stream_id} -> {host}:{port}")

    except asyncio.CancelledError:
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": "Connection cancelled",
        }, silent=True)
        raise

    except asyncio.TimeoutError:
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": f"Connection to {host}:{port} timed out",
        })
        print(f"[{ts()}] [TCP] Timeout: {stream_id} -> {host}:{port}")

    except OSError as e:
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": f"Connection failed: {e}",
        })
        print(f"[{ts()}] [TCP] Failed: {stream_id} -> {host}:{port}: {e}")

    except Exception as e:
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": f"Unexpected error: {type(e).__name__}: {e}",
        })
        print(f"[{ts()}] [TCP] Error: {stream_id} -> {host}:{port}: {e}")

    finally:
        async with lock:
            pending_connections.pop(stream_id, None)


async def handle_tcp_connect(ws, request: dict) -> None:
    stream_id = request.get("stream_id")
    host = request.get("host")
    port = request.get("port")

    lock = _get_streams_lock()

    async with lock:
        pending_count = len(pending_connections)
        active_count = len(active_streams)

    if pending_count >= MAX_CONCURRENT_CONNECTIONS:
        print(f"[{ts()}] [TCP] Rejected (too many pending): {stream_id} -> {host}:{port}")
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": "Too many pending connections",
        })
        return

    if active_count >= MAX_ACTIVE_STREAMS:
        print(f"[{ts()}] [TCP] Rejected (too many active): {stream_id} -> {host}:{port}")
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": "Too many active streams",
        })
        return

    # Validate destination against private ranges
    dest_allowed, dest_reason = await validate_destination(host, port)
    if not dest_allowed:
        print(f"[{ts()}] [TCP] Destination denied: {stream_id} -> {host}:{port}: {dest_reason}")
        await send_to_relay(ws, {
            "type": "tcp_connect_result",
            "stream_id": stream_id,
            "success": False,
            "error": f"Destination {host}:{port} is not allowed",
        })
        return

    print(f"[{ts()}] [TCP] Connect request: {stream_id} -> {host}:{port}")

    task = asyncio.create_task(_do_tcp_connect(ws, stream_id, host, port))
    async with lock:
        pending_connections[stream_id] = task


async def forward_tcp_to_ws(stream_id: str, reader: asyncio.StreamReader, ws) -> None:
    lock = _get_streams_lock()

    try:
        while True:
            try:
                data = await asyncio.wait_for(reader.read(TCP_BUFFER_SIZE), timeout=READ_TIMEOUT)
            except asyncio.TimeoutError:
                print(f"[{ts()}] [TCP] Read timeout: {stream_id} (no data for {READ_TIMEOUT}s)")
                break

            if not data:
                break

            async with lock:
                stream = active_streams.get(stream_id)
                if stream:
                    stream.touch()

            success = await send_to_relay(ws, {
                "type": "tcp_data",
                "stream_id": stream_id,
                "data": base64.b64encode(data).decode("ascii"),
            })
            if not success:
                print(f"[{ts()}] [TCP] Write failed to relay: {stream_id}")
                break

    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"[{ts()}] [TCP] Forward error {stream_id}: {type(e).__name__}: {e}")
    finally:
        await send_to_relay(ws, {
            "type": "tcp_close",
            "stream_id": stream_id,
            "reason": "server_closed",
        }, silent=True)

        await close_stream(stream_id)
        print(f"[{ts()}] [TCP] Stream closed: {stream_id}")


async def handle_tcp_data(request: dict) -> None:
    stream_id = request.get("stream_id")
    data_b64 = request.get("data", "")

    lock = _get_streams_lock()
    async with lock:
        stream = active_streams.get(stream_id)

    if not stream:
        return

    stream.touch()

    try:
        data = base64.b64decode(data_b64)
        stream.writer.write(data)
        await stream.writer.drain()
    except Exception as e:
        print(f"[{ts()}] [TCP] Write error {stream_id}: {type(e).__name__}: {e}")
        await close_stream(stream_id)


async def handle_tcp_close(request: dict) -> None:
    stream_id = request.get("stream_id")
    reason = request.get("reason", "unknown")
    print(f"[{ts()}] [TCP] Close request: {stream_id} ({reason})")
    await close_stream(stream_id)


async def close_stream(stream_id: str, timeout: float = 2.0) -> None:
    lock = _get_streams_lock()
    async with lock:
        stream = active_streams.pop(stream_id, None)

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


async def close_all_streams(timeout: float = 5.0) -> None:
    lock = _get_streams_lock()
    tasks_to_cancel = []
    stream_ids = []

    async with lock:
        if pending_connections:
            print(f"[{ts()}] [*] Cancelling {len(pending_connections)} pending connections...")
            for stream_id, task in list(pending_connections.items()):
                if not task.done():
                    task.cancel()
                    tasks_to_cancel.append(task)
            pending_connections.clear()

        if active_streams:
            stream_ids = list(active_streams.keys())
            print(f"[{ts()}] [*] Closing {len(stream_ids)} active streams...")

            for stream_id in stream_ids:
                stream = active_streams.get(stream_id)
                if stream and stream.forward_task and not stream.forward_task.done():
                    stream.forward_task.cancel()
                    tasks_to_cancel.append(stream.forward_task)

    if tasks_to_cancel:
        done, pending = await asyncio.wait(tasks_to_cancel, timeout=timeout)
        if pending:
            print(f"[{ts()}] [!] {len(pending)} tasks did not complete in time")

    for stream_id in stream_ids:
        await close_stream(stream_id, timeout=1.0)


async def cleanup_idle_streams(stop_event: asyncio.Event) -> None:
    last_stats_time = time.monotonic()
    lock = _get_streams_lock()

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=CLEANUP_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass

        now = time.monotonic()

        idle_streams = []
        async with lock:
            for stream_id, stream in list(active_streams.items()):
                if stream.is_idle(IDLE_STREAM_TIMEOUT):
                    idle_streams.append((stream_id, stream))

        for stream_id, stream in idle_streams:
            print(f"[{ts()}] [TCP] Closing idle stream: {stream_id} -> {stream.host}:{stream.port} "
                  f"(idle {int(now - stream.last_activity)}s)")
            await close_stream(stream_id)

        if now - last_stats_time >= STATS_INTERVAL:
            last_stats_time = now
            async with lock:
                active_count = len(active_streams)
                pending_count = len(pending_connections)
            if active_count or pending_count:
                print(f"[{ts()}] [Stats] Active streams: {active_count}, "
                      f"Pending connections: {pending_count}")


async def handle_message(ws, msg: str):
    try:
        request = json.loads(msg)
        msg_type = request.get("type")

        if msg_type == "tcp_connect":
            await handle_tcp_connect(ws, request)
        elif msg_type == "tcp_data":
            await handle_tcp_data(request)
        elif msg_type == "tcp_close":
            await handle_tcp_close(request)
        else:
            print(f"[{ts()}] [!] Unknown message type: {msg_type}")

    except json.JSONDecodeError:
        print(f"[{ts()}] [!] Invalid JSON message received")


async def heartbeat_sender(ws, stop_event: asyncio.Event, liveness_tracker: dict) -> None:
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=APP_HEARTBEAT_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass

        if ws.closed:
            print(f"[{ts()}] [Heartbeat] WebSocket closed, stopping heartbeat")
            break

        idle_time = time.monotonic() - liveness_tracker["last_message_time"]

        success = await send_to_relay(ws, {"type": "heartbeat"}, silent=True)
        if success:
            print(f"[{ts()}] [Heartbeat] Sent (last relay msg: {int(idle_time)}s ago)")
        else:
            print(f"[{ts()}] [!] Heartbeat send failed, connection may be dead")
            break


async def connect_and_run(
    relay_url: str,
    proxy: str | None,
    proxy_auth: aiohttp.BasicAuth | None,
    auth_token: str | None,
    stop_event: asyncio.Event,
):
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
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=10.0)
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    if data.get("type") == "registered":
                        print(f"[{ts()}] [+] Connected to relay! (session: {session_id})")
                        print(f"[{ts()}] [*] Passthrough connections: direct (no proxy)")
                    else:
                        print(f"[{ts()}] [!] Unexpected first message: {data.get('type')}")
                        return
                else:
                    print(f"[{ts()}] [!] Unexpected message type during registration: {msg.type}")
                    return
            except asyncio.TimeoutError:
                print(f"[{ts()}] [!] Timeout waiting for registration confirmation")
                return
            except json.JSONDecodeError:
                print(f"[{ts()}] [!] Invalid JSON in registration response")
                return

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
                            print(f"[{ts()}] [!] No messages from relay for {int(idle_time)}s, assuming connection dead")
                            break
                        continue

                    liveness_tracker["last_message_time"] = time.monotonic()

                    if msg.type == aiohttp.WSMsgType.TEXT:
                        try:
                            data = json.loads(msg.data)
                            if data.get("type") == "heartbeat_ack":
                                print(f"[{ts()}] [Heartbeat] Received ack from relay")
                                continue
                        except json.JSONDecodeError:
                            pass
                        await handle_message(ws, msg.data)
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        print(f"[{ts()}] [!] WebSocket error: {ws.exception()}")
                        break
                    elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSE):
                        if msg.type == aiohttp.WSMsgType.CLOSE:
                            print(f"[{ts()}] [*] Server requested close: {ws.close_code}")
                        else:
                            print(f"[{ts()}] [*] Connection closed by server")
                        break

                if stop_event.is_set():
                    print(f"[{ts()}] [*] Shutdown requested, closing connection...")

            except asyncio.CancelledError:
                pass
            finally:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass

                if not ws.closed:
                    try:
                        await asyncio.wait_for(ws.close(), timeout=2.0)
                    except (asyncio.TimeoutError, Exception):
                        pass
                await close_all_streams()


async def async_main(
    relay_url: str,
    auth_token: str | None,
    proxy_user: str | None = None,
    proxy_pass: str | None = None,
    token_refresh_callback=None,
    passthrough_proxy_user: str | None = None,
    passthrough_proxy_pass: str | None = None,
):
    """Main async entry point with proper signal handling."""
    global _stop_event, _passthrough_proxy_auth
    _stop_event = asyncio.Event()

    if passthrough_proxy_user:
        _passthrough_proxy_auth = (passthrough_proxy_user, passthrough_proxy_pass or "")
        print(f"[{ts()}] [*] Passthrough proxy auth: {passthrough_proxy_user}")
    else:
        _passthrough_proxy_auth = None

    proxy = get_system_proxy()
    if proxy:
        print(f"[{ts()}] [*] Relay proxy: {redact_proxy_url(proxy)}")
    else:
        print(f"[{ts()}] [*] Relay connection: direct (no proxy)")

    proxy_auth = get_proxy_auth(proxy, proxy_user, proxy_pass)
    if proxy_auth:
        print(f"[{ts()}] [*] Relay proxy auth: {proxy_auth.login}")

    print(f"[{ts()}] [*] Relay: {relay_url}")
    print(f"[{ts()}] [*] Heartbeat interval: {HEARTBEAT_INTERVAL}s")

    def signal_handler():
        print(f"\n[{ts()}] [*] Shutting down gracefully...")
        _stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            pass

    cleanup_task = asyncio.create_task(cleanup_idle_streams(_stop_event))

    token_holder = TokenHolder(auth_token, token_refresh_callback)

    token_refresh_task = None
    if token_refresh_callback:
        token_refresh_task = asyncio.create_task(token_refresh_loop(token_holder, _stop_event))

    current_delay = RECONNECT_DELAY

    try:
        while not _stop_event.is_set():
            current_token = token_holder.get()
            if current_token:
                is_valid, token_msg = check_token_expiration(current_token)
                if not is_valid:
                    print(f"[{ts()}] [!] {token_msg}")
                    if token_holder.refresh():
                        print(f"[{ts()}] [*] Token refreshed successfully")
                    else:
                        token_holder.failure_count += 1
                        if token_holder.failure_count >= MAX_AUTH_FAILURES:
                            print(f"[{ts()}] [!] {MAX_AUTH_FAILURES} consecutive auth failures. Giving up.")
                            print(f"[{ts()}] [!] Run 'az login' to re-authenticate, then restart the agent.")
                            break
                        if not token_refresh_callback:
                            print(f"[{ts()}] [!] Cannot refresh token (manual token provided).")
                            print(f"[{ts()}] [!] Get a new token and restart the agent with --token.")
                            break

            connection_succeeded = False
            try:
                await connect_and_run(relay_url, proxy, proxy_auth, token_holder.get(), _stop_event)
                if _stop_event.is_set():
                    break
                print(f"[{ts()}] [*] Connection ended normally")
                token_holder.failure_count = 0
                current_delay = RECONNECT_DELAY
                connection_succeeded = True
            except aiohttp.WSServerHandshakeError as e:
                if _stop_event.is_set():
                    break
                print(f"[{ts()}] [!] WebSocket handshake failed: {e.status} {e.message}")
                if e.status == 401:
                    token_holder.failure_count += 1
                    if token_holder.failure_count >= MAX_AUTH_FAILURES:
                        print(f"[{ts()}] [!] {MAX_AUTH_FAILURES} consecutive auth failures. Giving up.")
                        print(f"[{ts()}] [!] Run 'az login' to re-authenticate, then restart the agent.")
                        break
                    if token_holder.refresh():
                        print(f"[{ts()}] [*] Token refreshed successfully")
                    elif not token_refresh_callback:
                        print(f"[{ts()}] [!] Cannot refresh token. Restart with a new --token.")
                        break
                elif e.status == 403:
                    print(f"[{ts()}] [!] Access forbidden. Your account may not have permission to use this relay.")
                    break
            except asyncio.TimeoutError:
                if _stop_event.is_set():
                    break
                print(f"[{ts()}] [!] Connection timed out after {WS_CONNECT_TIMEOUT}s")
                print(f"[{ts()}] [!] The relay server may be unreachable or the network is slow.")
            except aiohttp.ClientError as e:
                if _stop_event.is_set():
                    break
                error_msg = str(e)
                if "Cannot connect to host" in error_msg:
                    print(f"[{ts()}] [!] Cannot reach relay server: {relay_url}")
                    print(f"[{ts()}] [!] Check your network connection and proxy settings.")
                elif "SSL" in error_msg or "certificate" in error_msg.lower():
                    print(f"[{ts()}] [!] SSL/TLS error: {e}")
                else:
                    print(f"[{ts()}] [!] Connection error: {type(e).__name__}: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                if _stop_event.is_set():
                    break
                print(f"[{ts()}] [!] Unexpected error: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()

            if not _stop_event.is_set():
                print(f"[{ts()}] [*] Reconnecting in {current_delay}s...")
                try:
                    await asyncio.wait_for(_stop_event.wait(), timeout=current_delay)
                except asyncio.TimeoutError:
                    pass
                if not connection_succeeded:
                    current_delay = min(current_delay * RECONNECT_BACKOFF_FACTOR, RECONNECT_DELAY_MAX)
    finally:
        tasks_to_cancel = [cleanup_task]
        if token_refresh_task:
            tasks_to_cancel.append(token_refresh_task)

        for task in tasks_to_cancel:
            task.cancel()

        for task in tasks_to_cancel:
            try:
                await task
            except asyncio.CancelledError:
                pass

        await close_all_streams(timeout=3.0)
        print(f"[{ts()}] [*] Cleanup complete")
