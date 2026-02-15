"""
Session management utilities for Network Bridge.

Contains session ID generation, token holder class, and shared constants
for bridge management across agent and proxy components.
"""

import getpass
import hashlib
import os
import socket
from typing import Callable, Optional


def get_int_env(name: str, default: int) -> int:
    """Get an integer from environment variable, with fallback to default."""
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


# Type alias for token refresh callbacks
TokenRefreshCallback = Callable[[], Optional[str]]

# Connection constants - shared between agent and proxy
RECONNECT_DELAY = 5  # seconds - initial delay between reconnection attempts
RECONNECT_DELAY_MAX = 60  # seconds - maximum backoff delay
RECONNECT_BACKOFF_FACTOR = 2  # multiplier for each failed attempt
HEARTBEAT_INTERVAL = get_int_env("NETBRIDGE_HEARTBEAT_INTERVAL", 30)  # seconds - ping interval
WS_CONNECT_TIMEOUT = get_int_env("NETBRIDGE_WS_CONNECT_TIMEOUT", 30)  # seconds - connection timeout
MAX_AUTH_FAILURES = 3  # consecutive auth failures before giving up
TOKEN_REFRESH_CHECK_INTERVAL = 60  # seconds - how often to check token expiration
TOKEN_REFRESH_THRESHOLD = 600  # seconds - refresh when less than 10 minutes remaining

# Stream management constants - configurable via environment variables
IDLE_STREAM_TIMEOUT = get_int_env("NETBRIDGE_IDLE_STREAM_TIMEOUT", 120)  # seconds - idle timeout
MAX_CONCURRENT_STREAMS = get_int_env("NETBRIDGE_MAX_CONCURRENT_STREAMS", 200)  # proxy limit
MAX_ACTIVE_STREAMS = get_int_env("NETBRIDGE_MAX_ACTIVE_STREAMS", 500)  # agent limit
STALLED_STREAM_CLEANUP_INTERVAL = get_int_env("NETBRIDGE_CLEANUP_INTERVAL", 30)  # seconds


def get_session_id() -> str:
    """
    Generate a stable session ID for this client/agent.

    Hashes hostname:username with SHA-256 so that the ID is stable and
    unique per machine/user, but does not leak plaintext metadata in
    headers, logs, or the tray UI.
    """
    hostname = socket.gethostname()
    username = getpass.getuser()
    raw = f"{hostname}:{username}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class TokenHolder:
    """Mutable container for auth token to allow background refresh."""

    def __init__(self, token: str | None, refresh_callback: TokenRefreshCallback | None = None):
        self.token = token
        self.refresh_callback = refresh_callback
        self.failure_count = 0

    def get(self) -> str | None:
        """Get the current token."""
        return self.token

    def refresh(self) -> bool:
        """Attempt to refresh the token. Returns True if successful."""
        if not self.refresh_callback:
            return False
        try:
            new_token = self.refresh_callback()
            if new_token:
                self.token = new_token
                self.failure_count = 0
                return True
        except RuntimeError:
            self.failure_count += 1
        return False
