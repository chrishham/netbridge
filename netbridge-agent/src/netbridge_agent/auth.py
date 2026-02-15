"""
ARM Token acquisition using Azure CLI credentials.

Re-exports from shared_auth for convenience.
"""

from shared_auth import (
    # Token acquisition and checking
    get_arm_token,
    get_user_identity,
    check_az_login,
    check_token_expiration,
    get_token_remaining_seconds,
    AZ_CLI_TIMEOUT,
    MIN_TOKEN_VALIDITY,
    # Session management
    get_session_id,
    TokenHolder,
    TokenRefreshCallback,
    # Connection constants
    RECONNECT_DELAY,
    RECONNECT_DELAY_MAX,
    RECONNECT_BACKOFF_FACTOR,
    HEARTBEAT_INTERVAL,
    WS_CONNECT_TIMEOUT,
    MAX_AUTH_FAILURES,
    TOKEN_REFRESH_CHECK_INTERVAL,
    TOKEN_REFRESH_THRESHOLD,
    IDLE_STREAM_TIMEOUT,
    MAX_ACTIVE_STREAMS,
    STALLED_STREAM_CLEANUP_INTERVAL,
    # Connection utilities
    create_tunnel_ssl_context,
    create_tunnel_timeout,
    create_tunnel_connector,
    build_auth_headers,
)

__all__ = [
    # Token acquisition and checking
    "get_arm_token",
    "get_user_identity",
    "check_az_login",
    "check_token_expiration",
    "get_token_remaining_seconds",
    "AZ_CLI_TIMEOUT",
    "MIN_TOKEN_VALIDITY",
    # Session management
    "get_session_id",
    "TokenHolder",
    "TokenRefreshCallback",
    # Connection constants
    "RECONNECT_DELAY",
    "RECONNECT_DELAY_MAX",
    "RECONNECT_BACKOFF_FACTOR",
    "HEARTBEAT_INTERVAL",
    "WS_CONNECT_TIMEOUT",
    "MAX_AUTH_FAILURES",
    "TOKEN_REFRESH_CHECK_INTERVAL",
    "TOKEN_REFRESH_THRESHOLD",
    "IDLE_STREAM_TIMEOUT",
    "MAX_ACTIVE_STREAMS",
    "STALLED_STREAM_CLEANUP_INTERVAL",
    # Connection utilities
    "create_tunnel_ssl_context",
    "create_tunnel_timeout",
    "create_tunnel_connector",
    "build_auth_headers",
]
