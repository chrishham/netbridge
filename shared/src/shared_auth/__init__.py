"""
Shared authentication module for Network Bridge.

Uses Azure CLI (az login) credentials - no app registration needed.
All components authenticate using ARM (Azure Resource Manager) tokens.
"""

from .token import (
    get_arm_token,
    get_user_identity,
    check_az_login,
    check_token_expiration,
    get_token_remaining_seconds,
    decode_jwt_payload,
    AZ_CLI_TIMEOUT,
    MIN_TOKEN_VALIDITY,
)
from .validate import validate_arm_token, TokenValidationError
from .session import (
    get_int_env,
    get_session_id,
    TokenHolder,
    TokenRefreshCallback,
    RECONNECT_DELAY,
    RECONNECT_DELAY_MAX,
    RECONNECT_BACKOFF_FACTOR,
    HEARTBEAT_INTERVAL,
    WS_CONNECT_TIMEOUT,
    MAX_AUTH_FAILURES,
    TOKEN_REFRESH_CHECK_INTERVAL,
    TOKEN_REFRESH_THRESHOLD,
    IDLE_STREAM_TIMEOUT,
    MAX_CONCURRENT_STREAMS,
    MAX_ACTIVE_STREAMS,
    STALLED_STREAM_CLEANUP_INTERVAL,
)
from .connection import (
    create_tunnel_ssl_context,
    create_tunnel_timeout,
    create_tunnel_connector,
    build_auth_headers,
    VERIFY_SSL_DEFAULT,
    ALLOW_INSECURE,
    CA_BUNDLE_DEFAULT,
)

__all__ = [
    # Token acquisition and checking
    "get_arm_token",
    "get_user_identity",
    "check_az_login",
    "check_token_expiration",
    "get_token_remaining_seconds",
    "decode_jwt_payload",
    "AZ_CLI_TIMEOUT",
    "MIN_TOKEN_VALIDITY",
    # Server-side validation
    "validate_arm_token",
    "TokenValidationError",
    # Utility
    "get_int_env",
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
    "MAX_CONCURRENT_STREAMS",
    "MAX_ACTIVE_STREAMS",
    "STALLED_STREAM_CLEANUP_INTERVAL",
    # Connection utilities
    "create_tunnel_ssl_context",
    "create_tunnel_timeout",
    "create_tunnel_connector",
    "build_auth_headers",
    "VERIFY_SSL_DEFAULT",
    "ALLOW_INSECURE",
    "CA_BUNDLE_DEFAULT",
]
