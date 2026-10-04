"""
Machine-readable reasons for a failed tcp_connect_result.

Agent and relay set the optional `error_code` field next to the free-text
`error`; the proxy maps it to a SOCKS5 reply and an HTTP status. Absent or
unknown codes (old or newer peers) keep the pre-code replies, 0x04 and 502.
"""

import re

REFUSED = "refused"
DNS_FAILED = "dns_failed"
HOST_UNREACHABLE = "host_unreachable"
NETWORK_UNREACHABLE = "network_unreachable"
TIMEOUT = "timeout"
NOT_ALLOWED = "not_allowed"
NO_AGENT = "no_agent"
CAPACITY = "capacity"
INVALID_REQUEST = "invalid_request"
UNAVAILABLE = "unavailable"
UPSTREAM_PROXY = "upstream_proxy"
GENERAL = "general"

ALL_CODES = frozenset({
    REFUSED, DNS_FAILED, HOST_UNREACHABLE, NETWORK_UNREACHABLE, TIMEOUT,
    NOT_ALLOWED, NO_AGENT, CAPACITY, INVALID_REQUEST, UNAVAILABLE,
    UPSTREAM_PROXY, GENERAL,
})

ERROR_CODE_RE = re.compile(r"[a-z_]{1,32}")

FALLBACK_SOCKS5_REPLY = 0x04  # host unreachable
FALLBACK_HTTP_STATUS = 502

SOCKS5_REPLY: dict[str, int] = {
    REFUSED: 0x05,
    DNS_FAILED: 0x04,
    HOST_UNREACHABLE: 0x04,
    NETWORK_UNREACHABLE: 0x03,
    TIMEOUT: 0x06,
    NOT_ALLOWED: 0x02,
    NO_AGENT: 0x04,  # what clients have always seen when the agent is down
    CAPACITY: 0x01,
    INVALID_REQUEST: 0x01,
    UNAVAILABLE: 0x01,
    UPSTREAM_PROXY: 0x01,
    GENERAL: 0x01,
}

HTTP_STATUS: dict[str, int] = {
    REFUSED: 502,
    DNS_FAILED: 502,
    HOST_UNREACHABLE: 502,
    NETWORK_UNREACHABLE: 502,
    TIMEOUT: 504,
    NOT_ALLOWED: 403,
    NO_AGENT: 503,
    CAPACITY: 503,
    INVALID_REQUEST: 400,
    UNAVAILABLE: 502,
    UPSTREAM_PROXY: 502,
    GENERAL: 502,
}


def valid_error_code(value) -> bool:
    """Whether value is a well-formed code (known or not)."""
    return isinstance(value, str) and ERROR_CODE_RE.fullmatch(value) is not None


def socks5_reply_for(code) -> int:
    return SOCKS5_REPLY.get(code, FALLBACK_SOCKS5_REPLY) if isinstance(code, str) else FALLBACK_SOCKS5_REPLY


def http_status_for(code) -> int:
    return HTTP_STATUS.get(code, FALLBACK_HTTP_STATUS) if isinstance(code, str) else FALLBACK_HTTP_STATUS
