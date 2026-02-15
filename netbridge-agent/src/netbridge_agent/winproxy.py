"""
Windows WinHTTP proxy resolution via ctypes.

Uses the native WinHTTP API to resolve proxy settings for URLs,
including PAC (Proxy Auto-Config) file support. This uses the
same mechanism as browsers for proxy resolution.

Windows handles PAC caching/refresh based on HTTP headers automatically.
"""

import ctypes
import ctypes.wintypes
import logging
from ctypes import POINTER, Structure, byref, c_void_p, c_wchar_p
from typing import Optional

logger = logging.getLogger(__name__)

# WinHTTP constants
WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
WINHTTP_ACCESS_TYPE_NO_PROXY = 1
WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4

WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002

WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002

WINHTTP_NO_PROXY_NAME = None
WINHTTP_NO_PROXY_BYPASS = None

# Error codes
ERROR_WINHTTP_AUTODETECTION_FAILED = 12180
ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT = 12167


class WINHTTP_AUTOPROXY_OPTIONS(Structure):
    """Structure for WinHttpGetProxyForUrl options."""
    _fields_ = [
        ("dwFlags", ctypes.wintypes.DWORD),
        ("dwAutoDetectFlags", ctypes.wintypes.DWORD),
        ("lpszAutoConfigUrl", c_wchar_p),
        ("lpvReserved", c_void_p),
        ("dwReserved", ctypes.wintypes.DWORD),
        ("fAutoLogonIfChallenged", ctypes.wintypes.BOOL),
    ]


class WINHTTP_PROXY_INFO(Structure):
    """Structure for proxy information returned by WinHttpGetProxyForUrl."""
    _fields_ = [
        ("dwAccessType", ctypes.wintypes.DWORD),
        ("lpszProxy", c_wchar_p),
        ("lpszProxyBypass", c_wchar_p),
    ]


class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(Structure):
    """Structure for Internet Explorer proxy configuration."""
    _fields_ = [
        ("fAutoDetect", ctypes.wintypes.BOOL),
        ("lpszAutoConfigUrl", c_wchar_p),
        ("lpszProxy", c_wchar_p),
        ("lpszProxyBypass", c_wchar_p),
    ]


def verify_bindings() -> None:
    """Verify ctypes bindings work at runtime (called by --import-check).

    Constructs all structs and assigns fields to catch type mismatches
    that only surface at assignment time, not import time.
    """
    opts = WINHTTP_AUTOPROXY_OPTIONS()
    opts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
    opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP
    opts.fAutoLogonIfChallenged = True

    info = WINHTTP_PROXY_INFO()
    info.dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY

    ie = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
    ie.fAutoDetect = False


def _load_winhttp():
    """Load winhttp.dll and set up function prototypes."""
    winhttp = ctypes.windll.winhttp

    # WinHttpOpen
    winhttp.WinHttpOpen.argtypes = [
        c_wchar_p,  # pszAgentW
        ctypes.wintypes.DWORD,  # dwAccessType
        c_wchar_p,  # pszProxyW
        c_wchar_p,  # pszProxyBypassW
        ctypes.wintypes.DWORD,  # dwFlags
    ]
    winhttp.WinHttpOpen.restype = c_void_p

    # WinHttpCloseHandle
    winhttp.WinHttpCloseHandle.argtypes = [c_void_p]
    winhttp.WinHttpCloseHandle.restype = ctypes.wintypes.BOOL

    # WinHttpGetProxyForUrl
    winhttp.WinHttpGetProxyForUrl.argtypes = [
        c_void_p,  # hSession
        c_wchar_p,  # lpcwszUrl
        POINTER(WINHTTP_AUTOPROXY_OPTIONS),  # pAutoProxyOptions
        POINTER(WINHTTP_PROXY_INFO),  # pProxyInfo
    ]
    winhttp.WinHttpGetProxyForUrl.restype = ctypes.wintypes.BOOL

    # WinHttpGetIEProxyConfigForCurrentUser
    winhttp.WinHttpGetIEProxyConfigForCurrentUser.argtypes = [
        POINTER(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG),
    ]
    winhttp.WinHttpGetIEProxyConfigForCurrentUser.restype = ctypes.wintypes.BOOL

    return winhttp


def _get_ie_proxy_config() -> Optional[WINHTTP_CURRENT_USER_IE_PROXY_CONFIG]:
    """Get the current user's IE proxy configuration."""
    try:
        winhttp = _load_winhttp()
        ie_config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
        if winhttp.WinHttpGetIEProxyConfigForCurrentUser(byref(ie_config)):
            return ie_config
    except Exception:
        pass
    return None


def _parse_proxy_list(proxy_string: str, target_url: str) -> Optional[str]:
    """Parse a proxy list string and return the appropriate proxy.

    Proxy strings can be:
    - "proxy:port" - single proxy
    - "http=proxy1:port;https=proxy2:port" - protocol-specific
    - "proxy1:port;proxy2:port" - fallback list (use first)

    Returns the first matching proxy as "host:port" or None for DIRECT.
    """
    if not proxy_string:
        return None

    # Handle DIRECT explicitly
    if proxy_string.upper() == "DIRECT":
        return None

    # Determine the scheme from the target URL
    scheme = "https" if target_url.startswith("https://") else "http"

    # Check for protocol-specific proxy (e.g., "https=proxy:port")
    parts = proxy_string.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            proto, proxy = part.split("=", 1)
            if proto.lower() == scheme:
                return proxy.strip()
        else:
            # No protocol specified, use this proxy
            return part

    return None


def get_proxy_for_url(url: str) -> Optional[str]:
    """
    Resolve proxy for URL using Windows WinHTTP.

    Uses the same PAC (Proxy Auto-Config) resolution as browsers.
    Windows handles PAC caching/refresh based on HTTP headers automatically.

    Args:
        url: The URL to resolve proxy for (e.g., "https://example.com:443/")

    Returns:
        None - direct connection (no proxy needed)
        "host:port" - HTTP proxy to use
    """
    try:
        winhttp = _load_winhttp()
    except Exception as e:
        # Not on Windows or winhttp not available
        return None

    # First, get the IE proxy configuration to check for PAC URL
    ie_config = _get_ie_proxy_config()

    # Create a WinHTTP session
    session = winhttp.WinHttpOpen(
        "NetBridge/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0,
    )

    if not session:
        return None

    try:
        proxy_info = WINHTTP_PROXY_INFO()

        # Try auto-detection or PAC URL based on IE config
        auto_proxy_options = WINHTTP_AUTOPROXY_OPTIONS()

        if ie_config and ie_config.lpszAutoConfigUrl:
            # Use explicit PAC URL from system settings
            auto_proxy_options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
            auto_proxy_options.lpszAutoConfigUrl = ie_config.lpszAutoConfigUrl
            auto_proxy_options.fAutoLogonIfChallenged = True

            if winhttp.WinHttpGetProxyForUrl(
                session, url, byref(auto_proxy_options), byref(proxy_info)
            ):
                if proxy_info.lpszProxy:
                    return _parse_proxy_list(proxy_info.lpszProxy, url)
                return None  # DIRECT

        if ie_config and ie_config.fAutoDetect:
            # Try WPAD auto-detection
            auto_proxy_options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
            auto_proxy_options.dwAutoDetectFlags = (
                WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
            )
            auto_proxy_options.fAutoLogonIfChallenged = True

            if winhttp.WinHttpGetProxyForUrl(
                session, url, byref(auto_proxy_options), byref(proxy_info)
            ):
                if proxy_info.lpszProxy:
                    return _parse_proxy_list(proxy_info.lpszProxy, url)
                return None  # DIRECT

        # Fall back to static proxy from IE config
        if ie_config and ie_config.lpszProxy:
            # Check bypass list
            if ie_config.lpszProxyBypass:
                bypass_list = ie_config.lpszProxyBypass.lower()
                # Extract host from URL
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname.lower() if parsed.hostname else ""

                # Check if host matches bypass patterns
                for pattern in bypass_list.split(";"):
                    pattern = pattern.strip()
                    if pattern == "<local>" and "." not in host:
                        return None  # DIRECT for local names
                    if pattern.startswith("*"):
                        if host.endswith(pattern[1:]):
                            return None  # DIRECT
                    elif host == pattern:
                        return None  # DIRECT

            return _parse_proxy_list(ie_config.lpszProxy, url)

        # No proxy configured
        return None

    finally:
        winhttp.WinHttpCloseHandle(session)


def get_proxy_for_url_safe(url: str) -> Optional[str]:
    """
    Safe wrapper around get_proxy_for_url that catches all exceptions.

    Use this in production code to prevent proxy resolution failures
    from breaking the connection flow.

    Args:
        url: The URL to resolve proxy for

    Returns:
        None - direct connection (no proxy needed or error occurred)
        "host:port" - HTTP proxy to use
    """
    try:
        return get_proxy_for_url(url)
    except Exception:
        # On any error, fall back to direct connection
        return None
