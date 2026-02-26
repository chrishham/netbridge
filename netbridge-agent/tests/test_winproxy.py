"""Tests for netbridge_agent.winproxy module.

Since WinHTTP (winhttp.dll) is only available on Windows, these tests focus on:
- Struct binding verification
- The pure-Python helper _parse_proxy_list
- Constants
"""

import sys

import pytest

from netbridge_agent.winproxy import (
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_ACCESS_TYPE_NAMED_PROXY,
    WINHTTP_ACCESS_TYPE_NO_PROXY,
    WINHTTP_AUTO_DETECT_TYPE_DHCP,
    WINHTTP_AUTO_DETECT_TYPE_DNS_A,
    WINHTTP_AUTOPROXY_AUTO_DETECT,
    WINHTTP_AUTOPROXY_CONFIG_URL,
    WINHTTP_AUTOPROXY_OPTIONS,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG,
    WINHTTP_PROXY_INFO,
    _parse_proxy_list,
    verify_bindings,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_access_type_values(self):
        assert WINHTTP_ACCESS_TYPE_DEFAULT_PROXY == 0
        assert WINHTTP_ACCESS_TYPE_NO_PROXY == 1
        assert WINHTTP_ACCESS_TYPE_NAMED_PROXY == 3
        assert WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY == 4

    def test_autoproxy_flags(self):
        assert WINHTTP_AUTOPROXY_AUTO_DETECT == 1
        assert WINHTTP_AUTOPROXY_CONFIG_URL == 2

    def test_auto_detect_types(self):
        assert WINHTTP_AUTO_DETECT_TYPE_DHCP == 1
        assert WINHTTP_AUTO_DETECT_TYPE_DNS_A == 2


# ---------------------------------------------------------------------------
# Struct bindings
# ---------------------------------------------------------------------------


class TestStructBindings:
    def test_verify_bindings_does_not_raise(self):
        verify_bindings()

    def test_autoproxy_options_fields(self):
        opts = WINHTTP_AUTOPROXY_OPTIONS()
        opts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
        opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP
        opts.fAutoLogonIfChallenged = True
        assert opts.dwFlags == WINHTTP_AUTOPROXY_AUTO_DETECT

    def test_proxy_info_fields(self):
        info = WINHTTP_PROXY_INFO()
        info.dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY
        assert info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY

    def test_ie_proxy_config_fields(self):
        ie = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
        ie.fAutoDetect = False
        assert not ie.fAutoDetect


# ---------------------------------------------------------------------------
# _parse_proxy_list
# ---------------------------------------------------------------------------


class TestParseProxyList:
    def test_simple_proxy(self):
        assert _parse_proxy_list("proxy.corp:3128", "https://example.com") == "proxy.corp:3128"

    def test_direct_returns_none(self):
        assert _parse_proxy_list("DIRECT", "https://example.com") is None

    def test_direct_case_insensitive(self):
        assert _parse_proxy_list("direct", "https://example.com") is None

    def test_empty_returns_none(self):
        assert _parse_proxy_list("", "https://example.com") is None

    def test_none_returns_none(self):
        assert _parse_proxy_list(None, "https://example.com") is None

    def test_protocol_specific_https(self):
        result = _parse_proxy_list(
            "http=proxy1:8080;https=proxy2:3128",
            "https://example.com",
        )
        assert result == "proxy2:3128"

    def test_protocol_specific_http(self):
        result = _parse_proxy_list(
            "http=proxy1:8080;https=proxy2:3128",
            "http://example.com",
        )
        assert result == "proxy1:8080"

    def test_fallback_list_uses_first(self):
        result = _parse_proxy_list(
            "proxy1:8080;proxy2:3128",
            "https://example.com",
        )
        assert result == "proxy1:8080"

    def test_protocol_specific_no_match(self):
        """When only http= is specified but URL is https, no match."""
        result = _parse_proxy_list(
            "http=proxy1:8080",
            "https://example.com",
        )
        assert result is None

    def test_whitespace_trimmed(self):
        result = _parse_proxy_list(
            "  proxy.corp:3128  ",
            "https://example.com",
        )
        assert result == "proxy.corp:3128"


# ---------------------------------------------------------------------------
# get_proxy_for_url on non-Windows
# ---------------------------------------------------------------------------


class TestGetProxyForUrlNonWindows:
    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_returns_none_on_non_windows(self):
        """get_proxy_for_url should return None on non-Windows (no winhttp)."""
        from netbridge_agent.winproxy import get_proxy_for_url
        assert get_proxy_for_url("https://example.com") is None

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_safe_wrapper_returns_none(self):
        from netbridge_agent.winproxy import get_proxy_for_url_safe
        assert get_proxy_for_url_safe("https://example.com") is None
