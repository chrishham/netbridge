"""Client IP resolution behind optional trusted proxies."""

import pytest
from unittest.mock import MagicMock

from multidict import CIMultiDict

import relay.__main__ as mod


def _req(remote, headers=None):
    """headers: a dict, or a list of (name, value) pairs to send a field more than once."""
    r = MagicMock()
    r.remote = remote
    r.headers = CIMultiDict(headers or {})  # what aiohttp's request.headers is
    return r


@pytest.fixture
def trusted(monkeypatch):
    def set_(cidrs, header="X-Forwarded-For"):
        monkeypatch.setattr(mod, "_TRUSTED_PROXIES", mod._parse_trusted_proxies(cidrs))
        monkeypatch.setattr(mod, "CLIENT_IP_HEADER", header)
    return set_


def test_default_uses_remote_even_with_header(monkeypatch):
    monkeypatch.setattr(mod, "_TRUSTED_PROXIES", ())
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": "1.1.1.1"})) == "10.0.0.5"


def test_missing_remote_is_unknown(monkeypatch):
    monkeypatch.setattr(mod, "_TRUSTED_PROXIES", ())
    assert mod._client_ip(_req(None)) == "unknown"


def test_untrusted_remote_ignores_header(trusted):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("203.0.113.9", {"X-Forwarded-For": "1.1.1.1"})) == "203.0.113.9"


def test_xff_rightmost_untrusted_wins(trusted):
    trusted("10.0.0.0/8")
    req = _req("10.0.0.5", {"X-Forwarded-For": "6.6.6.6, 1.1.1.1, 10.0.0.7"})
    assert mod._client_ip(req) == "1.1.1.1"


def test_xff_all_trusted_falls_back_to_remote(trusted):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": "10.1.1.1, 10.2.2.2"})) == "10.0.0.5"


def test_xff_garbage_entry_is_skipped(trusted):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": "1.1.1.1, not-an-ip"})) == "1.1.1.1"


@pytest.mark.parametrize("entry, want", [
    ("1.2.3.4:5678", "1.2.3.4"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("2001:db8::1", "2001:db8::1"),
])
def test_xff_entries_with_ports(trusted, entry, want):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": entry})) == want


@pytest.mark.parametrize("value", ["", "   ", " , "])
def test_blank_header_falls_back_to_remote(trusted, value):
    trusted("10.0.0.0/8")
    assert mod._client_ip(_req("10.0.0.5", {"X-Forwarded-For": value})) == "10.0.0.5"


def test_ipv6_trusted_remote(trusted):
    trusted("::1/128")
    assert mod._client_ip(_req("::1", {"X-Forwarded-For": "2001:db8::7"})) == "2001:db8::7"


def test_single_value_header(trusted):
    trusted("10.0.0.0/8", header="CF-Connecting-IP")
    assert mod._client_ip(_req("10.0.0.5", {"CF-Connecting-IP": " 1.1.1.1 "})) == "1.1.1.1"


def test_single_value_header_invalid_falls_back(trusted):
    trusted("10.0.0.0/8", header="CF-Connecting-IP")
    assert mod._client_ip(_req("10.0.0.5", {"CF-Connecting-IP": "1.1.1.1, 2.2.2.2"})) == "10.0.0.5"


def test_repeated_xff_fields_are_joined_in_order(trusted):
    # The client sends its own field; the trusted proxy appends the real peer as a second field
    trusted("10.0.0.0/8")
    req = _req("10.0.0.5", [("X-Forwarded-For", "6.6.6.6"), ("X-Forwarded-For", "1.1.1.1")])
    assert mod._client_ip(req) == "1.1.1.1"


def test_repeated_single_value_fields_fall_back(trusted):
    trusted("10.0.0.0/8", header="CF-Connecting-IP")
    req = _req("10.0.0.5", [("CF-Connecting-IP", "6.6.6.6"), ("CF-Connecting-IP", "1.1.1.1")])
    assert mod._client_ip(req) == "10.0.0.5"


def test_xff_header_name_case_insensitive(trusted):
    trusted("10.0.0.0/8", header="x-forwarded-for")
    req = _req("10.0.0.5", {"x-forwarded-for": "1.1.1.1, 10.0.0.7"})
    assert mod._client_ip(req) == "1.1.1.1"


def test_parse_trusted_proxies():
    nets = mod._parse_trusted_proxies(" 10.0.0.0/8, 192.168.1.1 ,::1/128,")
    assert [str(n) for n in nets] == ["10.0.0.0/8", "192.168.1.1/32", "::1/128"]
    assert mod._parse_trusted_proxies("") == ()


@pytest.mark.parametrize("raw", ["10.0.0.0/33", "nope", "10.0.0.0/8,bad"])
def test_parse_trusted_proxies_rejects_invalid(raw):
    with pytest.raises(ValueError):
        mod._parse_trusted_proxies(raw)
