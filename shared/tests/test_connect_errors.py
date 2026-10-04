"""Tests for the tcp_connect_result error-code vocabulary and its mappings."""

import pytest

from shared_auth import connect_errors as ce


def test_every_code_is_listed_and_well_formed():
    constants = {
        ce.REFUSED, ce.DNS_FAILED, ce.HOST_UNREACHABLE, ce.NETWORK_UNREACHABLE,
        ce.TIMEOUT, ce.NOT_ALLOWED, ce.NO_AGENT, ce.CAPACITY,
        ce.INVALID_REQUEST, ce.UNAVAILABLE, ce.UPSTREAM_PROXY, ce.GENERAL,
    }
    assert constants == ce.ALL_CODES
    assert all(ce.valid_error_code(c) for c in ce.ALL_CODES)


def test_unknown_but_well_formed_code_is_valid():
    assert ce.valid_error_code("future_code")
    assert ce.valid_error_code("a" * 32)


@pytest.mark.parametrize("value", [None, 1, True, "", "A", "a-b", "a" * 33, "refused\n", " refused"])
def test_malformed_codes_are_rejected(value):
    assert not ce.valid_error_code(value)


def test_both_maps_cover_exactly_the_vocabulary():
    assert set(ce.SOCKS5_REPLY) == ce.ALL_CODES
    assert set(ce.HTTP_STATUS) == ce.ALL_CODES


@pytest.mark.parametrize("code, reply, status", [
    ("refused", 0x05, 502),
    ("dns_failed", 0x04, 502),
    ("host_unreachable", 0x04, 502),
    ("network_unreachable", 0x03, 502),
    ("timeout", 0x06, 504),
    ("not_allowed", 0x02, 403),
    ("no_agent", 0x04, 503),
    ("capacity", 0x01, 503),
    ("invalid_request", 0x01, 400),
    ("unavailable", 0x01, 502),
    ("upstream_proxy", 0x01, 502),
    ("general", 0x01, 502),
])
def test_mapping_table(code, reply, status):
    assert ce.socks5_reply_for(code) == reply
    assert ce.http_status_for(code) == status


@pytest.mark.parametrize("code", [None, "future_code", 7, "BAD"])
def test_absent_or_unknown_code_keeps_todays_replies(code):
    assert ce.socks5_reply_for(code) == 0x04
    assert ce.http_status_for(code) == 502
