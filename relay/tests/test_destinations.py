"""Tests for destination allow/deny list filtering."""

import ipaddress

import pytest

from relay.__main__ import _check_destination_allowed


class TestCheckDestinationAllowed:
    """Tests for _check_destination_allowed()."""

    @pytest.mark.asyncio
    async def test_default_allow_when_no_lists(self, monkeypatch, _reload_destination_lists):
        """All destinations allowed when no env vars are set."""
        monkeypatch.delenv("RELAY_DENIED_DESTINATIONS", raising=False)
        monkeypatch.delenv("RELAY_ALLOWED_DESTINATIONS", raising=False)
        _reload_destination_lists()

        allowed, reason = await _check_destination_allowed("example.com")
        assert allowed is True
        assert reason == ""

    @pytest.mark.asyncio
    async def test_deny_cidr_blocks_ip(self, monkeypatch, _reload_destination_lists):
        """IP in a denied CIDR range is blocked."""
        monkeypatch.setenv("RELAY_DENIED_DESTINATIONS", "10.0.0.0/8")
        monkeypatch.delenv("RELAY_ALLOWED_DESTINATIONS", raising=False)
        _reload_destination_lists()

        allowed, reason = await _check_destination_allowed("10.1.2.3")
        assert allowed is False
        assert "denied" in reason.lower()

    @pytest.mark.asyncio
    async def test_deny_cidr_allows_other_ip(self, monkeypatch, _reload_destination_lists):
        """IP outside denied CIDR range is allowed."""
        monkeypatch.setenv("RELAY_DENIED_DESTINATIONS", "10.0.0.0/8")
        monkeypatch.delenv("RELAY_ALLOWED_DESTINATIONS", raising=False)
        _reload_destination_lists()

        allowed, _ = await _check_destination_allowed("192.168.1.1")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_deny_hostname_pattern(self, monkeypatch, _reload_destination_lists):
        """Hostname matching a denied glob pattern is blocked."""
        monkeypatch.setenv("RELAY_DENIED_DESTINATIONS", "*.evil.com")
        monkeypatch.delenv("RELAY_ALLOWED_DESTINATIONS", raising=False)
        _reload_destination_lists()

        allowed, reason = await _check_destination_allowed("app.evil.com")
        assert allowed is False
        assert "denied" in reason.lower()

    @pytest.mark.asyncio
    async def test_allow_cidr_permits_matching_ip(self, monkeypatch, _reload_destination_lists):
        """IP in allowed CIDR is permitted."""
        monkeypatch.delenv("RELAY_DENIED_DESTINATIONS", raising=False)
        monkeypatch.setenv("RELAY_ALLOWED_DESTINATIONS", "172.16.0.0/12")
        _reload_destination_lists()

        allowed, _ = await _check_destination_allowed("172.16.5.10")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_allow_cidr_blocks_non_matching_ip(self, monkeypatch, _reload_destination_lists):
        """IP not in allowed CIDR is blocked when allowlist is configured."""
        monkeypatch.delenv("RELAY_DENIED_DESTINATIONS", raising=False)
        monkeypatch.setenv("RELAY_ALLOWED_DESTINATIONS", "172.16.0.0/12")
        _reload_destination_lists()

        allowed, reason = await _check_destination_allowed("8.8.8.8")
        assert allowed is False
        assert "not in the allowed" in reason.lower()

    @pytest.mark.asyncio
    async def test_allow_hostname_pattern(self, monkeypatch, _reload_destination_lists):
        """Hostname matching allowed glob pattern is permitted."""
        monkeypatch.delenv("RELAY_DENIED_DESTINATIONS", raising=False)
        monkeypatch.setenv("RELAY_ALLOWED_DESTINATIONS", "*.corp.example.com")
        _reload_destination_lists()

        allowed, _ = await _check_destination_allowed("app.corp.example.com")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_allow_hostname_blocks_non_matching(self, monkeypatch, _reload_destination_lists):
        """Hostname not matching allowed glob is blocked."""
        monkeypatch.delenv("RELAY_DENIED_DESTINATIONS", raising=False)
        monkeypatch.setenv("RELAY_ALLOWED_DESTINATIONS", "*.corp.example.com")
        _reload_destination_lists()

        allowed, _ = await _check_destination_allowed("external.com")
        assert allowed is False

    @pytest.mark.asyncio
    async def test_deny_wins_over_allow(self, monkeypatch, _reload_destination_lists):
        """Deny list takes precedence over allow list."""
        monkeypatch.setenv("RELAY_DENIED_DESTINATIONS", "10.0.0.0/8")
        monkeypatch.setenv("RELAY_ALLOWED_DESTINATIONS", "10.0.0.0/8,172.16.0.0/12")
        _reload_destination_lists()

        # 10.x is in both lists — deny wins
        allowed, reason = await _check_destination_allowed("10.1.1.1")
        assert allowed is False
        assert "denied" in reason.lower()

        # 172.16.x is only in allow list — passes
        allowed, _ = await _check_destination_allowed("172.16.1.1")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_hostname_matching_case_insensitive(self, monkeypatch, _reload_destination_lists):
        """Hostname pattern matching is case-insensitive."""
        monkeypatch.setenv("RELAY_DENIED_DESTINATIONS", "*.Evil.COM")
        monkeypatch.delenv("RELAY_ALLOWED_DESTINATIONS", raising=False)
        _reload_destination_lists()

        allowed, _ = await _check_destination_allowed("APP.EVIL.COM")
        assert allowed is False

    @pytest.mark.asyncio
    async def test_multiple_entries(self, monkeypatch, _reload_destination_lists):
        """Multiple comma-separated entries are all checked."""
        monkeypatch.setenv("RELAY_DENIED_DESTINATIONS", "10.0.0.0/8,192.168.0.0/16,*.bad.com")
        monkeypatch.delenv("RELAY_ALLOWED_DESTINATIONS", raising=False)
        _reload_destination_lists()

        allowed1, _ = await _check_destination_allowed("10.0.0.1")
        allowed2, _ = await _check_destination_allowed("192.168.1.1")
        allowed3, _ = await _check_destination_allowed("host.bad.com")
        allowed4, _ = await _check_destination_allowed("8.8.8.8")

        assert allowed1 is False
        assert allowed2 is False
        assert allowed3 is False
        assert allowed4 is True

    @pytest.mark.asyncio
    async def test_ipv6_brackets_stripped(self, monkeypatch, _reload_destination_lists):
        """IPv6 addresses with brackets are handled correctly."""
        monkeypatch.setenv("RELAY_DENIED_DESTINATIONS", "::1/128")
        monkeypatch.delenv("RELAY_ALLOWED_DESTINATIONS", raising=False)
        _reload_destination_lists()

        allowed, reason = await _check_destination_allowed("[::1]")
        assert allowed is False
        assert "denied" in reason.lower()

    @pytest.mark.asyncio
    async def test_dns_resolved_ip_denied(self, monkeypatch, _reload_destination_lists):
        """Hostname resolving to a denied IP is blocked."""
        import asyncio

        monkeypatch.setenv("RELAY_DENIED_DESTINATIONS", "127.0.0.0/8")
        monkeypatch.delenv("RELAY_ALLOWED_DESTINATIONS", raising=False)
        _reload_destination_lists()

        # Mock getaddrinfo to return 127.0.0.1
        async def fake_getaddrinfo(host, port, *args, **kwargs):
            return [(2, 1, 6, "", ("127.0.0.1", 0))]

        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)

        allowed, reason = await _check_destination_allowed("evil.example.com")
        assert allowed is False
        assert "denied" in reason.lower()
        assert "127.0.0.1" in reason


@pytest.fixture
def _reload_destination_lists():
    """Fixture that returns a callable to reload destination lists from current env vars."""
    import relay.__main__ as mod

    def _reload():
        mod._DENIED_CIDRS, mod._DENIED_PATTERNS = mod._parse_destination_list(
            "RELAY_DENIED_DESTINATIONS"
        )
        mod._ALLOWED_CIDRS, mod._ALLOWED_PATTERNS = mod._parse_destination_list(
            "RELAY_ALLOWED_DESTINATIONS"
        )
        mod._HAS_ALLOWLIST = bool(mod._ALLOWED_CIDRS or mod._ALLOWED_PATTERNS)

    return _reload
