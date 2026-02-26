"""Tests for netbridge_agent.config module."""

import json

import pytest

from netbridge_agent.config import (
    Config,
    DEFAULT_RELAY_URL,
    normalize_relay_url,
    redact_proxy_url,
)


# ---------------------------------------------------------------------------
# normalize_relay_url
# ---------------------------------------------------------------------------


class TestNormalizeRelayUrl:
    def test_bare_hostname(self):
        assert normalize_relay_url("relay.example.com") == "wss://relay.example.com/ws"

    def test_bare_hostname_with_trailing_slash(self):
        assert normalize_relay_url("relay.example.com/") == "wss://relay.example.com/ws"

    def test_wss_scheme_no_path(self):
        assert normalize_relay_url("wss://relay.example.com") == "wss://relay.example.com/ws"

    def test_ws_scheme_no_path(self):
        assert normalize_relay_url("ws://relay.example.com") == "ws://relay.example.com/ws"

    def test_full_url_with_path_preserved(self):
        assert normalize_relay_url("wss://relay.example.com/custom") == "wss://relay.example.com/custom"

    def test_custom_path(self):
        assert normalize_relay_url("relay.example.com", path="/api") == "wss://relay.example.com/api"

    def test_whitespace_stripped(self):
        assert normalize_relay_url("  relay.example.com  ") == "wss://relay.example.com/ws"

    def test_full_url_trailing_slash_stripped(self):
        result = normalize_relay_url("wss://relay.example.com/ws/")
        assert result == "wss://relay.example.com/ws"


# ---------------------------------------------------------------------------
# redact_proxy_url
# ---------------------------------------------------------------------------


class TestRedactProxyUrl:
    def test_no_password_unchanged(self):
        assert redact_proxy_url("http://proxy:8080") == "http://proxy:8080"

    def test_plain_host_port_unchanged(self):
        assert redact_proxy_url("proxy:8080") == "proxy:8080"

    def test_password_redacted(self):
        result = redact_proxy_url("http://user:secret@proxy:8080")
        assert "secret" not in result
        assert "user" in result
        assert "***" in result
        assert "8080" in result

    def test_password_redacted_no_port(self):
        result = redact_proxy_url("http://user:secret@proxy")
        assert "secret" not in result
        assert "user" in result

    def test_empty_string(self):
        assert redact_proxy_url("") == ""

    def test_garbage_input_returned(self):
        """Non-URL strings should be returned as-is."""
        assert redact_proxy_url("not-a-url") == "not-a-url"


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


class TestConfig:
    def test_defaults(self):
        cfg = Config()
        assert cfg.relay_url == DEFAULT_RELAY_URL
        assert cfg.auto_connect is True
        assert cfg.show_notifications is True
        assert cfg.log_level == "INFO"
        assert cfg.allow_private_destinations is True
        assert cfg.allowed_destinations == []
        assert cfg.denied_destinations == []

    def test_to_dict_excludes_empty_lists(self):
        cfg = Config()
        d = cfg.to_dict()
        assert "allowed_destinations" not in d
        assert "denied_destinations" not in d

    def test_to_dict_includes_nonempty_lists(self):
        cfg = Config(allowed_destinations=["10.0.0.0/8"], denied_destinations=["evil.com"])
        d = cfg.to_dict()
        assert d["allowed_destinations"] == ["10.0.0.0/8"]
        assert d["denied_destinations"] == ["evil.com"]

    def test_roundtrip_dict(self):
        cfg = Config(relay_url="wss://my.relay/ws", log_level="DEBUG")
        d = cfg.to_dict()
        cfg2 = Config.from_dict(d)
        assert cfg2.relay_url == cfg.relay_url
        assert cfg2.log_level == cfg.log_level

    def test_from_dict_missing_keys_use_defaults(self):
        cfg = Config.from_dict({})
        assert cfg.relay_url == DEFAULT_RELAY_URL
        assert cfg.auto_connect is True

    def test_from_dict_extra_keys_ignored(self):
        cfg = Config.from_dict({"relay_url": "wss://x/ws", "unknown_key": 42})
        assert cfg.relay_url == "wss://x/ws"

    def test_save_and_load(self, tmp_path):
        path = tmp_path / "config.json"
        cfg = Config(relay_url="wss://test/ws", log_level="DEBUG")
        cfg.save(path)

        loaded = Config.load(path)
        assert loaded.relay_url == cfg.relay_url
        assert loaded.log_level == cfg.log_level

    def test_load_missing_file_returns_defaults(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        cfg = Config.load(path)
        assert cfg.relay_url == DEFAULT_RELAY_URL

    def test_load_corrupt_file_returns_defaults(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not valid json{{{")
        cfg = Config.load(path)
        assert cfg.relay_url == DEFAULT_RELAY_URL

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "a" / "b" / "config.json"
        cfg = Config()
        cfg.save(path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["relay_url"] == DEFAULT_RELAY_URL
