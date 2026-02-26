"""Tests for socks_proxy_win.config."""

import json
from pathlib import Path

from socks_proxy_win.config import (
    APP_NAME,
    Config,
    DEFAULT_RELAY_URL,
    ensure_app_dirs,
    get_app_dir,
    get_config_path,
    get_log_dir,
    get_log_path,
)


class TestPathHelpers:
    """Tests for path helper functions."""

    def test_get_app_dir_uses_localappdata(self, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", "/fake/appdata")
        assert get_app_dir() == Path("/fake/appdata") / APP_NAME

    def test_get_app_dir_falls_back_to_home(self, monkeypatch):
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        result = get_app_dir()
        assert result.name == APP_NAME

    def test_get_config_path(self, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", "/fake")
        assert get_config_path() == Path("/fake") / APP_NAME / "config.json"

    def test_get_log_dir(self, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", "/fake")
        assert get_log_dir() == Path("/fake") / APP_NAME / "logs"

    def test_get_log_path(self, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", "/fake")
        assert get_log_path() == Path("/fake") / APP_NAME / "logs" / "netbridge-socks.log"

    def test_ensure_app_dirs_creates_directories(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        ensure_app_dirs()
        assert (tmp_path / APP_NAME).is_dir()
        assert (tmp_path / APP_NAME / "logs").is_dir()

    def test_ensure_app_dirs_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        ensure_app_dirs()
        ensure_app_dirs()  # should not raise
        assert (tmp_path / APP_NAME).is_dir()


class TestConfigDefaults:
    """Tests for Config default values."""

    def test_defaults(self):
        config = Config()
        assert config.relay_url == DEFAULT_RELAY_URL
        assert config.socks_port == 1080
        assert config.http_port == 3128
        assert config.auto_connect is True
        assert config.show_notifications is True
        assert config.log_level == "INFO"


class TestConfigToDict:
    """Tests for Config.to_dict()."""

    def test_to_dict_default(self):
        d = Config().to_dict()
        assert d == {
            "relay_url": DEFAULT_RELAY_URL,
            "socks_port": 1080,
            "http_port": 3128,
            "auto_connect": True,
            "show_notifications": True,
            "log_level": "INFO",
        }

    def test_to_dict_custom(self):
        config = Config(relay_url="my-relay.example.com", socks_port=9999, log_level="DEBUG")
        d = config.to_dict()
        assert d["relay_url"] == "my-relay.example.com"
        assert d["socks_port"] == 9999
        assert d["log_level"] == "DEBUG"


class TestConfigFromDict:
    """Tests for Config.from_dict()."""

    def test_from_dict_full(self):
        data = {
            "relay_url": "relay.test.com",
            "socks_port": 2080,
            "http_port": 4128,
            "auto_connect": False,
            "show_notifications": False,
            "log_level": "DEBUG",
        }
        config = Config.from_dict(data)
        assert config.relay_url == "relay.test.com"
        assert config.socks_port == 2080
        assert config.http_port == 4128
        assert config.auto_connect is False
        assert config.show_notifications is False
        assert config.log_level == "DEBUG"

    def test_from_dict_empty_uses_defaults(self):
        config = Config.from_dict({})
        assert config.relay_url == DEFAULT_RELAY_URL
        assert config.socks_port == 1080

    def test_from_dict_partial(self):
        config = Config.from_dict({"relay_url": "partial.example.com"})
        assert config.relay_url == "partial.example.com"
        assert config.socks_port == 1080  # default

    def test_from_dict_extra_keys_ignored(self):
        config = Config.from_dict({"relay_url": "test.com", "unknown_key": "value"})
        assert config.relay_url == "test.com"
        assert not hasattr(config, "unknown_key")

    def test_roundtrip(self):
        original = Config(relay_url="rt.example.com", socks_port=5555, log_level="WARNING")
        restored = Config.from_dict(original.to_dict())
        assert restored == original


class TestConfigSaveLoad:
    """Tests for Config.save() and Config.load()."""

    def test_save_creates_file(self, tmp_path):
        config_path = tmp_path / "config.json"
        Config().save(path=config_path)
        assert config_path.exists()

    def test_save_creates_parent_dirs(self, tmp_path):
        config_path = tmp_path / "sub" / "dir" / "config.json"
        Config().save(path=config_path)
        assert config_path.exists()

    def test_save_writes_valid_json(self, tmp_path):
        config_path = tmp_path / "config.json"
        Config(relay_url="json-test.com").save(path=config_path)
        data = json.loads(config_path.read_text())
        assert data["relay_url"] == "json-test.com"

    def test_load_existing(self, tmp_path):
        config_path = tmp_path / "config.json"
        original = Config(relay_url="load-test.com", socks_port=7777)
        original.save(path=config_path)
        loaded = Config.load(path=config_path)
        assert loaded == original

    def test_load_missing_returns_defaults(self, tmp_path):
        config_path = tmp_path / "nonexistent.json"
        loaded = Config.load(path=config_path)
        assert loaded == Config()

    def test_load_corrupt_json_returns_defaults(self, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text("not valid json {{{")
        loaded = Config.load(path=config_path)
        assert loaded == Config()

    def test_load_empty_file_returns_defaults(self, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text("")
        loaded = Config.load(path=config_path)
        assert loaded == Config()

    def test_save_load_roundtrip(self, tmp_path):
        config_path = tmp_path / "config.json"
        original = Config(
            relay_url="roundtrip.example.com",
            socks_port=1234,
            http_port=5678,
            auto_connect=False,
            show_notifications=False,
            log_level="WARNING",
        )
        original.save(path=config_path)
        loaded = Config.load(path=config_path)
        assert loaded == original
