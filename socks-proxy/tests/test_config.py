"""Tests for socks_proxy.config."""

import json

from socks_proxy.config import Config, get_config_dir, get_config_path


class TestConfig:
    def test_defaults(self):
        c = Config()
        assert c.relay_url == "your-relay-host.example.com"
        assert c.socks_port == 1080
        assert c.http_port == 3128
        assert c.show_notifications is True
        assert c.log_level == "INFO"

    def test_roundtrip(self, tmp_path):
        path = tmp_path / "config.json"
        c = Config(relay_url="relay.test.com", socks_port=9090, http_port=4128)
        c.save(path)
        loaded = Config.load(path)
        assert loaded.relay_url == "relay.test.com"
        assert loaded.socks_port == 9090
        assert loaded.http_port == 4128
        assert loaded.show_notifications is True

    def test_load_missing_file(self, tmp_path):
        c = Config.load(tmp_path / "nonexistent.json")
        assert c.relay_url == "your-relay-host.example.com"

    def test_load_corrupt_file(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text("not json")
        c = Config.load(path)
        assert c.relay_url == "your-relay-host.example.com"

    def test_from_dict_partial(self):
        c = Config.from_dict({"relay_url": "custom.host"})
        assert c.relay_url == "custom.host"
        assert c.socks_port == 1080

    def test_to_dict(self):
        c = Config(relay_url="test.com", show_notifications=False)
        d = c.to_dict()
        assert d["relay_url"] == "test.com"
        assert d["show_notifications"] is False
        assert set(d.keys()) == {"relay_url", "socks_port", "http_port",
                                  "show_notifications", "log_level",
                                  "probe_target"}

    def test_from_dict_non_dict(self):
        c = Config.from_dict([1, 2, 3])
        assert c.relay_url == "your-relay-host.example.com"

    def test_from_dict_null_relay(self):
        c = Config.from_dict({"relay_url": None})
        assert c.relay_url == "your-relay-host.example.com"

    def test_from_dict_port_out_of_range(self):
        c = Config.from_dict({"socks_port": 70000})
        assert c.socks_port == 1080

    def test_from_dict_port_negative(self):
        c = Config.from_dict({"socks_port": -1})
        assert c.socks_port == 1080

    def test_from_dict_port_zero(self):
        c = Config.from_dict({"socks_port": 0})
        assert c.socks_port == 1080

    def test_from_dict_string_port(self):
        c = Config.from_dict({"socks_port": "8080"})
        assert c.socks_port == 1080

    def test_from_dict_bool_is_not_port(self):
        c = Config.from_dict({"socks_port": True})
        assert c.socks_port == 1080

    def test_from_dict_string_false_notifications(self):
        c = Config.from_dict({"show_notifications": "false"})
        assert c.show_notifications is True

    def test_from_dict_valid_port(self):
        c = Config.from_dict({"socks_port": 9090, "http_port": 4128})
        assert c.socks_port == 9090
        assert c.http_port == 4128

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "sub" / "dir" / "config.json"
        Config().save(path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["socks_port"] == 1080


class TestPaths:
    def test_config_dir_returns_path(self):
        d = get_config_dir()
        assert "netbridge-socks" in str(d)

    def test_config_path_is_json(self):
        p = get_config_path()
        assert p.name == "config.json"
