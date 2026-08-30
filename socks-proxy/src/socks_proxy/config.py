"""Persistent configuration for NetBridge Socks (macOS/Linux)."""

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


APP_NAME = "netbridge-socks"
DEFAULT_RELAY_URL = "your-relay-host.example.com"


def get_config_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    xdg = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    return Path(xdg) / APP_NAME


def get_config_path() -> Path:
    return get_config_dir() / "config.json"


@dataclass
class Config:
    relay_url: str = DEFAULT_RELAY_URL
    socks_port: int = 1080
    http_port: int = 3128
    show_notifications: bool = True
    log_level: str = "INFO"
    # Optional "host:port" used to verify the tunnel works end to end. Only
    # needed when the relay's destination allow list rejects the default.
    probe_target: str = ""

    def to_dict(self) -> dict:
        return {
            "relay_url": self.relay_url,
            "socks_port": self.socks_port,
            "http_port": self.http_port,
            "show_notifications": self.show_notifications,
            "log_level": self.log_level,
            "probe_target": self.probe_target,
        }

    def parsed_probe_target(self) -> Optional[tuple[str, int]]:
        """Return probe_target as (host, port), or None if unset/invalid."""
        if not self.probe_target or ":" not in self.probe_target:
            return None
        host, _, port = self.probe_target.rpartition(":")
        if not host:
            return None
        try:
            port_num = int(port)
        except ValueError:
            return None
        if not 1 <= port_num <= 65535:
            return None
        return host, port_num

    @classmethod
    def from_dict(cls, data) -> "Config":
        if not isinstance(data, dict):
            return cls()

        def _str(val, default):
            return val if isinstance(val, str) and val else default

        def _port(val, default):
            if not isinstance(val, int) or isinstance(val, bool):
                return default
            return val if 1 <= val <= 65535 else default

        def _bool(val, default):
            return val if isinstance(val, bool) else default

        return cls(
            relay_url=_str(data.get("relay_url"), DEFAULT_RELAY_URL),
            socks_port=_port(data.get("socks_port"), 1080),
            http_port=_port(data.get("http_port"), 3128),
            show_notifications=_bool(data.get("show_notifications"), True),
            log_level=_str(data.get("log_level"), "INFO"),
            probe_target=_str(data.get("probe_target"), ""),
        )

    def save(self, path: Optional[Path] = None) -> None:
        config_path = path or get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        config_path = path or get_config_path()
        if config_path.exists():
            try:
                with open(config_path) as f:
                    data = json.load(f)
                return cls.from_dict(data)
            except (json.JSONDecodeError, IOError, UnicodeDecodeError):
                pass
        return cls()
