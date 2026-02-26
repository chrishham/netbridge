"""
Configuration management for NetBridge Socks (Windows).

Handles loading/saving configuration from JSON file in %LOCALAPPDATA%/NetBridgeSocks/.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import __version__ as APP_VERSION


# Default relay hostname
DEFAULT_RELAY_URL = "your-relay-host.example.com"

# App directories
APP_NAME = "NetBridgeSocks"


def get_app_dir() -> Path:
    """Get the application data directory (%LOCALAPPDATA%/NetBridgeSocks)."""
    local_app_data = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    return Path(local_app_data) / APP_NAME


def get_config_path() -> Path:
    """Get the path to the config file."""
    return get_app_dir() / "config.json"


def get_log_dir() -> Path:
    """Get the log directory."""
    return get_app_dir() / "logs"


def get_log_path() -> Path:
    """Get the path to the current log file."""
    return get_log_dir() / "netbridge-socks.log"


@dataclass
class Config:
    """NetBridge Socks configuration."""
    relay_url: str = DEFAULT_RELAY_URL
    socks_port: int = 1080
    http_port: int = 3128
    auto_connect: bool = True
    show_notifications: bool = True
    log_level: str = "INFO"

    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return {
            "relay_url": self.relay_url,
            "socks_port": self.socks_port,
            "http_port": self.http_port,
            "auto_connect": self.auto_connect,
            "show_notifications": self.show_notifications,
            "log_level": self.log_level,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        """Create config from dictionary."""
        return cls(
            relay_url=data.get("relay_url", DEFAULT_RELAY_URL),
            socks_port=data.get("socks_port", 1080),
            http_port=data.get("http_port", 3128),
            auto_connect=data.get("auto_connect", True),
            show_notifications=data.get("show_notifications", True),
            log_level=data.get("log_level", "INFO"),
        )

    def save(self, path: Optional[Path] = None) -> None:
        """Save configuration to file."""
        config_path = path or get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        """Load configuration from file, or return defaults if not found."""
        config_path = path or get_config_path()
        if config_path.exists():
            try:
                with open(config_path) as f:
                    data = json.load(f)
                return cls.from_dict(data)
            except (json.JSONDecodeError, IOError):
                pass
        return cls()


def ensure_app_dirs() -> None:
    """Create application directories if they don't exist."""
    get_app_dir().mkdir(parents=True, exist_ok=True)
    get_log_dir().mkdir(parents=True, exist_ok=True)
