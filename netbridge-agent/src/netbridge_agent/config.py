"""
Configuration management for NetBridge.

Handles loading/saving configuration from JSON file in %LOCALAPPDATA%/NetBridge/.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlunparse


# Default relay hostname (each component appends its own path)
DEFAULT_RELAY_URL = "your-relay-host.example.com"


def normalize_relay_url(relay: str, path: str = "/ws") -> str:
    """Normalize a relay hostname or URL to a full WebSocket URL.

    Accepts: bare hostname, hostname with scheme, or full URL with path.
    """
    relay = relay.strip().rstrip("/")
    # Already a full URL with path
    if relay.startswith(("ws://", "wss://")) and "/" in relay.split("//", 1)[1]:
        return relay
    # Has scheme but no path
    if relay.startswith(("ws://", "wss://")):
        return relay + path
    # Bare hostname
    return f"wss://{relay}{path}"


# App directories
APP_NAME = "NetBridge"

# Get version from __init__.py (single source of truth, works with PyInstaller)
from . import __version__ as APP_VERSION


def get_app_dir() -> Path:
    """Get the application data directory (%LOCALAPPDATA%/NetBridge)."""
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
    return get_log_dir() / "netbridge.log"


@dataclass
class ProxyConfig:
    """Proxy configuration."""
    http: Optional[str] = None
    https: Optional[str] = None


@dataclass
class Config:
    """NetBridge configuration."""
    relay_url: str = DEFAULT_RELAY_URL
    auto_connect: bool = True
    show_notifications: bool = True
    log_level: str = "INFO"
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    allow_private_destinations: bool = True
    allowed_destinations: list[str] = field(default_factory=list)
    denied_destinations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        d = {
            "relay_url": self.relay_url,
            "auto_connect": self.auto_connect,
            "show_notifications": self.show_notifications,
            "log_level": self.log_level,
            "proxy": {
                "http": self.proxy.http,
                "https": self.proxy.https,
            },
        }
        d["allow_private_destinations"] = self.allow_private_destinations
        if self.allowed_destinations:
            d["allowed_destinations"] = self.allowed_destinations
        if self.denied_destinations:
            d["denied_destinations"] = self.denied_destinations
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        """Create config from dictionary."""
        proxy_data = data.get("proxy", {})
        proxy = ProxyConfig(
            http=proxy_data.get("http"),
            https=proxy_data.get("https"),
        )
        return cls(
            relay_url=data.get("relay_url", DEFAULT_RELAY_URL),
            auto_connect=data.get("auto_connect", True),
            show_notifications=data.get("show_notifications", True),
            log_level=data.get("log_level", "INFO"),
            proxy=proxy,
            allow_private_destinations=data.get("allow_private_destinations", True),
            allowed_destinations=data.get("allowed_destinations", []),
            denied_destinations=data.get("denied_destinations", []),
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
                # Return defaults if config is corrupted
                pass
        return cls()


def redact_proxy_url(url: str) -> str:
    """Redact password from a proxy URL for safe logging.

    Returns the original URL unchanged if no password is present.
    """
    try:
        parsed = urlparse(url)
        if parsed.password:
            # Rebuild with redacted password
            netloc = f"{parsed.username}:***@{parsed.hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urlunparse(parsed._replace(netloc=netloc))
    except Exception:
        pass
    return url


def ensure_app_dirs() -> None:
    """Create application directories if they don't exist."""
    get_app_dir().mkdir(parents=True, exist_ok=True)
    get_log_dir().mkdir(parents=True, exist_ok=True)
