"""System tray icon for NetBridge Socks (cross-platform)."""

import logging
import os
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

import pystray
from PIL import Image, ImageDraw

from . import __version__

logger = logging.getLogger(__name__)

APP_NAME = "NetBridge Socks"


class Status(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTH_REQUIRED = "auth_required"
    # Relay connection is fine but the VDI agent is not reachable, so nothing
    # can actually be tunnelled
    NO_AGENT = "no_agent"


STATUS_COLORS = {
    Status.DISCONNECTED: "#E74C3C",     # Red
    Status.CONNECTING: "#F1C40F",       # Yellow
    Status.CONNECTED: "#2ECC71",        # Green
    Status.AUTH_REQUIRED: "#E67E22",    # Orange
    Status.NO_AGENT: "#9B59B6",         # Purple
}

# Drawn as a ring instead of a filled dot, so the state is still obvious in
# a monochrome tray or to a colour blind user
STATUS_HOLLOW = {Status.NO_AGENT}

STATUS_LABELS = {
    Status.DISCONNECTED: "Disconnected",
    Status.CONNECTING: "Connecting...",
    Status.CONNECTED: "Connected",
    Status.AUTH_REQUIRED: "Login Required",
    Status.NO_AGENT: "VDI Unreachable",
}

STATUS_TOOLTIPS = {
    Status.DISCONNECTED: f"{APP_NAME} - Disconnected",
    Status.CONNECTING: f"{APP_NAME} - Connecting...",
    Status.CONNECTED: f"{APP_NAME} - Connected (tunnel working)",
    Status.AUTH_REQUIRED: f"{APP_NAME} - Login Required",
    Status.NO_AGENT: f"{APP_NAME} - Relay OK, VDI agent unreachable",
}


def create_icon_image(
    color: str, size: int = 64, hollow: bool = False,
) -> Image.Image:
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    padding = size // 8
    box = [padding, padding, size - padding, size - padding]
    if hollow:
        draw.ellipse(box, fill=None, outline=color, width=max(2, size // 8))
    else:
        draw.ellipse(box, fill=color, outline=color)
    return image


def get_log_path() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "netbridge-socks.log"
    state_dir = os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))
    return Path(state_dir) / "netbridge-socks" / "netbridge-socks.log"


def _open_file(path: str) -> None:
    if sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def _open_login_terminal() -> None:
    try:
        if sys.platform == "darwin":
            subprocess.Popen([
                "osascript", "-e",
                'tell application "Terminal" to do script "az login"',
            ])
        else:
            for cmd in [
                ["gnome-terminal", "--", "bash", "-c",
                 "az login; read -rp 'Press Enter to close...'"],
                ["konsole", "-e", "bash", "-c",
                 "az login; read -rp 'Press Enter to close...'"],
                ["xfce4-terminal", "-e",
                 "bash -c 'az login; read -rp Press_Enter...'"],
                ["xterm", "-e",
                 "bash -c 'az login; read -rp Press_Enter...'"],
            ]:
                try:
                    subprocess.Popen(cmd)
                    return
                except FileNotFoundError:
                    continue
            logger.warning("No terminal emulator found for az login")
    except Exception as e:
        logger.error(f"Failed to open login terminal: {e}")


class TrayIcon:

    def __init__(
        self,
        host: str = "127.0.0.1",
        socks_port: int = 1080,
        http_port: int | None = 3128,
        log_path: Path | None = None,
        show_notifications: bool = True,
        on_reconnect: Optional[Callable] = None,
        on_change_relay: Optional[Callable] = None,
        on_check_connection: Optional[Callable] = None,
    ):
        self._host = host
        self._socks_port = socks_port
        self._http_port = http_port
        self._log_path = log_path
        self._show_notifications = show_notifications
        self._on_reconnect = on_reconnect
        self._on_change_relay = on_change_relay
        self._on_check_connection = on_check_connection
        self._status = Status.DISCONNECTED
        self._icon: Optional[pystray.Icon] = None

        self._icon_cache: dict[Status, Image.Image] = {}
        for status in Status:
            self._icon_cache[status] = create_icon_image(
                STATUS_COLORS[status], hollow=status in STATUS_HOLLOW,
            )

    @property
    def status(self) -> Status:
        return self._status

    def set_status(self, status: Status) -> None:
        old = self._status
        self._status = status
        if self._icon:
            self._icon.icon = self._icon_cache[status]
            self._icon.title = STATUS_TOOLTIPS[status]

            if old != status:
                if status == Status.CONNECTED:
                    if old == Status.NO_AGENT:
                        self._notify("Tunnel Restored",
                                     "VDI agent is reachable again")
                    else:
                        self._notify("Connected", "Tunnel is working end to end")
                elif status == Status.NO_AGENT:
                    self._notify(
                        "VDI Unreachable",
                        "Connected to the relay, but no bridge agent is "
                        "available. Check that the agent is running on your VDI.",
                    )
                elif status == Status.DISCONNECTED and old in (
                    Status.CONNECTED, Status.NO_AGENT,
                ):
                    self._notify("Disconnected",
                                 "Connection lost, reconnecting...")
                elif status == Status.AUTH_REQUIRED:
                    self._notify("Login Required",
                                 "Authentication expired - run 'az login'")

    def _notify(self, title: str, message: str) -> None:
        if self._icon and self._show_notifications:
            try:
                self._icon.notify(message, title)
            except Exception:
                pass

    def _create_menu(self) -> pystray.Menu:
        def get_status_text(item):
            return f"Status: {STATUS_LABELS[self._status]}"

        def get_relay_text(item):
            if self._status in (Status.CONNECTED, Status.NO_AGENT):
                return "  Relay: connected"
            if self._status == Status.CONNECTING:
                return "  Relay: connecting..."
            if self._status == Status.AUTH_REQUIRED:
                return "  Relay: login required"
            return "  Relay: disconnected"

        def get_agent_text(item):
            if self._status == Status.CONNECTED:
                return "  VDI agent: reachable"
            if self._status == Status.NO_AGENT:
                return "  VDI agent: NOT reachable"
            return "  VDI agent: unknown"

        def get_socks_text(item):
            return f"SOCKS5: {self._host}:{self._socks_port}"

        def get_http_text(item):
            return f"HTTP: {self._host}:{self._http_port}"

        items = [
            pystray.MenuItem(
                f"{APP_NAME} v{__version__}", None, enabled=False,
            ),
            pystray.MenuItem(get_status_text, None, enabled=False),
            pystray.MenuItem(get_relay_text, None, enabled=False),
            pystray.MenuItem(get_agent_text, None, enabled=False),
            pystray.MenuItem(get_socks_text, None, enabled=False),
        ]

        if self._http_port is not None:
            items.append(
                pystray.MenuItem(get_http_text, None, enabled=False),
            )

        items.append(pystray.Menu.SEPARATOR)

        if self._on_check_connection:
            items.append(pystray.MenuItem(
                "Check Connection Now",
                lambda icon, item: self._on_check_connection(),
            ))

        if self._on_reconnect:
            items.append(pystray.MenuItem(
                "Reconnect",
                lambda icon, item: self._on_reconnect(),
            ))

        if self._on_change_relay:
            items.append(pystray.MenuItem(
                "Change Relay URL",
                lambda icon, item: self._on_change_relay(),
            ))

        items.append(pystray.MenuItem(
            "Login (az login)",
            lambda icon, item: _open_login_terminal(),
        ))

        if self._log_path:
            def on_view_logs(icon, item):
                if self._log_path.exists():
                    _open_file(str(self._log_path))

            items.append(pystray.MenuItem("View Logs", on_view_logs))

        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Exit", lambda icon, item: self.stop()))

        return pystray.Menu(*items)

    def run(self, setup_callback: Optional[Callable] = None) -> None:
        self._icon = pystray.Icon(
            name=APP_NAME,
            icon=self._icon_cache[self._status],
            title=STATUS_TOOLTIPS[self._status],
            menu=self._create_menu(),
        )

        def _setup(icon):
            icon.visible = True
            if setup_callback:
                setup_callback(icon)

        self._icon.run(setup=_setup)

    def stop(self) -> None:
        if self._icon:
            self._icon.stop()
