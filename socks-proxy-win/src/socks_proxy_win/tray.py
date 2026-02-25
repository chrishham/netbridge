"""
System tray icon and menu for NetBridge Socks.

Provides visual status indication and user interaction through the Windows system tray.
"""

import os
import subprocess
from enum import Enum
from typing import TYPE_CHECKING, Callable, Optional

import pystray
from PIL import Image, ImageDraw

from .config import APP_NAME, APP_VERSION, get_log_path
from .installer import Installer


if TYPE_CHECKING:
    from .app import NetBridgeSocksApp


class Status(Enum):
    """Connection status for the tray icon."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTH_REQUIRED = "auth_required"


# Status to color mapping
STATUS_COLORS = {
    Status.DISCONNECTED: "#E74C3C",    # Red
    Status.CONNECTING: "#F1C40F",       # Yellow
    Status.CONNECTED: "#2ECC71",        # Green
    Status.AUTH_REQUIRED: "#E67E22",    # Orange
}

# Status to tooltip mapping
STATUS_TOOLTIPS = {
    Status.DISCONNECTED: f"{APP_NAME} - Disconnected",
    Status.CONNECTING: f"{APP_NAME} - Connecting...",
    Status.CONNECTED: f"{APP_NAME} - Connected",
    Status.AUTH_REQUIRED: f"{APP_NAME} - Login Required",
}


def create_icon_image(color: str, size: int = 64) -> Image.Image:
    """Create a simple circle icon with the given color."""
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    padding = size // 8
    draw.ellipse(
        [padding, padding, size - padding, size - padding],
        fill=color,
        outline=color,
    )

    return image


class TrayIcon:
    """Manages the system tray icon and context menu."""

    def __init__(self, app: "NetBridgeSocksApp"):
        self.app = app
        self._status = Status.DISCONNECTED
        self._icon: Optional[pystray.Icon] = None

        # Cache generated icons
        self._icon_cache: dict[Status, Image.Image] = {}
        for status in Status:
            self._icon_cache[status] = create_icon_image(STATUS_COLORS[status])

    @property
    def status(self) -> Status:
        """Get the current status."""
        return self._status

    def set_status(self, status: Status) -> None:
        """Update the icon and tooltip based on status."""
        self._status = status
        if self._icon:
            self._icon.icon = self._icon_cache[status]
            self._icon.title = STATUS_TOOLTIPS[status]

    def show_notification(self, title: str, message: str) -> None:
        """Show a Windows notification."""
        if self._icon and self.app.config.show_notifications:
            try:
                self._icon.notify(message, title)
            except Exception:
                pass

    def _create_menu(self) -> pystray.Menu:
        """Create the context menu."""

        def get_status_text(item):
            status_map = {
                Status.DISCONNECTED: "Disconnected",
                Status.CONNECTING: "Connecting...",
                Status.CONNECTED: "Connected",
                Status.AUTH_REQUIRED: "Login Required",
            }
            return f"Status: {status_map[self._status]}"

        def get_socks_text(item):
            return f"SOCKS5: 127.0.0.1:{self.app.config.socks_port}"

        def get_http_text(item):
            return f"HTTP: 127.0.0.1:{self.app.config.http_port}"

        def on_login(icon, item):
            self.app.request_login()

        def on_view_logs(icon, item):
            self._open_logs()

        def on_install(icon, item):
            self.app.request_install()

        def on_uninstall(icon, item):
            self.app.request_uninstall()

        def on_exit(icon, item):
            self.app.request_exit()

        def is_installed(item):
            return Installer.is_installed()

        def is_not_installed(item):
            return not Installer.is_installed()

        return pystray.Menu(
            pystray.MenuItem(
                f"{APP_NAME} v{APP_VERSION}",
                None,
                enabled=False,
            ),
            pystray.MenuItem(
                get_status_text,
                None,
                enabled=False,
            ),
            pystray.MenuItem(
                get_socks_text,
                None,
                enabled=False,
            ),
            pystray.MenuItem(
                get_http_text,
                None,
                enabled=False,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Login (az login)",
                on_login,
            ),
            pystray.MenuItem(
                "View Logs",
                on_view_logs,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Install",
                on_install,
                visible=is_not_installed,
            ),
            pystray.MenuItem(
                "Uninstall",
                on_uninstall,
                visible=is_installed,
            ),
            pystray.MenuItem(
                "Exit",
                on_exit,
            ),
        )

    def _open_logs(self) -> None:
        """Open the log file in the default text editor."""
        log_path = get_log_path()
        if log_path.exists():
            os.startfile(log_path)
        else:
            self.show_notification("No Logs", "Log file not found")

    def run(self, setup_callback: Optional[Callable] = None) -> None:
        """Start the tray icon (blocks until stopped)."""
        self._icon = pystray.Icon(
            name=APP_NAME,
            icon=self._icon_cache[self._status],
            title=STATUS_TOOLTIPS[self._status],
            menu=self._create_menu(),
        )

        self._icon.run(setup=setup_callback)

    def stop(self) -> None:
        """Stop the tray icon."""
        if self._icon:
            self._icon.stop()
