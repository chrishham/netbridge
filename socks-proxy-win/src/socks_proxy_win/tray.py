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
    # Relay connection is fine but the VDI agent is not reachable, so nothing
    # can actually be tunnelled
    NO_AGENT = "no_agent"


# Status to color mapping
STATUS_COLORS = {
    Status.DISCONNECTED: "#E74C3C",    # Red
    Status.CONNECTING: "#F1C40F",       # Yellow
    Status.CONNECTED: "#2ECC71",        # Green
    Status.AUTH_REQUIRED: "#E67E22",    # Orange
    Status.NO_AGENT: "#9B59B6",         # Purple
}

# Drawn as a ring instead of a filled dot, so the state is still obvious in
# a monochrome tray or to a colour blind user
STATUS_HOLLOW = {Status.NO_AGENT}

# Status to menu label mapping
STATUS_LABELS = {
    Status.DISCONNECTED: "Disconnected",
    Status.CONNECTING: "Connecting...",
    Status.CONNECTED: "Connected",
    Status.AUTH_REQUIRED: "Login Required",
    Status.NO_AGENT: "VDI Unreachable",
}

# Status to tooltip mapping
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
    """Create a simple circle icon with the given color.

    A hollow icon is drawn as a ring so states stay distinguishable without
    relying on colour alone.
    """
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    padding = size // 8
    box = [padding, padding, size - padding, size - padding]
    if hollow:
        draw.ellipse(box, fill=None, outline=color, width=max(2, size // 8))
    else:
        draw.ellipse(box, fill=color, outline=color)

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
            self._icon_cache[status] = create_icon_image(
                STATUS_COLORS[status], hollow=status in STATUS_HOLLOW,
            )

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

    def update_menu(self) -> None:
        """Force menu refresh (e.g., after update becomes available)."""
        if self._icon:
            self._icon.update_menu()

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

        def on_check_connection(icon, item):
            self.app.request_check_connection()

        def get_socks_text(item):
            return f"SOCKS5: 127.0.0.1:{self.app.config.socks_port}"

        def get_http_text(item):
            return f"HTTP: 127.0.0.1:{self.app.config.http_port}"

        def on_change_relay_url(icon, item):
            self.app.request_change_relay_url()

        def on_login(icon, item):
            self.app.request_login()

        def on_view_logs(icon, item):
            self._open_logs()

        def on_check_update(icon, item):
            self.app.request_check_update()

        def get_update_label(item):
            if self.app._available_update:
                return f"Update to v{self.app._available_update.version}"
            return "Check for Updates"

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
                get_relay_text,
                None,
                enabled=False,
            ),
            pystray.MenuItem(
                get_agent_text,
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
                "Check Connection Now",
                on_check_connection,
            ),
            pystray.MenuItem(
                "Change Relay URL",
                on_change_relay_url,
                visible=is_installed,
            ),
            pystray.MenuItem(
                "Login (az login)",
                on_login,
            ),
            pystray.MenuItem(
                "View Logs",
                on_view_logs,
            ),
            pystray.MenuItem(
                get_update_label,
                on_check_update,
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
