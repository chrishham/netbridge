"""
System tray icon and menu for NetBridge.

Provides visual status indication and user interaction through the Windows system tray.
"""

import os
import subprocess
import sys
import threading
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except Exception as e:
    # Catch ANY exception, not just ImportError
    TRAY_AVAILABLE = False
    TRAY_IMPORT_ERROR = str(e)

from .config import APP_NAME, APP_VERSION, get_log_path
from .installer import Installer


if TYPE_CHECKING:
    from .app import NetBridgeApp


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


def create_icon_image(color: str, size: int = 64) -> "Image.Image":
    """Create a simple circle icon with the given color.

    Args:
        color: Hex color string (e.g., "#2ECC71")
        size: Icon size in pixels

    Returns:
        PIL Image object
    """
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Draw filled circle with slight padding
    padding = size // 8
    draw.ellipse(
        [padding, padding, size - padding, size - padding],
        fill=color,
        outline=color,
    )

    return image


def load_icon_from_file(path: Path) -> Optional["Image.Image"]:
    """Load an icon from file if it exists."""
    if path.exists():
        try:
            return Image.open(path)
        except Exception:
            pass
    return None


class TrayIcon:
    """Manages the system tray icon and context menu."""

    def __init__(self, app: "NetBridgeApp"):
        """Initialize the tray icon.

        Args:
            app: The main NetBridge application instance
        """
        if not TRAY_AVAILABLE:
            raise RuntimeError("pystray and Pillow are required for tray mode")

        self.app = app
        self._status = Status.DISCONNECTED
        self._icon: Optional[pystray.Icon] = None
        self._session_info: str = ""

        # Cache generated icons
        self._icon_cache: dict[Status, Image.Image] = {}
        for status in Status:
            self._icon_cache[status] = create_icon_image(STATUS_COLORS[status])

    @property
    def status(self) -> Status:
        """Get the current status."""
        return self._status

    def set_status(self, status: Status) -> None:
        """Update the icon and tooltip based on status.

        Args:
            status: New connection status
        """
        self._status = status
        if self._icon:
            self._icon.icon = self._icon_cache[status]
            self._icon.title = STATUS_TOOLTIPS[status]

    def set_session_info(self, info: str) -> None:
        """Set the session info displayed in menu.

        Args:
            info: Session info string (e.g., "PC01:E40274")
        """
        self._session_info = info
        # Update menu to show new session info
        if self._icon:
            self._icon.update_menu()

    def show_notification(self, title: str, message: str) -> None:
        """Show a Windows notification.

        Args:
            title: Notification title
            message: Notification message
        """
        if self._icon and self.app.config.show_notifications:
            try:
                self._icon.notify(message, title)
            except Exception:
                pass  # Notifications may fail silently

    def _create_menu(self) -> "pystray.Menu":
        """Create the context menu."""

        def get_status_text(item):
            """Get current status text for menu."""
            status_map = {
                Status.DISCONNECTED: "Disconnected",
                Status.CONNECTING: "Connecting...",
                Status.CONNECTED: "Connected",
                Status.AUTH_REQUIRED: "Login Required",
            }
            return f"Status: {status_map[self._status]}"

        def get_session_text(item):
            """Get session info for menu."""
            return f"Session: {self._session_info}" if self._session_info else "Session: Not connected"

        def is_connected(item):
            """Check if currently connected."""
            return self._status == Status.CONNECTED

        def is_disconnected(item):
            """Check if currently disconnected."""
            return self._status in (Status.DISCONNECTED, Status.AUTH_REQUIRED)

        # Menu item callbacks
        def on_connect(icon, item):
            self.app.request_connect()

        def on_disconnect(icon, item):
            self.app.request_disconnect()

        def on_login(icon, item):
            self.app.request_login()

        def on_change_relay_url(icon, item):
            self.app.request_change_relay_url()

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
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                get_status_text,
                None,
                enabled=False,
            ),
            pystray.MenuItem(
                get_session_text,
                None,
                enabled=False,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Connect",
                on_connect,
                visible=is_disconnected,
            ),
            pystray.MenuItem(
                "Disconnect",
                on_disconnect,
                visible=is_connected,
            ),
            pystray.MenuItem(
                "Login (az login)",
                on_login,
            ),
            pystray.MenuItem(
                "Change Relay URL",
                on_change_relay_url,
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
            if sys.platform == "win32":
                os.startfile(log_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", log_path])
            else:
                subprocess.run(["xdg-open", log_path])
        else:
            self.show_notification("No Logs", "Log file not found")

    def run(self, setup_callback: Optional[Callable] = None) -> None:
        """Start the tray icon (blocks until stopped).

        Args:
            setup_callback: Optional callback to run after icon is ready
        """
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
