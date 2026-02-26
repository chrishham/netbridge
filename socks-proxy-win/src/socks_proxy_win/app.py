"""
NetBridge Socks Application - coordinates proxy servers and tray.

This is the main application class that ties together:
- The system tray UI (runs in main thread)
- The async proxy servers (runs in background thread via socks_proxy.run_server)
- Configuration management
- Status updates and notifications
"""

import asyncio
import ctypes
import logging
import os
import subprocess
import sys
import threading
from typing import Optional

from .config import Config, ensure_app_dirs, get_log_path, APP_NAME, APP_VERSION
from .tray import TrayIcon, Status

logger = logging.getLogger(__name__)


def setup_logging(config: Config, console: bool = False) -> None:
    """Set up logging to file and optionally console."""
    from logging.handlers import TimedRotatingFileHandler

    ensure_app_dirs()
    log_path = get_log_path()

    level = getattr(logging, config.log_level.upper(), logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()

    file_handler = TimedRotatingFileHandler(
        log_path,
        when="D",
        interval=1,
        backupCount=2,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)


class NetBridgeSocksApp:
    """Main application - coordinates proxy servers and tray."""

    def __init__(self):
        self.config = Config.load()

        setup_logging(self.config)

        self.tray: Optional[TrayIcon] = None
        self._status = Status.DISCONNECTED

        # Threading coordination
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_thread: Optional[threading.Thread] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._server_task: Optional[asyncio.Task] = None

        # Pending requests from tray menu (thread-safe)
        self._pending_exit = threading.Event()

        logger.info(f"{APP_NAME} v{APP_VERSION} starting")

    @property
    def status(self) -> Status:
        """Get current connection status."""
        return self._status

    def set_status(self, status: Status, notify: bool = True) -> None:
        """Update connection status."""
        old_status = self._status
        self._status = status

        if self.tray:
            self.tray.set_status(status)

            if notify and old_status != status:
                if status == Status.CONNECTED:
                    self.tray.show_notification("Connected", "Connected to relay server")
                elif status == Status.DISCONNECTED and old_status == Status.CONNECTED:
                    self.tray.show_notification("Disconnected", "Connection lost, reconnecting...")
                elif status == Status.AUTH_REQUIRED:
                    self.tray.show_notification("Login Required", "Authentication expired - click to login")

        logger.info(f"Status changed: {old_status.value} -> {status.value}")

    # --- Menu action handlers (called from tray thread) ---

    def request_login(self) -> None:
        """Open az login in a terminal (from tray menu)."""
        logger.info("Opening az login...")
        try:
            subprocess.Popen(
                ["powershell", "-NoExit", "-Command", "az login"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        except Exception as e:
            logger.error(f"Failed to open az login: {e}")
            if self.tray:
                self.tray.show_notification("Error", f"Could not open terminal: {e}")

    def request_change_relay_url(self) -> None:
        """Prompt for a new relay URL, save config, and restart (from tray menu)."""
        from .dialogs import prompt_relay_url
        from .installer import get_exe_path

        logger.info("Change relay URL requested")

        url = prompt_relay_url(self.config.relay_url)
        if url is None or url == self.config.relay_url:
            logger.info("Relay URL change cancelled or unchanged")
            return

        self.config.relay_url = url
        self.config.save()
        logger.info(f"Relay URL changed to: {url}")

        # Relaunch and exit cleanly so file handles are released
        target_exe = get_exe_path()
        logger.info(f"Relaunching: {target_exe} --no-install")
        try:
            subprocess.Popen(
                [str(target_exe), "--no-install"],
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
            )
        except OSError:
            logger.exception("Failed to launch new process")
            return

        self._pending_exit.set()
        if self._async_loop and self._stop_event:
            self._async_loop.call_soon_threadsafe(self._stop_event.set)

        if self.tray:
            self.tray.stop()

    def request_install(self) -> None:
        """Request install (from tray menu)."""
        from .installer import Installer
        from .dialogs import prompt_relay_url

        logger.info("Install requested")

        url = prompt_relay_url(self.config.relay_url)
        if url is None:
            return

        self._pending_exit.set()

        if self._async_loop and self._stop_event:
            self._async_loop.call_soon_threadsafe(self._stop_event.set)

        success = Installer.install_fresh(url)

        if self.tray:
            self.tray.stop()

        if success:
            os._exit(0)

    def request_uninstall(self) -> None:
        """Request uninstall (from tray menu)."""
        from .installer import Installer

        result = ctypes.windll.user32.MessageBoxW(
            0,
            f"Are you sure you want to uninstall {APP_NAME}?\n\nThis will remove the application and its data.",
            f"Uninstall {APP_NAME}",
            0x04 | 0x30,
        )
        if result != 6:
            return

        logger.info("Uninstall requested")
        Installer.uninstall(confirm=False)
        self.request_exit()

    def request_exit(self) -> None:
        """Request application exit (from tray menu)."""
        logger.info("Exit requested")
        self._pending_exit.set()

        if self._async_loop and self._stop_event:
            self._async_loop.call_soon_threadsafe(self._stop_event.set)

        if self.tray:
            self.tray.stop()

    # --- Async proxy loop ---

    async def _run_proxy(self) -> None:
        """Run the proxy server connection loop."""
        from socks_proxy.auth import get_arm_token, check_az_login
        from socks_proxy.__main__ import run_server

        self.set_status(Status.CONNECTING)

        try:
            # Authenticate
            logger.info("Authenticating with Azure CLI...")
            logged_in, message = check_az_login()
            if not logged_in:
                logger.error(f"Authentication failed: {message}")
                self.set_status(Status.AUTH_REQUIRED)
                return

            logger.info(message)
            auth_token = get_arm_token()
            token_refresh = get_arm_token

            self._stop_event = asyncio.Event()

            def on_status_change(connected: bool, auth_required: bool = False):
                if auth_required:
                    self.set_status(Status.AUTH_REQUIRED)
                elif connected:
                    self.set_status(Status.CONNECTED)
                else:
                    self.set_status(Status.CONNECTING)

            await run_server(
                host="127.0.0.1",
                socks_port=self.config.socks_port,
                http_port=self.config.http_port,
                relay_url=self.config.relay_url,
                auth_token=auth_token,
                token_refresh_callback=token_refresh,
                stop_event=self._stop_event,
                on_status_change=on_status_change,
            )
        except Exception as e:
            logger.error(f"Proxy error: {e}")
        finally:
            self.set_status(Status.DISCONNECTED)

    async def _async_main(self) -> None:
        """Main async loop running in background thread."""
        self._stop_event = asyncio.Event()

        if self.config.auto_connect:
            self._server_task = asyncio.create_task(self._run_proxy())

        await self._stop_event.wait()

        if self._server_task and not self._server_task.done():
            self._server_task.cancel()
            try:
                await self._server_task
            except asyncio.CancelledError:
                pass

    def _run_async_loop(self) -> None:
        """Run the async event loop in a background thread."""
        self._async_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._async_loop)

        try:
            self._async_loop.run_until_complete(self._async_main())
        finally:
            self._async_loop.close()

    # --- Main entry point ---

    def run(self) -> int:
        """Run the application (tray mode)."""
        logger.info("Running in tray mode")

        self.tray = TrayIcon(self)

        self._async_thread = threading.Thread(target=self._run_async_loop, daemon=True)
        self._async_thread.start()

        try:
            self.tray.run()
        except Exception as e:
            logger.error(f"Tray error: {e}")
            return 1

        if self._async_thread:
            self._async_thread.join(timeout=5.0)

        logger.info("Application exited")
        return 0
