"""
NetBridge Application - coordinates agent and tray.

This is the main application class that ties together:
- The system tray UI (runs in main thread)
- The async agent core (runs in background thread)
- Configuration management
- Status updates and notifications
"""

import asyncio
import logging
import os
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import Config, ensure_app_dirs, get_log_path, APP_NAME, APP_VERSION
from .tray import TrayIcon, Status, TRAY_AVAILABLE

# Configure logging
logger = logging.getLogger(__name__)


def setup_logging(config: Config, console: bool = False) -> None:
    """Set up logging to file and optionally console.

    Args:
        config: Application configuration
        console: If True, also log to console
    """
    from logging.handlers import TimedRotatingFileHandler

    ensure_app_dirs()
    log_path = get_log_path()

    # Parse log level
    level = getattr(logging, config.log_level.upper(), logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Set up root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Time-based rotating file handler: rotate daily, keep 2 days of logs
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


class NetBridgeApp:
    """Main application - coordinates agent and tray."""

    def __init__(self, console: bool = False):
        """Initialize the application.

        Args:
            console: If True, run in console mode (no tray, log to stdout)
        """
        self.console_mode = console
        self.config = Config.load()

        # Set up logging
        setup_logging(self.config, console=console)

        # Core components
        self.tray: Optional[TrayIcon] = None
        self._status = Status.DISCONNECTED

        # Threading coordination
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_thread: Optional[threading.Thread] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._agent_task: Optional[asyncio.Task] = None

        # Pending requests from tray menu (thread-safe)
        self._pending_connect = threading.Event()
        self._pending_disconnect = threading.Event()
        self._pending_exit = threading.Event()

        logger.info(f"{APP_NAME} v{APP_VERSION} starting")

    @property
    def status(self) -> Status:
        """Get current connection status."""
        return self._status

    def set_status(self, status: Status, notify: bool = True) -> None:
        """Update connection status.

        Args:
            status: New status
            notify: If True, show notification on significant changes
        """
        old_status = self._status
        self._status = status

        # Update tray icon
        if self.tray:
            self.tray.set_status(status)

            # Show notifications on significant changes
            if notify and old_status != status:
                if status == Status.CONNECTED:
                    self.tray.show_notification("Connected", "Connected to relay server")
                elif status == Status.DISCONNECTED and old_status == Status.CONNECTED:
                    self.tray.show_notification("Disconnected", "Connection lost, reconnecting...")
                elif status == Status.AUTH_REQUIRED:
                    self.tray.show_notification("Login Required", "Authentication expired - click to login")

        logger.info(f"Status changed: {old_status.value} -> {status.value}")

    def set_session_info(self, info: str) -> None:
        """Set session info displayed in tray menu.

        Args:
            info: Session info string
        """
        if self.tray:
            self.tray.set_session_info(info)

    # --- Menu action handlers (called from tray thread) ---

    def request_connect(self) -> None:
        """Request connection (from tray menu)."""
        self._pending_connect.set()
        if self._async_loop:
            self._async_loop.call_soon_threadsafe(self._check_pending_requests)

    def request_disconnect(self) -> None:
        """Request disconnection (from tray menu)."""
        self._pending_disconnect.set()
        if self._async_loop:
            self._async_loop.call_soon_threadsafe(self._check_pending_requests)

    def request_login(self) -> None:
        """Open az login in a terminal (from tray menu)."""
        logger.info("Opening az login...")
        try:
            if sys.platform == "win32":
                # Open PowerShell with az login
                subprocess.Popen(
                    ["powershell", "-NoExit", "-Command", "az login"],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                )
            else:
                # For other platforms, try common terminal emulators
                subprocess.Popen(["gnome-terminal", "--", "az", "login"])
        except Exception as e:
            logger.error(f"Failed to open az login: {e}")
            if self.tray:
                self.tray.show_notification("Error", f"Could not open terminal: {e}")

    def request_change_relay_url(self) -> None:
        """Prompt for a new relay URL, save config, and restart (from tray menu)."""
        if sys.platform != "win32":
            return

        logger.info("Change relay URL requested")

        from .dialogs import prompt_relay_url

        url = prompt_relay_url(self.config.relay_url)
        if url is None or url == self.config.relay_url:
            logger.info("Relay URL change cancelled or unchanged")
            return

        # Save new URL
        self.config.relay_url = url
        self.config.save()
        logger.info(f"Relay URL changed to: {url}")

        # Restart: launch new instance with --no-install, then exit cleanly.
        # We avoid os._exit() because it skips Python cleanup — file handles
        # (including the log file) may not be released before the child opens
        # them, causing the child to crash in setup_logging() with no visible
        # error.  Instead we let pystray's stop() unwind the message loop so
        # _run_tray() returns normally and the process exits via sys.exit().
        from .installer import get_exe_path

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

        # Signal async loop to stop, then let pystray unwind cleanly
        self._pending_exit.set()
        if self._async_loop and self._stop_event:
            self._async_loop.call_soon_threadsafe(self._stop_event.set)

        if self.tray:
            self.tray.stop()

    def request_install(self) -> None:
        """Request install (from tray menu)."""
        from .installer import Installer

        logger.info("Install requested")

        # Prompt for relay URL before installing
        if sys.platform == "win32":
            from .dialogs import prompt_relay_url
            url = prompt_relay_url(self.config.relay_url)
            if url is None:
                return  # User cancelled
        else:
            url = self.config.relay_url

        # First stop this instance, then install (which launches the new one)
        self._pending_exit.set()

        # Signal async loop to stop
        if self._async_loop and self._stop_event:
            self._async_loop.call_soon_threadsafe(self._stop_event.set)

        # Do the install (this launches the installed version)
        success = Installer.install_fresh(url)

        # Force exit - stop tray and terminate
        if self.tray:
            self.tray.stop()

        if success:
            # Force process exit after a short delay to let tray cleanup
            import os
            os._exit(0)

    def request_uninstall(self) -> None:
        """Request uninstall (from tray menu)."""
        from .installer import Installer

        # Confirm with user
        if sys.platform == "win32":
            import ctypes
            result = ctypes.windll.user32.MessageBoxW(
                0,
                f"Are you sure you want to uninstall {APP_NAME}?\n\nThis will remove the application and its data.",
                f"Uninstall {APP_NAME}",
                0x04 | 0x30,  # MB_YESNO | MB_ICONWARNING
            )
            if result != 6:  # IDYES
                return

        logger.info("Uninstall requested")

        # Perform uninstall first (this schedules file deletion via batch script)
        Installer.uninstall(confirm=False)

        # Then exit the app
        self.request_exit()

    def request_exit(self) -> None:
        """Request application exit (from tray menu)."""
        logger.info("Exit requested")
        self._pending_exit.set()

        # Signal async loop to stop
        if self._async_loop and self._stop_event:
            self._async_loop.call_soon_threadsafe(self._stop_event.set)

        # Stop tray
        if self.tray:
            self.tray.stop()

    # --- Async agent loop ---

    def _check_pending_requests(self) -> None:
        """Check for pending requests from tray menu (called in async loop)."""
        if self._pending_connect.is_set():
            self._pending_connect.clear()
            if self._agent_task is None or self._agent_task.done():
                self._agent_task = asyncio.create_task(self._run_agent())

        if self._pending_disconnect.is_set():
            self._pending_disconnect.clear()
            if self._agent_task and not self._agent_task.done():
                if self._stop_event:
                    self._stop_event.set()

    async def _run_agent(self) -> None:
        """Run the agent connection loop."""
        from .agent import run_agent

        self.set_status(Status.CONNECTING)

        try:
            # Create new stop event for this connection
            self._stop_event = asyncio.Event()

            await run_agent(
                relay_url=self.config.relay_url,
                stop_event=self._stop_event,
                on_status_change=self._on_agent_status,
                on_session_info=self.set_session_info,
            )
        except Exception as e:
            logger.error(f"Agent error: {e}")
        finally:
            self.set_status(Status.DISCONNECTED)

    def _on_agent_status(self, connected: bool, auth_required: bool = False) -> None:
        """Callback from agent when status changes.

        Args:
            connected: True if connected to relay
            auth_required: True if authentication is required
        """
        if auth_required:
            self.set_status(Status.AUTH_REQUIRED)
        elif connected:
            self.set_status(Status.CONNECTED)
        else:
            self.set_status(Status.CONNECTING if self._agent_task else Status.DISCONNECTED)

    async def _async_main(self) -> None:
        """Main async loop running in background thread."""
        self._stop_event = asyncio.Event()

        # Auto-connect if configured
        if self.config.auto_connect:
            self._agent_task = asyncio.create_task(self._run_agent())

        # Wait for exit request
        await self._stop_event.wait()

        # Cancel agent task if running
        if self._agent_task and not self._agent_task.done():
            self._agent_task.cancel()
            try:
                await self._agent_task
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
        """Run the application.

        Returns:
            Exit code (0 for success)
        """
        if self.console_mode:
            return self._run_console()
        else:
            return self._run_tray()

    def _run_console(self) -> int:
        """Run in console mode (no tray, for debugging)."""
        logger.info("Running in console mode")
        print(f"[*] {APP_NAME} v{APP_VERSION} - Console Mode")
        print(f"[*] Relay: {self.config.relay_url}")
        print("[*] Press Ctrl+C to exit")

        try:
            asyncio.run(self._async_main())
        except KeyboardInterrupt:
            print("\n[*] Interrupted")

        return 0

    def _run_tray(self) -> int:
        """Run in tray mode (normal operation)."""
        if not TRAY_AVAILABLE:
            try:
                from . import tray
                error_msg = getattr(tray, 'TRAY_IMPORT_ERROR', 'pystray/Pillow not installed')
            except Exception:
                error_msg = "pystray/Pillow not installed"
            logger.error(f"Tray not available: {error_msg}")
            print(f"[!] Error: {error_msg}")
            print("[!] Run with --console for console mode")
            return 1

        logger.info("Running in tray mode")

        # Create tray icon
        self.tray = TrayIcon(self)

        # Start async loop in background thread
        self._async_thread = threading.Thread(target=self._run_async_loop, daemon=True)
        self._async_thread.start()

        # Run tray icon (blocks until stopped)
        try:
            self.tray.run()
        except Exception as e:
            logger.error(f"Tray error: {e}")
            return 1

        # Wait for async thread to finish
        if self._async_thread:
            self._async_thread.join(timeout=5.0)

        logger.info("Application exited")
        return 0
