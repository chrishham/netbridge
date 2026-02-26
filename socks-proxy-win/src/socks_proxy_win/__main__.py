"""
NetBridge Socks - Windows Tray Application

Entry point for the Windows executable. Handles auto-install, tray mode,
and uninstall. The actual proxy logic lives in the socks_proxy package.
"""

import argparse
import ctypes
import logging
import sys

from .config import APP_NAME, APP_VERSION, ensure_app_dirs, get_log_path


def hide_console_window() -> None:
    """Hide the console window on Windows."""
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


def setup_early_logging() -> None:
    """Set up basic file logging before app initialization."""
    from logging.handlers import TimedRotatingFileHandler

    try:
        ensure_app_dirs()
        log_path = get_log_path()

        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)

        if not root_logger.handlers:
            file_handler = TimedRotatingFileHandler(
                log_path,
                when="D",
                interval=1,
                backupCount=2,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
    except Exception:
        pass


def main():
    """Entry point for the Windows tray application."""
    # Hide the console window for normal tray operation, but skip for
    # CLI flags that need stdout (--version, --import-check).
    if "--version" not in sys.argv and "--import-check" not in sys.argv:
        hide_console_window()

    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - Windows tray for SOCKS5 & HTTP proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
The tray icon shows connection status:
  Green   - Connected
  Yellow  - Connecting
  Red     - Disconnected
  Orange  - Login required (run 'az login')
        """,
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove from system",
    )
    mode_group.add_argument(
        "--no-install",
        action="store_true",
        help="Run tray without installing (standalone mode)",
    )
    mode_group.add_argument(
        "--import-check",
        action="store_true",
        help="Import all modules and exit (for CI testing)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} v{APP_VERSION}",
    )

    args = parser.parse_args()

    # Handle import check (CI smoke test for bundled modules)
    if args.import_check:
        from . import app, config, dialogs, installer, tray  # noqa: F401
        from socks_proxy import socks5, http_proxy, tunnel, auth  # noqa: F401
        print(f"{APP_NAME} v{APP_VERSION}: all modules imported OK")
        dialogs.verify_bindings()
        print("ctypes bindings verified OK")
        sys.exit(0)

    # Set up file logging early so install/update messages are captured
    setup_early_logging()

    # Handle uninstall
    if args.uninstall:
        from .installer import Installer
        success = Installer.uninstall()
        sys.exit(0 if success else 1)

    # Default behavior: auto-install/update if needed, then run tray
    if not args.no_install:
        from .installer import Installer

        if not Installer.is_running_installed():
            if not Installer.is_installed():
                # --- Fresh install ---
                from .dialogs import prompt_relay_url
                url = prompt_relay_url()
                if url is None:
                    sys.exit(0)
                success = Installer.install_fresh(url)
                sys.exit(0 if success else 1)

            elif Installer.needs_update():
                # --- Update (newer exe version) ---
                from .config import Config
                from .dialogs import ask_keep_or_change_url
                config = Config.load()
                url = ask_keep_or_change_url(config.relay_url)
                if url is None:
                    sys.exit(0)
                if url != config.relay_url:
                    config.relay_url = url
                    config.save()
                Installer.terminate_running_instances()
                success = Installer.update_exe()
                sys.exit(0 if success else 1)

            else:
                # --- Same version, already installed ---
                from .config import Config
                from .dialogs import ask_keep_or_change_url
                config = Config.load()
                url = ask_keep_or_change_url(config.relay_url)
                if url is None:
                    sys.exit(0)
                config_changed = False
                if url != config.relay_url:
                    config.relay_url = url
                    config.save()
                    config_changed = True
                if config_changed:
                    Installer.terminate_running_instances()
                    Installer.launch_installed()
                else:
                    if not Installer.is_process_running():
                        Installer.launch_installed()
                sys.exit(0)

    # Run in tray mode (either from install location or with --no-install)
    try:
        from .app import NetBridgeSocksApp

        app = NetBridgeSocksApp()
        exit_code = app.run()
        sys.exit(exit_code)
    except Exception:
        logging.exception("Fatal error in tray mode")
        sys.exit(1)


if __name__ == "__main__":
    main()
