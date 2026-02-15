"""
NetBridge Agent - Entry point

A system tray application that provides TCP tunneling through a relay server.

Usage:
    netbridge                  # Auto-install if needed, then run
    netbridge --console        # Run in console mode (for debugging)
    netbridge --uninstall      # Remove from system
    netbridge --version        # Show version
"""

import argparse
import logging
import sys

from .config import APP_NAME, APP_VERSION, ensure_app_dirs, get_log_path


def hide_console_window() -> None:
    """Hide any console/blank window on Windows."""
    if sys.platform != "win32":
        return

    try:
        import ctypes
        # Get the console window handle
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            # SW_HIDE = 0
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


def setup_early_logging() -> None:
    """Set up basic logging before app initialization."""
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

        # Only add handler if not already present
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
        pass  # Silently fail if logging can't be set up


def main():
    """Entry point for the NetBridge application."""
    # Hide the console window for normal tray operation, but skip for
    # CLI flags that need stdout (--version, --import-check).
    if "--version" not in sys.argv and "--import-check" not in sys.argv:
        hide_console_window()

    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - Network tunneling through relay server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netbridge                    Auto-install/update if needed, then run
  netbridge --console          Run in console mode (for debugging)
  netbridge --uninstall        Remove from system

The tray icon shows connection status:
  Green   - Connected
  Yellow  - Connecting
  Red     - Disconnected
  Orange  - Login required (run 'az login')
        """,
    )

    # Mode selection (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove from system",
    )
    mode_group.add_argument(
        "--console",
        action="store_true",
        help="Run in console mode (no tray, for debugging)",
    )
    mode_group.add_argument(
        "--legacy",
        action="store_true",
        help="Run legacy console-only mode (original behavior)",
    )
    mode_group.add_argument(
        "--no-install",
        action="store_true",
        help="Run without installing (standalone mode)",
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

    # Legacy options (only used in legacy mode)
    parser.add_argument(
        "--relay",
        help="Relay WebSocket URL (legacy mode only)",
    )
    parser.add_argument(
        "--token",
        help="ARM access token (legacy mode only). "
             "Can also be set via NETBRIDGE_TOKEN env var.",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable authentication (legacy mode only)",
    )
    parser.add_argument(
        "--proxy-user",
        help="Relay proxy username (legacy mode only)",
    )
    parser.add_argument(
        "--proxy-pass",
        help="Relay proxy password (legacy mode only)",
    )
    parser.add_argument(
        "--passthrough-proxy-user",
        help="Passthrough proxy username (legacy mode only)",
    )
    parser.add_argument(
        "--passthrough-proxy-pass",
        help="Passthrough proxy password (legacy mode only)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="INSECURE: Disable SSL certificate verification. Only use as a last resort when behind a TLS-intercepting proxy (legacy mode only).",
    )
    parser.add_argument(
        "--ca-bundle",
        metavar="FILE",
        help="Path to a custom CA certificate file for SSL verification. "
             "Use this instead of --no-verify-ssl when behind a TLS-intercepting proxy (legacy mode only).",
    )

    args = parser.parse_args()

    # Handle import check (CI smoke test for bundled modules)
    if args.import_check:
        from . import agent, app, auth, config, dialogs, installer, legacy, tray, tunnel, winproxy  # noqa: F401
        print(f"{APP_NAME} v{APP_VERSION}: all modules imported OK")
        # Verify ctypes bindings (catches runtime type mismatches)
        if sys.platform == "win32":
            dialogs.verify_bindings()
            winproxy.verify_bindings()
            print("ctypes bindings verified OK")
        sys.exit(0)

    # Set up logging early so install/update messages are captured
    setup_early_logging()

    # Handle uninstall
    if args.uninstall:
        from .installer import Installer
        success = Installer.uninstall()
        sys.exit(0 if success else 1)

    # Handle legacy mode (original console behavior)
    if args.legacy:
        return run_legacy_mode(args)

    # Handle console mode (no install check)
    if args.console:
        from .app import NetBridgeApp
        app = NetBridgeApp(console=True)
        exit_code = app.run()
        sys.exit(exit_code)

    # Default behavior: auto-install/update if needed
    if not args.no_install:
        from .installer import Installer

        # Check if we're already running from install location
        if not Installer.is_running_installed():
            if not Installer.is_installed():
                # --- Fresh install ---
                from .dialogs import prompt_relay_url
                url = prompt_relay_url()
                if url is None:
                    sys.exit(0)  # User cancelled
                success = Installer.install_fresh(url)
                sys.exit(0 if success else 1)

            elif Installer.needs_update():
                # --- Update (newer exe version) ---
                from .config import Config
                from .dialogs import ask_keep_or_change_url
                config = Config.load()
                url = ask_keep_or_change_url(config.relay_url)
                if url is None:
                    sys.exit(0)  # User cancelled
                if url != config.relay_url:
                    config.relay_url = url
                    config.save()
                # Kill existing instance before overwriting exe
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
                    sys.exit(0)  # User cancelled
                config_changed = False
                if url != config.relay_url:
                    config.relay_url = url
                    config.save()
                    config_changed = True
                # Only restart if config changed; otherwise avoid touching a running install
                if config_changed:
                    Installer.terminate_running_instances()
                    Installer.launch_installed()
                else:
                    if not Installer.is_process_running():
                        Installer.launch_installed()
                sys.exit(0)

    # Run in tray mode (either from install location or with --no-install)
    try:
        from .app import NetBridgeApp

        app = NetBridgeApp(console=False)
        exit_code = app.run()
        sys.exit(exit_code)
    except Exception:
        logging.exception("Fatal error in tray mode")
        sys.exit(1)


def run_legacy_mode(args):
    """Run in legacy console-only mode (original behavior).

    This preserves the original command-line interface for backwards compatibility.
    """
    import asyncio
    import os
    from datetime import datetime

    from .auth import (
        get_arm_token,
        check_az_login,
        get_user_identity,
        check_token_expiration,
    )
    from .config import DEFAULT_RELAY_URL

    # Guard --no-auth: require explicit opt-in
    if args.no_auth:
        allow_no_auth = os.environ.get(
            "NETBRIDGE_ALLOW_NO_AUTH", ""
        ).lower() in ("1", "true", "yes")
        if not allow_no_auth:
            print(
                "[!] --no-auth requires NETBRIDGE_ALLOW_NO_AUTH=true "
                "environment variable"
            )
            sys.exit(1)

    # Guard --no-verify-ssl: require NETBRIDGE_ALLOW_INSECURE=1
    if args.no_verify_ssl:
        allow_insecure = os.environ.get(
            "NETBRIDGE_ALLOW_INSECURE", ""
        ).lower() in ("1", "true", "yes")
        if not allow_insecure:
            print(
                "[!] --no-verify-ssl requires NETBRIDGE_ALLOW_INSECURE=1 "
                "environment variable. Consider using --ca-bundle instead."
            )
            sys.exit(1)
        os.environ["NETBRIDGE_VERIFY_SSL"] = "false"
        print("[*] SSL certificate verification disabled")

    # Set NETBRIDGE_CA_BUNDLE from --ca-bundle flag
    if args.ca_bundle:
        os.environ["NETBRIDGE_CA_BUNDLE"] = args.ca_bundle
        print(f"[*] Using custom CA bundle: {args.ca_bundle}")

    def ts() -> str:
        return datetime.now().strftime("%H:%M:%S")

    EXIT_SUCCESS = 0
    EXIT_AUTH_FAILURE = 2

    print(f"[*] {APP_NAME} v{APP_VERSION} (Legacy Mode)")

    relay_url = args.relay or DEFAULT_RELAY_URL

    # Get auth token
    if not args.token:
        env_token = os.environ.get("NETBRIDGE_TOKEN")
        if env_token:
            args.token = env_token
            print("[*] Using token from NETBRIDGE_TOKEN environment variable")

    auth_token = None
    if args.token:
        auth_token = args.token
        print("[*] Using provided token")
        is_valid, token_msg = check_token_expiration(auth_token)
        if not is_valid:
            print(f"[!] {token_msg}")
            sys.exit(EXIT_AUTH_FAILURE)
        print(f"[*] {token_msg}")
    elif not args.no_auth:
        print("[*] Authenticating with Azure CLI...")
        logged_in, message = check_az_login()
        if not logged_in:
            print(f"[!] {message}")
            print()
            print("[!] Exiting with code 2 (auth failure)")
            sys.exit(EXIT_AUTH_FAILURE)

        print(f"[*] {message}")

        try:
            auth_token = get_arm_token()
            is_valid, token_msg = check_token_expiration(auth_token)
            if not is_valid:
                print(f"[!] {token_msg}")
                sys.exit(EXIT_AUTH_FAILURE)
            user = get_user_identity() or "unknown"
            print(f"[*] Authenticated as: {user}")
            print(f"[*] {token_msg}")
        except RuntimeError as e:
            print(f"[!] Authentication failed: {e}")
            sys.exit(EXIT_AUTH_FAILURE)
    else:
        print("[!] WARNING: Authentication disabled")

    # Import and run legacy async_main
    from . import legacy
    token_refresh = get_arm_token if (not args.no_auth and not args.token) else None

    try:
        asyncio.run(legacy.async_main(
            relay_url,
            auth_token,
            args.proxy_user,
            args.proxy_pass,
            token_refresh,
            args.passthrough_proxy_user,
            args.passthrough_proxy_pass,
        ))
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    finally:
        print("[*] Goodbye!")


if __name__ == "__main__":
    main()
