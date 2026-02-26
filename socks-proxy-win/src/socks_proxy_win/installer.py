"""
Installer for NetBridge Socks tray application.

Handles:
- Installing to %LOCALAPPDATA%/NetBridgeSocks/
- Adding to Windows Startup (registry)
- Uninstalling and cleanup
"""

import filecmp
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .config import APP_NAME, APP_VERSION, get_app_dir, get_config_path, Config, ensure_app_dirs

logger = logging.getLogger(__name__)


# Registry key for Windows startup
STARTUP_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP_VALUE_NAME = "NetBridgeSocks"


def get_exe_path() -> Path:
    """Get path to the current executable."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable)
    else:
        return Path(sys.argv[0]).resolve()


def get_installed_exe_path() -> Path:
    """Get path where the exe should be installed."""
    return get_app_dir() / "netbridge-socks.exe"


def get_version_file_path() -> Path:
    """Get path to the version file in install directory."""
    return get_app_dir() / "version.json"


class Installer:
    """Handles install/uninstall operations."""

    @staticmethod
    def get_installed_exe_path() -> Path:
        """Get path where the exe should be installed."""
        return get_installed_exe_path()

    @staticmethod
    def is_installed() -> bool:
        """Check if NetBridge Socks is installed."""
        return get_installed_exe_path().exists()

    @staticmethod
    def is_running_installed() -> bool:
        """Check if we're running from the install location."""
        return get_exe_path() == get_installed_exe_path()

    @staticmethod
    def get_installed_version() -> Optional[str]:
        """Get the version of the installed application."""
        version_file = get_version_file_path()
        if version_file.exists():
            try:
                with open(version_file) as f:
                    data = json.load(f)
                    return data.get("version")
            except (json.JSONDecodeError, IOError):
                pass
        return None

    @staticmethod
    def save_installed_version(version: str) -> None:
        """Save the installed version to version file."""
        version_file = get_version_file_path()
        try:
            with open(version_file, "w") as f:
                json.dump({"version": version}, f)
        except IOError:
            pass

    @staticmethod
    def needs_update() -> bool:
        """Check if the current exe is newer than the installed version."""
        if not Installer.is_installed():
            return True

        installed_version = Installer.get_installed_version()
        if not installed_version:
            return True

        try:
            from packaging.version import Version
            return Version(APP_VERSION) > Version(installed_version)
        except Exception:
            return True

    @staticmethod
    def terminate_running_instances() -> None:
        """Kill any running netbridge-socks.exe processes except the current one."""
        our_pid = os.getpid()
        killed_any = False

        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq netbridge-socks.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            for line in result.stdout.strip().splitlines():
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                    except (ValueError, IndexError):
                        continue
                    if pid == our_pid:
                        continue
                    subprocess.run(
                        ["taskkill", "/PID", str(pid), "/F"],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    killed_any = True
                    logger.info(f"Terminated existing netbridge-socks.exe (PID {pid})")

        except Exception as e:
            logger.warning(f"Failed to enumerate processes: {e}")
            return

        if killed_any:
            target_exe = get_installed_exe_path()
            if target_exe.exists():
                for _ in range(10):
                    try:
                        with open(target_exe, "r+b"):
                            break
                    except (IOError, OSError):
                        time.sleep(0.5)

    @staticmethod
    def is_process_running() -> bool:
        """Check if any netbridge-socks.exe process is running besides us."""
        our_pid = os.getpid()
        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq netbridge-socks.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in result.stdout.strip().splitlines():
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                    except (ValueError, IndexError):
                        continue
                    if pid != our_pid:
                        return True
        except Exception:
            return False

        return False

    @staticmethod
    def copy_exe() -> None:
        """Copy the current executable to the install location."""
        source_exe = get_exe_path()
        target_exe = get_installed_exe_path()

        if source_exe != target_exe:
            if getattr(sys, "frozen", False):
                if target_exe.exists():
                    try:
                        if filecmp.cmp(source_exe, target_exe, shallow=False):
                            logger.info(f"Executable already up to date: {target_exe}")
                            return
                    except OSError:
                        pass

                target_exe.parent.mkdir(parents=True, exist_ok=True)
                temp_exe = target_exe.with_name(f"{target_exe.name}.tmp")
                try:
                    if temp_exe.exists():
                        temp_exe.unlink()
                except OSError:
                    pass

                shutil.copy2(source_exe, temp_exe)
                os.replace(temp_exe, target_exe)
                logger.info(f"Copied executable to: {target_exe}")
            else:
                logger.warning("Running from source - skipping exe copy")

    @staticmethod
    def create_config(relay_url: str) -> None:
        """Create config with the provided relay URL. Only creates if config doesn't already exist."""
        config_path = get_config_path()
        if not config_path.exists():
            config = Config(relay_url=relay_url)
            config.save()
            logger.info(f"Created config: {config_path}")

    @staticmethod
    def ensure_startup_registered() -> None:
        """Add to Windows Startup only if not already registered."""
        if not Installer.is_in_startup():
            Installer.add_to_startup()
            logger.info("Added to Windows Startup")

    @staticmethod
    def launch_installed() -> bool:
        """Launch the installed application."""
        target_exe = get_installed_exe_path()
        if getattr(sys, "frozen", False) and target_exe.exists():
            logger.info(f"Launching {APP_NAME}...")
            subprocess.Popen(
                [str(target_exe)],
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
            )
            return True
        return False

    @staticmethod
    def install_fresh(relay_url: str) -> bool:
        """Full first-time install."""
        logger.info(f"Installing {APP_NAME} v{APP_VERSION}...")

        try:
            ensure_app_dirs()
            logger.info(f"Created directory: {get_app_dir()}")

            Installer.copy_exe()
            Installer.create_config(relay_url)
            Installer.save_installed_version(APP_VERSION)
            Installer.ensure_startup_registered()

            logger.info("Installation complete!")
            Installer.launch_installed()
            return True

        except Exception as e:
            logger.error(f"Installation failed: {e}")
            return False

    @staticmethod
    def update_exe() -> bool:
        """Update only: copies exe, saves version, ensures startup, launches."""
        logger.info(f"Updating {APP_NAME} to v{APP_VERSION}...")

        try:
            ensure_app_dirs()
            Installer.copy_exe()
            Installer.save_installed_version(APP_VERSION)
            Installer.ensure_startup_registered()

            logger.info("Update complete!")
            Installer.launch_installed()
            return True

        except Exception as e:
            logger.error(f"Update failed: {e}")
            return False

    @staticmethod
    def uninstall(confirm: bool = True) -> bool:
        """Uninstall the application."""
        import ctypes

        logger.info(f"Uninstalling {APP_NAME}...")

        # Close all logging handlers to release log file
        for handler in logging.root.handlers[:]:
            handler.close()
            logging.root.removeHandler(handler)

        if confirm:
            result = ctypes.windll.user32.MessageBoxW(
                0,
                f"Are you sure you want to uninstall {APP_NAME}?",
                f"Uninstall {APP_NAME}",
                0x04 | 0x30,  # MB_YESNO | MB_ICONWARNING
            )
            if result != 6:  # IDYES
                return False

        try:
            Installer.remove_from_startup()

            app_dir = get_app_dir()
            if app_dir.exists():
                if Installer.is_running_installed():
                    Installer._schedule_delete(app_dir)
                else:
                    shutil.rmtree(app_dir)

            return True

        except Exception as e:
            logger.error(f"Uninstall failed: {e}")
            return False

    @staticmethod
    def _schedule_delete(path: Path) -> None:
        """Schedule deletion of a directory after process exits."""
        batch_content = f'''@echo off
:retry
timeout /t 3 /nobreak > nul
rmdir /s /q "{path}" 2>nul
if exist "{path}" goto retry
del "%~f0"
'''
        batch_path = Path(os.environ.get("TEMP", ".")) / "netbridge_socks_uninstall.bat"
        batch_path.write_text(batch_content)

        subprocess.Popen(
            ["cmd", "/c", str(batch_path)],
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
        )

    @staticmethod
    def add_to_startup() -> bool:
        """Add application to Windows Startup."""
        try:
            import winreg

            exe_path = get_installed_exe_path()
            if not exe_path.exists():
                exe_path = get_exe_path()

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                STARTUP_REG_KEY,
                0,
                winreg.KEY_SET_VALUE,
            )
            try:
                winreg.SetValueEx(
                    key,
                    STARTUP_VALUE_NAME,
                    0,
                    winreg.REG_SZ,
                    f'"{exe_path}"',
                )
            finally:
                winreg.CloseKey(key)

            return True

        except Exception as e:
            logger.error(f"Failed to add to startup: {e}")
            return False

    @staticmethod
    def remove_from_startup() -> bool:
        """Remove application from Windows Startup."""
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                STARTUP_REG_KEY,
                0,
                winreg.KEY_SET_VALUE,
            )
            try:
                winreg.DeleteValue(key, STARTUP_VALUE_NAME)
            except FileNotFoundError:
                pass
            finally:
                winreg.CloseKey(key)

            return True

        except Exception as e:
            logger.error(f"Failed to remove from startup: {e}")
            return False

    @staticmethod
    def is_in_startup() -> bool:
        """Check if application is in Windows Startup."""
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                STARTUP_REG_KEY,
                0,
                winreg.KEY_READ,
            )
            try:
                winreg.QueryValueEx(key, STARTUP_VALUE_NAME)
                return True
            except FileNotFoundError:
                return False
            finally:
                winreg.CloseKey(key)

        except Exception:
            return False
