"""Cross-platform input dialogs for relay URL configuration."""

import logging
import shutil
import subprocess
import sys
from typing import Optional

logger = logging.getLogger(__name__)


def _prompt_macos(title: str, prompt: str, default: str) -> Optional[str]:
    # Pass values via argv to avoid AppleScript injection
    script = (
        "on run argv\n"
        "  set result to display dialog (item 1 of argv) "
        "default answer (item 2 of argv) "
        "with title (item 3 of argv) "
        'buttons {"Cancel", "OK"} default button "OK"\n'
        "  return text returned of result\n"
        "end run"
    )
    try:
        proc = subprocess.run(
            ["osascript", "-e", script, prompt, default, title],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode == 0:
            return proc.stdout.strip() or None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def _prompt_zenity(title: str, prompt: str, default: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            [
                "zenity", "--entry",
                f"--title={title}",
                f"--text={prompt}",
                f"--entry-text={default}",
            ],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode == 0:
            return proc.stdout.strip() or None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def _prompt_kdialog(title: str, prompt: str, default: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            [
                "kdialog", "--inputbox", prompt, default,
                "--title", title,
            ],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode == 0:
            return proc.stdout.strip() or None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def prompt_relay_url(default: str = "") -> Optional[str]:
    """Show a dialog prompting for the relay URL. Returns None if cancelled."""
    title = "NetBridge Socks - Relay Host"
    prompt = "Enter the relay hostname:"

    if sys.platform == "darwin":
        return _prompt_macos(title, prompt, default)

    if shutil.which("zenity"):
        return _prompt_zenity(title, prompt, default)

    if shutil.which("kdialog"):
        return _prompt_kdialog(title, prompt, default)

    logger.warning("No GUI dialog tool found (zenity or kdialog)")
    return None
