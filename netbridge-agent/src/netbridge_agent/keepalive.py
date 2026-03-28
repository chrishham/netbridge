"""
VDI session keep-alive via simulated mouse input.

Prevents Windows RDS/VDI from marking the session as idle by:
1. Calling SetThreadExecutionState to signal the system is in use
2. Periodically sending a tiny mouse movement (1px right, then 1px left)
   via SendInput to reset the GetLastInputInfo idle timer

The combination covers both OS-level idle detection and RDS input-based
idle tracking.
"""

import asyncio
import ctypes
import ctypes.wintypes
import logging
import sys

logger = logging.getLogger(__name__)

# Keep-alive interval in seconds (3 minutes)
KEEPALIVE_INTERVAL = 180

# Windows constants
INPUT_MOUSE = 0
MOUSEEVENTF_MOVE = 0x0001

# SetThreadExecutionState flags
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.wintypes.LONG),
        ("dy", ctypes.wintypes.LONG),
        ("mouseData", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("time", ctypes.wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]


class INPUT(ctypes.Structure):
    class _INPUT_UNION(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT)]

    _fields_ = [
        ("type", ctypes.wintypes.DWORD),
        ("union", _INPUT_UNION),
    ]


def _set_execution_state(active: bool) -> None:
    """Tell Windows the system is in use (or clear the flag).

    When active, prevents the OS from entering sleep or turning off the display.
    """
    if sys.platform != "win32":
        return

    if active:
        flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
    else:
        flags = ES_CONTINUOUS  # Clear previous flags

    ctypes.windll.kernel32.SetThreadExecutionState(flags)


def _jiggle_mouse() -> bool:
    """Send a 1px mouse movement right then left (net zero).

    Resets the GetLastInputInfo idle timer used by RDS for idle detection.
    Returns True if successful.
    """
    if sys.platform != "win32":
        return False

    inputs = (INPUT * 2)()

    # Move 1px right
    inputs[0].type = INPUT_MOUSE
    inputs[0].union.mi.dx = 1
    inputs[0].union.mi.dy = 0
    inputs[0].union.mi.dwFlags = MOUSEEVENTF_MOVE

    # Move 1px left
    inputs[1].type = INPUT_MOUSE
    inputs[1].union.mi.dx = -1
    inputs[1].union.mi.dy = 0
    inputs[1].union.mi.dwFlags = MOUSEEVENTF_MOVE

    sent = ctypes.windll.user32.SendInput(2, ctypes.byref(inputs), ctypes.sizeof(INPUT))
    return sent == 2


async def session_keepalive_loop(stop_event: asyncio.Event) -> None:
    """Periodically jiggle the mouse to keep the VDI session alive.

    Args:
        stop_event: Event to signal shutdown.
    """
    logger.info("Session keep-alive started (interval: %ds)", KEEPALIVE_INTERVAL)

    # Tell Windows the system is in use
    _set_execution_state(active=True)

    try:
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=KEEPALIVE_INTERVAL)
                break  # stop_event was set
            except asyncio.TimeoutError:
                pass

            if _jiggle_mouse():
                logger.debug("Session keep-alive: mouse jiggle sent")
            else:
                logger.warning("Session keep-alive: SendInput failed")
    finally:
        # Clear the execution state flag
        _set_execution_state(active=False)
        logger.info("Session keep-alive stopped")
