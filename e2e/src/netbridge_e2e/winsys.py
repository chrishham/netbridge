"""Windows-only helpers: the startup Run value and the uninstall confirmation."""
import ctypes
import time
import winreg
from ctypes import wintypes

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
WM_COMMAND = 0x0111
IDYES = 6

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
_user32.FindWindowW.restype = wintypes.HWND
_user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.PostMessageW.restype = wintypes.BOOL


def set_run_value(name: str, value: str) -> None:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


def delete_run_value(name: str) -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def run_value_exists(name: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, name)
        return True
    except FileNotFoundError:
        return False


def click_messagebox_yes(title: str, timeout: float) -> bool:
    """Answer "Yes" on the MessageBox (dialog class #32770) with this title."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hwnd = _user32.FindWindowW("#32770", title)
        if hwnd:
            return bool(_user32.PostMessageW(hwnd, WM_COMMAND, IDYES, 0))
        time.sleep(0.5)
    return False
