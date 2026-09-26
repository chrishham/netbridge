"""Windows-only helpers: the startup Run value and the uninstall confirmation."""
import ctypes
import time
import winreg
from collections.abc import Callable
from ctypes import wintypes

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
WM_COMMAND = 0x0111
IDYES = 6
TH32CS_SNAPPROCESS = 0x00000002

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
_user32.FindWindowW.restype = wintypes.HWND
_user32.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
_user32.FindWindowExW.restype = wintypes.HWND
_user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
_user32.GetWindowThreadProcessId.restype = wintypes.DWORD
_user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.PostMessageW.restype = wintypes.BOOL

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
_kernel32.Process32FirstW.restype = wintypes.BOOL
_kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
_kernel32.Process32NextW.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


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


def parent_pid(pid: int) -> int | None:
    """Return the parent process ID of the given PID, or None if not found."""
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        return None
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not _kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return None
        while True:
            if entry.th32ProcessID == pid:
                return entry.th32ParentProcessID
            if not _kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                return None
    finally:
        _kernel32.CloseHandle(snapshot)


def click_messagebox_yes(title: str, timeout: float, accept_pid: Callable[[int], bool]) -> bool:
    """Answer "Yes" on the MessageBox (dialog class #32770) with this title.

    Only clicks windows whose PID is accepted by the accept_pid predicate.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        prev_hwnd = None
        while True:
            hwnd = _user32.FindWindowExW(None, prev_hwnd, "#32770", title)
            if not hwnd:
                break
            window_pid = wintypes.DWORD()
            _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
            if accept_pid(window_pid.value):
                return bool(_user32.PostMessageW(hwnd, WM_COMMAND, IDYES, 0))
            prev_hwnd = hwnd
        time.sleep(0.5)
    return False
