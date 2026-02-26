"""
Win32 input dialogs for relay URL configuration.

Uses ctypes Win32 API — no new dependencies.
"""

import ctypes
import ctypes.wintypes
from ctypes import byref, c_wchar_p
from typing import Optional


# Win32 constants
WS_OVERLAPPED = 0x00000000
WS_CAPTION = 0x00C00000
WS_SYSMENU = 0x00080000
WS_VISIBLE = 0x10000000
WS_CHILD = 0x40000000
WS_TABSTOP = 0x00010000
WS_EX_DLGMODALFRAME = 0x00000001
WS_EX_CLIENTEDGE = 0x00000200

ES_AUTOHSCROLL = 0x0080

SS_LEFT = 0x00000000

BS_DEFPUSHBUTTON = 0x0001
BS_PUSHBUTTON = 0x0000

WM_COMMAND = 0x0111
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
WM_SETFONT = 0x0030
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
WM_SETTEXT = 0x000C

BN_CLICKED = 0

SW_SHOW = 5

IDC_ARROW = 32512

IDYES = 6
IDNO = 7

MB_YESNO = 0x04
MB_ICONQUESTION = 0x20

# Control IDs
ID_EDIT = 1001
ID_OK = 1002
ID_CANCEL = 1003
ID_LABEL = 1004
ID_ERROR_LABEL = 1005

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
gdi32 = ctypes.windll.gdi32
dwmapi = ctypes.windll.dwmapi

# Declare argtypes/restypes for 64-bit Windows safety.
kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
kernel32.GetModuleHandleW.restype = ctypes.wintypes.HINSTANCE

user32.CreateWindowExW.restype = ctypes.wintypes.HWND
user32.CreateWindowExW.argtypes = [
    ctypes.wintypes.DWORD,     # dwExStyle
    ctypes.c_wchar_p,          # lpClassName
    ctypes.c_wchar_p,          # lpWindowName
    ctypes.wintypes.DWORD,     # dwStyle
    ctypes.c_int,              # X
    ctypes.c_int,              # Y
    ctypes.c_int,              # nWidth
    ctypes.c_int,              # nHeight
    ctypes.wintypes.HWND,      # hWndParent
    ctypes.c_void_p,           # hMenu (control ID for child windows)
    ctypes.wintypes.HINSTANCE, # hInstance
    ctypes.c_void_p,           # lpParam
]

user32.SendMessageW.restype = ctypes.wintypes.LPARAM  # LRESULT
user32.SendMessageW.argtypes = [
    ctypes.wintypes.HWND, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p,
]

user32.LoadCursorW.restype = ctypes.c_void_p
user32.LoadCursorW.argtypes = [ctypes.wintypes.HINSTANCE, ctypes.c_void_p]

user32.RegisterClassW.argtypes = [ctypes.c_void_p]
user32.RegisterClassW.restype = ctypes.wintypes.ATOM

user32.UnregisterClassW.argtypes = [ctypes.c_wchar_p, ctypes.wintypes.HINSTANCE]

user32.ShowWindow.argtypes = [ctypes.wintypes.HWND, ctypes.c_int]
user32.UpdateWindow.argtypes = [ctypes.wintypes.HWND]
user32.SetFocus.argtypes = [ctypes.wintypes.HWND]
user32.DestroyWindow.argtypes = [ctypes.wintypes.HWND]

user32.GetMessageW.argtypes = [ctypes.c_void_p, ctypes.wintypes.HWND, ctypes.c_uint, ctypes.c_uint]
user32.IsDialogMessageW.argtypes = [ctypes.wintypes.HWND, ctypes.c_void_p]
user32.TranslateMessage.argtypes = [ctypes.c_void_p]
user32.DispatchMessageW.argtypes = [ctypes.c_void_p]

user32.DefWindowProcW.restype = ctypes.c_void_p
user32.DefWindowProcW.argtypes = [
    ctypes.wintypes.HWND, ctypes.c_uint, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM,
]

user32.MessageBoxW.argtypes = [ctypes.wintypes.HWND, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]

gdi32.CreateFontW.restype = ctypes.c_void_p
gdi32.DeleteObject.argtypes = [ctypes.c_void_p]

# DWM attribute for window border color (Windows 11+)
DWMWA_BORDER_COLOR = 34

# Callback type
WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.wintypes.HWND,
    ctypes.c_uint,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
)


class WNDCLASSW(ctypes.Structure):
    """Win32 WNDCLASSW structure."""
    _fields_ = [
        ("style", ctypes.c_uint),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", ctypes.wintypes.HINSTANCE),
        ("hIcon", ctypes.wintypes.HICON),
        ("hCursor", ctypes.c_void_p),
        ("hbrBackground", ctypes.c_void_p),
        ("lpszMenuName", ctypes.c_wchar_p),
        ("lpszClassName", ctypes.c_wchar_p),
    ]


def verify_bindings() -> None:
    """Verify ctypes bindings work at runtime (called by --import-check)."""
    def _dummy(hwnd, msg, wparam, lparam):
        return 0

    cb = WNDPROC(_dummy)
    wc = WNDCLASSW()
    wc.lpfnWndProc = cb
    wc.lpszClassName = "SelfTestClass"

    msg = ctypes.wintypes.MSG()
    _ = msg.message


def _get_default_font():
    """Create a default UI font (Segoe UI 9pt)."""
    return gdi32.CreateFontW(
        -12, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0, "Segoe UI"
    )


def prompt_relay_url(default: str = "") -> Optional[str]:
    """Show a modal dialog prompting for relay URL."""
    result = [None]
    hwnd_edit = [None]
    hwnd_error = [None]
    font = [None]
    done = [False]

    CLASS_NAME = "NetBridgeSocksRelayDialog"

    def wndproc(hwnd, msg, wparam, lparam):
        if msg == WM_COMMAND:
            control_id = wparam & 0xFFFF
            notification = (wparam >> 16) & 0xFFFF

            if control_id == ID_OK and notification == BN_CLICKED:
                length = user32.SendMessageW(hwnd_edit[0], WM_GETTEXTLENGTH, 0, 0)
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.SendMessageW(hwnd_edit[0], WM_GETTEXT, length + 1, buf)
                url = buf.value.strip()

                if not url:
                    user32.SendMessageW(
                        hwnd_error[0],
                        WM_SETTEXT,
                        0,
                        c_wchar_p("Please enter a relay hostname"),
                    )
                    user32.ShowWindow(hwnd_error[0], SW_SHOW)
                    return 0

                result[0] = url
                user32.DestroyWindow(hwnd)
                return 0

            elif control_id == ID_CANCEL and notification == BN_CLICKED:
                user32.DestroyWindow(hwnd)
                return 0

        elif msg == WM_CLOSE:
            user32.DestroyWindow(hwnd)
            return 0

        elif msg == WM_DESTROY:
            if font[0]:
                gdi32.DeleteObject(font[0])
            done[0] = True
            return 0

        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    wndproc_cb = WNDPROC(wndproc)

    wc = WNDCLASSW()
    wc.lpfnWndProc = wndproc_cb
    wc.hInstance = kernel32.GetModuleHandleW(None)
    wc.hCursor = user32.LoadCursorW(None, IDC_ARROW)
    wc.hbrBackground = ctypes.c_void_p(6)  # COLOR_WINDOW + 1
    wc.lpszClassName = CLASS_NAME

    atom = user32.RegisterClassW(byref(wc))
    if not atom:
        pass

    win_w, win_h = 480, 200
    screen_w = user32.GetSystemMetrics(0)
    screen_h = user32.GetSystemMetrics(1)
    x = (screen_w - win_w) // 2
    y = (screen_h - win_h) // 2

    hwnd = user32.CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        "NetBridge Socks - Relay Host",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        x, y, win_w, win_h,
        None, None, wc.hInstance, None,
    )

    try:
        border_color = ctypes.wintypes.DWORD(0x00707070)
        dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_BORDER_COLOR,
            byref(border_color), ctypes.sizeof(border_color),
        )
    except Exception:
        pass

    font[0] = _get_default_font()

    h_label = user32.CreateWindowExW(
        0, "STATIC",
        "Enter the relay hostname:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 20, 430, 20,
        hwnd, ID_LABEL, wc.hInstance, None,
    )
    user32.SendMessageW(h_label, WM_SETFONT, font[0], 1)

    hwnd_edit[0] = user32.CreateWindowExW(
        WS_EX_CLIENTEDGE, "EDIT",
        default,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        20, 48, 430, 24,
        hwnd, ID_EDIT, wc.hInstance, None,
    )
    user32.SendMessageW(hwnd_edit[0], WM_SETFONT, font[0], 1)

    hwnd_error[0] = user32.CreateWindowExW(
        0, "STATIC",
        "",
        WS_CHILD | SS_LEFT,
        20, 78, 430, 20,
        hwnd, ID_ERROR_LABEL, wc.hInstance, None,
    )
    user32.SendMessageW(hwnd_error[0], WM_SETFONT, font[0], 1)

    h_ok = user32.CreateWindowExW(
        0, "BUTTON",
        "OK",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        240, 115, 90, 30,
        hwnd, ID_OK, wc.hInstance, None,
    )
    user32.SendMessageW(h_ok, WM_SETFONT, font[0], 1)

    h_cancel = user32.CreateWindowExW(
        0, "BUTTON",
        "Cancel",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        340, 115, 90, 30,
        hwnd, ID_CANCEL, wc.hInstance, None,
    )
    user32.SendMessageW(h_cancel, WM_SETFONT, font[0], 1)

    user32.ShowWindow(hwnd, SW_SHOW)
    user32.UpdateWindow(hwnd)
    user32.SetFocus(hwnd_edit[0])

    msg = ctypes.wintypes.MSG()
    while not done[0]:
        ret = user32.GetMessageW(byref(msg), None, 0, 0)
        if ret <= 0:
            break
        if not user32.IsDialogMessageW(hwnd, byref(msg)):
            user32.TranslateMessage(byref(msg))
            user32.DispatchMessageW(byref(msg))

    user32.UnregisterClassW(CLASS_NAME, wc.hInstance)

    return result[0]


def ask_keep_or_change_url(current_url: str) -> Optional[str]:
    """Ask the user whether to keep or change the current relay URL."""
    result = user32.MessageBoxW(
        None,
        f"Current relay host:\n\n{current_url}\n\nDo you want to change it?",
        "NetBridge Socks - Relay Host",
        MB_YESNO | MB_ICONQUESTION,
    )

    if result == IDYES:
        return prompt_relay_url(current_url)

    if result == IDNO:
        return current_url

    return None
