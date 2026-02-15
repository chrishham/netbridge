"""
Win32 input dialogs for relay URL configuration.

Uses ctypes Win32 API (same pattern as winproxy.py) — no new dependencies.
"""

import ctypes
import ctypes.wintypes
from ctypes import byref, c_int, c_wchar_p
from typing import Optional


# Win32 constants
WS_OVERLAPPED = 0x00000000
WS_CAPTION = 0x00C00000
WS_SYSMENU = 0x00080000
WS_VISIBLE = 0x10000000
WS_CHILD = 0x40000000
WS_TABSTOP = 0x00010000
WS_BORDER = 0x00800000
WS_GROUP = 0x00020000
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

IDOK = 1
IDCANCEL = 2
IDYES = 6
IDNO = 7

MB_YESNO = 0x04
MB_ICONQUESTION = 0x20
MB_ICONERROR = 0x10

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
# Without these, ctypes defaults to c_int (32-bit) for arguments and return
# values. Handles are pointer-sized (64-bit) and overflow c_int on Win64.
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
    """Verify ctypes bindings work at runtime (called by --import-check).

    Constructs all structs and assigns callback fields to catch type
    mismatches that only surface at assignment time, not import time.
    """
    # Verify WNDCLASSW struct can be constructed with a real callback
    def _dummy(hwnd, msg, wparam, lparam):
        return 0

    cb = WNDPROC(_dummy)
    wc = WNDCLASSW()
    wc.lpfnWndProc = cb
    wc.lpszClassName = "SelfTestClass"

    # Verify MSG struct
    msg = ctypes.wintypes.MSG()
    _ = msg.message


def _get_default_font():
    """Create a default UI font (Segoe UI 9pt)."""
    return gdi32.CreateFontW(
        -12, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0, "Segoe UI"
    )


def prompt_relay_url(default: str = "") -> Optional[str]:
    """Show a modal dialog prompting for relay URL.

    Args:
        default: Pre-filled URL value

    Returns:
        The entered URL, or None if cancelled
    """
    result = [None]  # mutable container for closure
    hwnd_edit = [None]
    hwnd_error = [None]
    font = [None]
    done = [False]

    CLASS_NAME = "NetBridgeRelayDialog"

    def wndproc(hwnd, msg, wparam, lparam):
        if msg == WM_COMMAND:
            control_id = wparam & 0xFFFF
            notification = (wparam >> 16) & 0xFFFF

            if control_id == ID_OK and notification == BN_CLICKED:
                # Get text from edit control
                length = user32.SendMessageW(hwnd_edit[0], WM_GETTEXTLENGTH, 0, 0)
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.SendMessageW(hwnd_edit[0], WM_GETTEXT, length + 1, buf)
                url = buf.value.strip()

                # Validate: accept bare hostname, hostname with scheme, or full URL
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
            # Do NOT call PostQuitMessage here. It posts WM_QUIT to the
            # thread's message queue which kills pystray's message loop when
            # this dialog is opened from a tray-menu callback.  Instead, set
            # a flag that the message loop checks after DispatchMessageW
            # returns (DestroyWindow sends WM_DESTROY synchronously, so the
            # flag is set before the loop condition is re-evaluated).
            done[0] = True
            return 0

        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    # prevent garbage collection of the callback
    wndproc_cb = WNDPROC(wndproc)

    # Register window class
    wc = WNDCLASSW()
    wc.lpfnWndProc = wndproc_cb
    wc.hInstance = kernel32.GetModuleHandleW(None)
    wc.hCursor = user32.LoadCursorW(None, IDC_ARROW)
    wc.hbrBackground = ctypes.c_void_p(6)  # COLOR_WINDOW + 1
    wc.lpszClassName = CLASS_NAME

    atom = user32.RegisterClassW(byref(wc))
    if not atom:
        # Class may already be registered from previous call
        pass

    # Window dimensions
    win_w, win_h = 480, 200
    # Center on screen
    screen_w = user32.GetSystemMetrics(0)
    screen_h = user32.GetSystemMetrics(1)
    x = (screen_w - win_w) // 2
    y = (screen_h - win_h) // 2

    # Create main window
    hwnd = user32.CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        "NetBridge - Relay Host",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        x, y, win_w, win_h,
        None, None, wc.hInstance, None,
    )

    # Set solid border color (Windows 11+ where borders are 1px and invisible)
    try:
        border_color = ctypes.wintypes.DWORD(0x00707070)  # gray COLORREF
        dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_BORDER_COLOR,
            byref(border_color), ctypes.sizeof(border_color),
        )
    except Exception:
        pass  # Pre-Windows 11, borders are already visible

    font[0] = _get_default_font()

    # Label
    h_label = user32.CreateWindowExW(
        0, "STATIC",
        "Enter the relay hostname:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 20, 430, 20,
        hwnd, ID_LABEL, wc.hInstance, None,
    )
    user32.SendMessageW(h_label, WM_SETFONT, font[0], 1)

    # Edit control
    hwnd_edit[0] = user32.CreateWindowExW(
        WS_EX_CLIENTEDGE, "EDIT",
        default,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        20, 48, 430, 24,
        hwnd, ID_EDIT, wc.hInstance, None,
    )
    user32.SendMessageW(hwnd_edit[0], WM_SETFONT, font[0], 1)

    # Error label (hidden initially)
    hwnd_error[0] = user32.CreateWindowExW(
        0, "STATIC",
        "",
        WS_CHILD | SS_LEFT,
        20, 78, 430, 20,
        hwnd, ID_ERROR_LABEL, wc.hInstance, None,
    )
    user32.SendMessageW(hwnd_error[0], WM_SETFONT, font[0], 1)
    # Set text color to red via a simple approach: we'll just show the text

    # OK button
    h_ok = user32.CreateWindowExW(
        0, "BUTTON",
        "OK",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        240, 115, 90, 30,
        hwnd, ID_OK, wc.hInstance, None,
    )
    user32.SendMessageW(h_ok, WM_SETFONT, font[0], 1)

    # Cancel button
    h_cancel = user32.CreateWindowExW(
        0, "BUTTON",
        "Cancel",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        340, 115, 90, 30,
        hwnd, ID_CANCEL, wc.hInstance, None,
    )
    user32.SendMessageW(h_cancel, WM_SETFONT, font[0], 1)

    # Show window
    user32.ShowWindow(hwnd, SW_SHOW)
    user32.UpdateWindow(hwnd)

    # Set focus to edit control
    user32.SetFocus(hwnd_edit[0])

    # Message loop — use done flag instead of relying on GetMessageW
    # returning 0 from PostQuitMessage (which would interfere with
    # pystray's message loop on the same thread).
    msg = ctypes.wintypes.MSG()
    while not done[0]:
        ret = user32.GetMessageW(byref(msg), None, 0, 0)
        if ret <= 0:
            break
        # Handle Tab key navigation
        if not user32.IsDialogMessageW(hwnd, byref(msg)):
            user32.TranslateMessage(byref(msg))
            user32.DispatchMessageW(byref(msg))

    # Unregister class
    user32.UnregisterClassW(CLASS_NAME, wc.hInstance)

    return result[0]


def ask_keep_or_change_url(current_url: str) -> Optional[str]:
    """Ask the user whether to keep or change the current relay URL.

    Shows a Yes/No message box. If the user clicks Yes (change),
    opens the relay URL prompt dialog.

    Args:
        current_url: The currently configured relay URL

    Returns:
        The final URL (same or new), or None if cancelled
    """
    result = user32.MessageBoxW(
        None,
        f"Current relay host:\n\n{current_url}\n\nDo you want to change it?",
        "NetBridge - Relay Host",
        MB_YESNO | MB_ICONQUESTION,
    )

    if result == IDYES:
        return prompt_relay_url(current_url)

    if result == IDNO:
        return current_url

    # Dialog was dismissed (shouldn't happen with MB_YESNO, but be safe)
    return None
