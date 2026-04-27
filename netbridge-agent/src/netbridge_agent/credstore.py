"""
Encrypted credential store for passthrough proxy auth.

On Windows, password is encrypted via DPAPI (CryptProtectData) scoped to the
current user. On other platforms, falls back to plaintext (since SSPI is
Windows-only this module is mainly relevant on Windows anyway).

Stored as JSON in %LOCALAPPDATA%/NetBridge/proxy_creds.json:
    {"username": "...", "password_b64": "<base64-of-DPAPI-blob>"}
"""

import base64
import ctypes
import ctypes.wintypes
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from .config import get_app_dir

logger = logging.getLogger(__name__)


def get_creds_path() -> Path:
    return get_app_dir() / "proxy_creds.json"


# --- Win32 DPAPI bindings ---

if sys.platform == "win32":
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_wchar_p,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    _crypt32.CryptProtectData.restype = ctypes.wintypes.BOOL

    _crypt32.CryptUnprotectData.argtypes = _crypt32.CryptProtectData.argtypes
    _crypt32.CryptUnprotectData.restype = ctypes.wintypes.BOOL


def _dpapi_encrypt(plaintext: str) -> bytes:
    """Encrypt with DPAPI. Returns raw blob bytes."""
    data = plaintext.encode("utf-8")
    blob_in = DATA_BLOB(len(data), ctypes.cast(
        ctypes.c_char_p(data), ctypes.POINTER(ctypes.c_char)
    ))
    blob_out = DATA_BLOB()
    ok = _crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        "NetBridgeProxyCreds",
        None, None, None, 0,
        ctypes.byref(blob_out),
    )
    if not ok:
        raise OSError(f"CryptProtectData failed: {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _kernel32.LocalFree(blob_out.pbData)


def _dpapi_decrypt(ciphertext: bytes) -> str:
    """Decrypt DPAPI blob. Returns plaintext."""
    blob_in = DATA_BLOB(len(ciphertext), ctypes.cast(
        ctypes.c_char_p(ciphertext), ctypes.POINTER(ctypes.c_char)
    ))
    blob_out = DATA_BLOB()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None, None, None, None, 0,
        ctypes.byref(blob_out),
    )
    if not ok:
        raise OSError(f"CryptUnprotectData failed: {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData).decode("utf-8")
    finally:
        _kernel32.LocalFree(blob_out.pbData)


def save_proxy_credentials(username: str, password: str) -> None:
    """Save proxy credentials. Password encrypted via DPAPI on Windows."""
    path = get_creds_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform == "win32":
        encrypted = _dpapi_encrypt(password)
        password_b64 = base64.b64encode(encrypted).decode("ascii")
        data = {"username": username, "password_b64": password_b64}
    else:
        # Fallback: plaintext (mark scheme so we know on load)
        data = {"username": username, "password_plain": password, "scheme": "plain"}

    with open(path, "w") as f:
        json.dump(data, f)

    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_proxy_credentials() -> Optional[tuple[str, str]]:
    """Load proxy credentials. Returns (user, pass) or None if not set."""
    path = get_creds_path()
    if not path.exists():
        return None

    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to read proxy creds: {e}")
        return None

    username = data.get("username")
    if not username:
        return None

    if "password_b64" in data and sys.platform == "win32":
        try:
            ciphertext = base64.b64decode(data["password_b64"])
            password = _dpapi_decrypt(ciphertext)
            return (username, password)
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to decrypt proxy password: {e}")
            return None

    if "password_plain" in data:
        return (username, data["password_plain"])

    return None


def clear_proxy_credentials() -> None:
    """Delete stored proxy credentials."""
    path = get_creds_path()
    if path.exists():
        path.unlink()


def has_proxy_credentials() -> bool:
    """Return True if creds file exists and has a username."""
    creds = load_proxy_credentials()
    return creds is not None
