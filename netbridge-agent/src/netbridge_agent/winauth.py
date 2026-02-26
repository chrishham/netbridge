"""
Windows SSPI-based NTLM/Negotiate proxy authentication via ctypes.

Uses the native SSPI API (secur32.dll) to authenticate with corporate
proxies using the current Windows user's session credentials - the same
mechanism used by Chrome/Edge for transparent proxy authentication.

On non-Windows platforms this module can be imported but SSPIAuth will
raise RuntimeError on instantiation.
"""

import base64
import ctypes
import ctypes.wintypes
import logging
import sys
from ctypes import POINTER, Structure, byref, c_ulong, c_void_p, c_wchar_p

logger = logging.getLogger(__name__)

# SSPI constants
SEC_E_OK = 0x00000000
SEC_I_CONTINUE_NEEDED = 0x00090312
SEC_I_COMPLETE_AND_CONTINUE = 0x00090314
SEC_I_COMPLETE_NEEDED = 0x00090313

SECPKG_CRED_OUTBOUND = 0x00000002

ISC_REQ_CONFIDENTIALITY = 0x00000010
ISC_REQ_ALLOCATE_MEMORY = 0x00000100
ISC_REQ_CONNECTION = 0x00000800

SECURITY_NATIVE_DREP = 0x00000010

SECBUFFER_TOKEN = 2
SECBUFFER_EMPTY = 0

ISC_REQ_FLAGS = ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION

# Max token size for Negotiate/NTLM
MAX_TOKEN_SIZE = 48000


class SecHandle(Structure):
    """SSPI credential/context handle (two pointer-width fields)."""
    _fields_ = [
        ("dwLower", c_void_p),
        ("dwUpper", c_void_p),
    ]


class TimeStamp(Structure):
    """SECURITY_INTEGER used for credential expiry."""
    _fields_ = [
        ("LowPart", ctypes.wintypes.DWORD),
        ("HighPart", ctypes.wintypes.LONG),
    ]


class SecBuffer(Structure):
    """Single SSPI buffer."""
    _fields_ = [
        ("cbBuffer", c_ulong),
        ("BufferType", c_ulong),
        ("pvBuffer", c_void_p),
    ]


class SecBufferDesc(Structure):
    """SSPI buffer descriptor (array of SecBuffer)."""
    _fields_ = [
        ("ulVersion", c_ulong),
        ("cBuffers", c_ulong),
        ("pBuffers", POINTER(SecBuffer)),
    ]


def verify_bindings() -> None:
    """Verify ctypes bindings work at runtime (called by --import-check).

    Constructs all structs and assigns fields to catch type mismatches
    that only surface at assignment time, not import time.
    """
    h = SecHandle()
    h.dwLower = 0
    h.dwUpper = 0

    ts = TimeStamp()
    ts.LowPart = 0
    ts.HighPart = 0

    buf = SecBuffer()
    buf.cbBuffer = 0
    buf.BufferType = SECBUFFER_TOKEN
    buf.pvBuffer = None

    desc = SecBufferDesc()
    desc.ulVersion = 0
    desc.cBuffers = 1
    desc.pBuffers = ctypes.pointer(buf)


def _load_secur32():
    """Load secur32.dll and set up function prototypes."""
    secur32 = ctypes.windll.secur32

    # AcquireCredentialsHandleW
    secur32.AcquireCredentialsHandleW.argtypes = [
        c_wchar_p,               # pszPrincipal
        c_wchar_p,               # pszPackage
        c_ulong,                 # fCredentialUse
        c_void_p,                # pvLogonId
        c_void_p,                # pAuthData
        c_void_p,                # pGetKeyFn
        c_void_p,                # pvGetKeyArgument
        POINTER(SecHandle),      # phCredential
        POINTER(TimeStamp),      # ptsExpiry
    ]
    secur32.AcquireCredentialsHandleW.restype = ctypes.wintypes.LONG

    # InitializeSecurityContextW
    secur32.InitializeSecurityContextW.argtypes = [
        POINTER(SecHandle),      # phCredential
        POINTER(SecHandle),      # phContext (None on first call)
        c_wchar_p,               # pszTargetName
        c_ulong,                 # fContextReq
        c_ulong,                 # Reserved1
        c_ulong,                 # TargetDataRep
        POINTER(SecBufferDesc),  # pInput (None on first call)
        c_ulong,                 # Reserved2
        POINTER(SecHandle),      # phNewContext
        POINTER(SecBufferDesc),  # pOutput
        POINTER(c_ulong),        # pfContextAttr
        POINTER(TimeStamp),      # ptsExpiry
    ]
    secur32.InitializeSecurityContextW.restype = ctypes.wintypes.LONG

    # FreeCredentialsHandle
    secur32.FreeCredentialsHandle.argtypes = [POINTER(SecHandle)]
    secur32.FreeCredentialsHandle.restype = ctypes.wintypes.LONG

    # DeleteSecurityContext
    secur32.DeleteSecurityContext.argtypes = [POINTER(SecHandle)]
    secur32.DeleteSecurityContext.restype = ctypes.wintypes.LONG

    # FreeContextBuffer
    secur32.FreeContextBuffer.argtypes = [c_void_p]
    secur32.FreeContextBuffer.restype = ctypes.wintypes.LONG

    return secur32


class SSPIAuth:
    """SSPI-based NTLM/Negotiate authentication for proxy connections.

    Usage:
        auth = SSPIAuth("Negotiate")
        token1 = auth.get_initial_token("proxy.corp.example.com")
        # Send token1 in Proxy-Authorization header, get challenge back
        token3 = auth.get_response_token("proxy.corp.example.com", challenge_b64)
        # Send token3 in Proxy-Authorization header
        auth.close()
    """

    def __init__(self, scheme: str = "Negotiate"):
        if sys.platform != "win32":
            raise RuntimeError("SSPIAuth is only available on Windows")

        self._scheme = scheme
        self._secur32 = _load_secur32()
        self._cred_handle = SecHandle()
        self._ctx_handle = SecHandle()
        self._have_ctx = False
        self._closed = False

        # Acquire credentials for the current user
        expiry = TimeStamp()
        status = self._secur32.AcquireCredentialsHandleW(
            None,                    # principal (None = current user)
            self._scheme,            # package name ("Negotiate" or "NTLM")
            SECPKG_CRED_OUTBOUND,    # client credentials
            None,                    # logon id
            None,                    # auth data (None = current session)
            None,                    # get key fn
            None,                    # get key arg
            byref(self._cred_handle),
            byref(expiry),
        )
        if status != SEC_E_OK:
            raise RuntimeError(
                f"AcquireCredentialsHandleW failed for {scheme}: "
                f"0x{status & 0xFFFFFFFF:08X}"
            )

    def get_initial_token(self, target: str) -> str:
        """Generate the initial (Type 1) authentication token.

        Args:
            target: The SPN or proxy hostname (e.g. "HTTP/proxy.corp.example.com")

        Returns:
            Base64-encoded token for the Proxy-Authorization header.
        """
        return self._call_isc(target, None)

    def get_response_token(self, target: str, challenge_b64: str) -> str:
        """Generate a response (Type 3) token from a server challenge.

        Args:
            target: The SPN or proxy hostname
            challenge_b64: Base64-encoded challenge from the Proxy-Authenticate header

        Returns:
            Base64-encoded response token for the Proxy-Authorization header.
        """
        return self._call_isc(target, challenge_b64)

    def _call_isc(self, target: str, input_token_b64: str | None) -> str:
        """Call InitializeSecurityContextW and return the output token."""
        # Prepare output buffer
        out_buf = SecBuffer()
        out_buf.cbBuffer = MAX_TOKEN_SIZE
        out_buf_data = ctypes.create_string_buffer(MAX_TOKEN_SIZE)
        out_buf.pvBuffer = ctypes.cast(out_buf_data, c_void_p)
        out_buf.BufferType = SECBUFFER_TOKEN

        out_desc = SecBufferDesc()
        out_desc.ulVersion = 0
        out_desc.cBuffers = 1
        out_desc.pBuffers = ctypes.pointer(out_buf)

        # Prepare input buffer if we have a challenge
        in_desc_ptr = None
        if input_token_b64 is not None:
            in_data = base64.b64decode(input_token_b64)
            in_buf = SecBuffer()
            in_buf.cbBuffer = len(in_data)
            in_buf_data = ctypes.create_string_buffer(in_data)
            in_buf.pvBuffer = ctypes.cast(in_buf_data, c_void_p)
            in_buf.BufferType = SECBUFFER_TOKEN

            in_desc = SecBufferDesc()
            in_desc.ulVersion = 0
            in_desc.cBuffers = 1
            in_desc.pBuffers = ctypes.pointer(in_buf)
            in_desc_ptr = byref(in_desc)

        ctx_attr = c_ulong()
        expiry = TimeStamp()
        new_ctx = SecHandle()

        # On the first call, phContext is None; on subsequent calls, use existing context
        ctx_ptr = byref(self._ctx_handle) if self._have_ctx else None

        status = self._secur32.InitializeSecurityContextW(
            byref(self._cred_handle),
            ctx_ptr,
            target,
            ISC_REQ_FLAGS,
            0,                         # Reserved1
            SECURITY_NATIVE_DREP,
            in_desc_ptr,
            0,                         # Reserved2
            byref(new_ctx),
            byref(out_desc),
            byref(ctx_attr),
            byref(expiry),
        )

        if status not in (SEC_E_OK, SEC_I_CONTINUE_NEEDED,
                          SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED):
            raise RuntimeError(
                f"InitializeSecurityContextW failed: 0x{status & 0xFFFFFFFF:08X}"
            )

        # Save context handle for next call
        self._ctx_handle = new_ctx
        self._have_ctx = True

        # Extract output token
        token_bytes = ctypes.string_at(out_buf.pvBuffer, out_buf.cbBuffer)
        return base64.b64encode(token_bytes).decode("ascii")

    def close(self) -> None:
        """Release SSPI handles."""
        if self._closed:
            return
        self._closed = True

        if self._have_ctx:
            try:
                self._secur32.DeleteSecurityContext(byref(self._ctx_handle))
            except Exception:
                pass

        try:
            self._secur32.FreeCredentialsHandle(byref(self._cred_handle))
        except Exception:
            pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
