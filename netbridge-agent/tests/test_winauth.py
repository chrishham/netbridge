"""Tests for netbridge_agent.winauth module.

Since SSPI (secur32.dll) is only available on Windows, these tests focus on:
- Struct binding verification
- SSPIAuth behavior on non-Windows platforms
- Constants and module-level values
"""

import ctypes
import sys
from unittest.mock import MagicMock, patch

import pytest

from netbridge_agent.winauth import (
    ISC_REQ_FLAGS,
    MAX_TOKEN_SIZE,
    SEC_E_OK,
    SEC_I_COMPLETE_AND_CONTINUE,
    SEC_I_COMPLETE_NEEDED,
    SEC_I_CONTINUE_NEEDED,
    SECBUFFER_EMPTY,
    SECBUFFER_TOKEN,
    SECPKG_CRED_OUTBOUND,
    SECURITY_NATIVE_DREP,
    SecBuffer,
    SecBufferDesc,
    SecHandle,
    SSPIAuth,
    TimeStamp,
    verify_bindings,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_sec_e_ok(self):
        assert SEC_E_OK == 0

    def test_sec_i_continue_needed(self):
        assert SEC_I_CONTINUE_NEEDED == 0x00090312

    def test_sec_i_complete_and_continue(self):
        assert SEC_I_COMPLETE_AND_CONTINUE == 0x00090314

    def test_sec_i_complete_needed(self):
        assert SEC_I_COMPLETE_NEEDED == 0x00090313

    def test_secpkg_cred_outbound(self):
        assert SECPKG_CRED_OUTBOUND == 2

    def test_secbuffer_token(self):
        assert SECBUFFER_TOKEN == 2

    def test_secbuffer_empty(self):
        assert SECBUFFER_EMPTY == 0

    def test_security_native_drep(self):
        assert SECURITY_NATIVE_DREP == 0x10

    def test_isc_req_flags_combines_three(self):
        """ISC_REQ_FLAGS should be the OR of CONFIDENTIALITY | ALLOCATE_MEMORY | CONNECTION."""
        assert ISC_REQ_FLAGS == (0x10 | 0x100 | 0x800)

    def test_max_token_size(self):
        assert MAX_TOKEN_SIZE == 48000


# ---------------------------------------------------------------------------
# Struct bindings
# ---------------------------------------------------------------------------


class TestStructBindings:
    def test_verify_bindings_does_not_raise(self):
        """verify_bindings() should complete without error on any platform."""
        verify_bindings()

    def test_sec_handle_fields(self):
        h = SecHandle()
        h.dwLower = 0
        h.dwUpper = 0
        # c_void_p stores 0 as None
        assert h.dwLower is None or h.dwLower == 0

    def test_timestamp_fields(self):
        ts = TimeStamp()
        ts.LowPart = 42
        ts.HighPart = -1
        assert ts.LowPart == 42
        assert ts.HighPart == -1

    def test_sec_buffer_fields(self):
        buf = SecBuffer()
        buf.cbBuffer = 1024
        buf.BufferType = SECBUFFER_TOKEN
        buf.pvBuffer = None
        assert buf.cbBuffer == 1024
        assert buf.BufferType == SECBUFFER_TOKEN

    def test_sec_buffer_desc_fields(self):
        buf = SecBuffer()
        desc = SecBufferDesc()
        desc.ulVersion = 0
        desc.cBuffers = 1
        desc.pBuffers = ctypes.pointer(buf)
        assert desc.cBuffers == 1

    def test_sec_handle_size(self):
        """SecHandle should be two pointer-sized fields."""
        h = SecHandle()
        expected = ctypes.sizeof(ctypes.c_void_p) * 2
        assert ctypes.sizeof(h) == expected


# ---------------------------------------------------------------------------
# SSPIAuth on non-Windows
# ---------------------------------------------------------------------------


class TestSSPIAuthNonWindows:
    @pytest.mark.skipif(sys.platform == "win32", reason="Test for non-Windows only")
    def test_raises_on_non_windows(self):
        """SSPIAuth should raise RuntimeError on non-Windows platforms."""
        with pytest.raises(RuntimeError, match="only available on Windows"):
            SSPIAuth("Negotiate")

    @pytest.mark.skipif(sys.platform == "win32", reason="Test for non-Windows only")
    def test_raises_with_ntlm_scheme(self):
        with pytest.raises(RuntimeError, match="only available on Windows"):
            SSPIAuth("NTLM")


# ---------------------------------------------------------------------------
# SSPIAuth with mocked secur32 (tests internal logic without real DLL)
# ---------------------------------------------------------------------------


class TestSSPIAuthMocked:
    @pytest.mark.skipif(sys.platform == "win32", reason="Mocking tests for non-Windows")
    def test_close_idempotent(self):
        """Calling close() multiple times should not error."""
        with patch("netbridge_agent.winauth.sys") as mock_sys, \
             patch("netbridge_agent.winauth._load_secur32") as mock_load:
            mock_sys.platform = "win32"
            mock_secur32 = MagicMock()
            mock_secur32.AcquireCredentialsHandleW.return_value = SEC_E_OK
            mock_load.return_value = mock_secur32

            auth = SSPIAuth.__new__(SSPIAuth)
            auth._scheme = "Negotiate"
            auth._secur32 = mock_secur32
            auth._cred_handle = SecHandle()
            auth._ctx_handle = SecHandle()
            auth._have_ctx = False
            auth._closed = False

            auth.close()
            auth.close()  # second call should be no-op

            # FreeCredentialsHandle called only once
            assert mock_secur32.FreeCredentialsHandle.call_count == 1

    @pytest.mark.skipif(sys.platform == "win32", reason="Mocking tests for non-Windows")
    def test_close_releases_context_if_created(self):
        """close() should call DeleteSecurityContext when a context exists."""
        mock_secur32 = MagicMock()

        auth = SSPIAuth.__new__(SSPIAuth)
        auth._scheme = "Negotiate"
        auth._secur32 = mock_secur32
        auth._cred_handle = SecHandle()
        auth._ctx_handle = SecHandle()
        auth._have_ctx = True
        auth._closed = False

        auth.close()

        mock_secur32.DeleteSecurityContext.assert_called_once()
        mock_secur32.FreeCredentialsHandle.assert_called_once()

    @pytest.mark.skipif(sys.platform == "win32", reason="Mocking tests for non-Windows")
    def test_close_no_context_skips_delete(self):
        """close() should not call DeleteSecurityContext when no context was created."""
        mock_secur32 = MagicMock()

        auth = SSPIAuth.__new__(SSPIAuth)
        auth._scheme = "Negotiate"
        auth._secur32 = mock_secur32
        auth._cred_handle = SecHandle()
        auth._ctx_handle = SecHandle()
        auth._have_ctx = False
        auth._closed = False

        auth.close()

        mock_secur32.DeleteSecurityContext.assert_not_called()
        mock_secur32.FreeCredentialsHandle.assert_called_once()
