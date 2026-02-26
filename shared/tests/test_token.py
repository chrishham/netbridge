"""Tests for shared_auth.token — JWT decoding, Azure CLI helpers, and token management."""

import base64
import json
import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest

from shared_auth.token import (
    _az_command,
    check_az_login,
    check_token_expiration,
    decode_jwt_payload,
    get_arm_token,
    get_token_remaining_seconds,
    get_user_identity,
    AZ_CLI_TIMEOUT,
)


def _make_jwt(payload: dict) -> str:
    """Build a minimal JWT with the given payload (header and signature are filler)."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.sig"


# ---------------------------------------------------------------------------
# decode_jwt_payload
# ---------------------------------------------------------------------------
class TestDecodeJwtPayload:
    """Tests for decode_jwt_payload()."""

    def test_valid_jwt(self):
        """A properly-formed JWT is decoded to its payload dict."""
        token = _make_jwt({"sub": "alice", "exp": 9999999999})
        result = decode_jwt_payload(token)
        assert result["sub"] == "alice"
        assert result["exp"] == 9999999999

    def test_missing_parts(self):
        """A token without three dot-separated parts raises ValueError."""
        with pytest.raises(ValueError, match="Invalid JWT format"):
            decode_jwt_payload("only.two")

    def test_too_many_parts(self):
        """Extra dots still fail (only exactly 3 parts accepted)."""
        with pytest.raises(ValueError, match="Invalid JWT format"):
            decode_jwt_payload("a.b.c.d")

    def test_invalid_base64(self):
        """Non-base64 payload raises ValueError."""
        with pytest.raises(ValueError, match="Failed to decode JWT"):
            decode_jwt_payload("hdr.!!!invalid!!!.sig")

    def test_non_json_payload(self):
        """Valid base64 but non-JSON payload raises ValueError."""
        body = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
        with pytest.raises(ValueError, match="Failed to decode JWT"):
            decode_jwt_payload(f"hdr.{body}.sig")


# ---------------------------------------------------------------------------
# check_token_expiration
# ---------------------------------------------------------------------------
class TestCheckTokenExpiration:
    """Tests for check_token_expiration()."""

    def test_valid_token(self):
        """Token with sufficient remaining validity returns (True, message)."""
        token = _make_jwt({"exp": time.time() + 3600})
        is_valid, msg = check_token_expiration(token)
        assert is_valid is True
        assert "valid" in msg.lower()

    def test_expired_seconds_ago(self):
        """Token that expired seconds ago shows seconds in message."""
        token = _make_jwt({"exp": time.time() - 30})
        is_valid, msg = check_token_expiration(token)
        assert is_valid is False
        assert "seconds ago" in msg

    def test_expired_minutes_ago(self):
        """Token that expired minutes ago shows minutes in message."""
        token = _make_jwt({"exp": time.time() - 300})
        is_valid, msg = check_token_expiration(token)
        assert is_valid is False
        assert "minutes ago" in msg

    def test_expired_hours_ago(self):
        """Token that expired hours ago shows hours in message."""
        token = _make_jwt({"exp": time.time() - 7200})
        is_valid, msg = check_token_expiration(token)
        assert is_valid is False
        assert "hours ago" in msg

    def test_about_to_expire(self):
        """Token expiring within min_validity_seconds is invalid."""
        token = _make_jwt({"exp": time.time() + 60})
        is_valid, msg = check_token_expiration(token, min_validity_seconds=300)
        assert is_valid is False
        assert "expires in" in msg.lower()

    def test_no_exp_claim(self):
        """Token without exp claim is invalid."""
        token = _make_jwt({"sub": "alice"})
        is_valid, msg = check_token_expiration(token)
        assert is_valid is False
        assert "no expiration" in msg.lower()

    def test_invalid_jwt(self):
        """Garbage token returns (False, error message)."""
        is_valid, msg = check_token_expiration("not-a-jwt")
        assert is_valid is False
        assert msg  # some error message


# ---------------------------------------------------------------------------
# get_token_remaining_seconds
# ---------------------------------------------------------------------------
class TestGetTokenRemainingSeconds:
    """Tests for get_token_remaining_seconds()."""

    def test_valid_token(self):
        """Returns positive seconds for a future-expiring token."""
        token = _make_jwt({"exp": time.time() + 600})
        remaining = get_token_remaining_seconds(token)
        assert remaining is not None
        assert remaining > 500

    def test_expired_token(self):
        """Returns negative seconds for an expired token."""
        token = _make_jwt({"exp": time.time() - 100})
        remaining = get_token_remaining_seconds(token)
        assert remaining is not None
        assert remaining < 0

    def test_no_exp(self):
        """Returns None when exp claim is missing."""
        token = _make_jwt({"sub": "bob"})
        assert get_token_remaining_seconds(token) is None

    def test_invalid_jwt(self):
        """Returns None for an invalid JWT."""
        assert get_token_remaining_seconds("garbage") is None


# ---------------------------------------------------------------------------
# _az_command
# ---------------------------------------------------------------------------
class TestAzCommand:
    """Tests for _az_command() — Azure CLI path resolution."""

    @patch("shared_auth.token.shutil.which", return_value="/usr/bin/az")
    @patch("shared_auth.token.sys")
    def test_linux_found(self, mock_sys, mock_which):
        """On Linux, returns the which-resolved path."""
        mock_sys.platform = "linux"
        assert _az_command() == ["/usr/bin/az"]

    @patch("shared_auth.token.shutil.which", return_value=None)
    @patch("shared_auth.token.sys")
    def test_linux_fallback(self, mock_sys, mock_which):
        """When which returns None on Linux, falls back to bare 'az'."""
        mock_sys.platform = "linux"
        assert _az_command() == ["az"]

    @patch("shared_auth.token.shutil.which")
    @patch("shared_auth.token.sys")
    def test_windows_az_cmd(self, mock_sys, mock_which):
        """On Windows, tries az.cmd first."""
        mock_sys.platform = "win32"
        mock_which.side_effect = lambda name: r"C:\CLI\az.cmd" if name == "az.cmd" else None
        assert _az_command() == [r"C:\CLI\az.cmd"]

    @patch("shared_auth.token.shutil.which", return_value=None)
    @patch("shared_auth.token.os.access", return_value=True)
    @patch("shared_auth.token.os.path.isfile", return_value=True)
    @patch("shared_auth.token.sys")
    def test_macos_homebrew_fallback(self, mock_sys, mock_isfile, mock_access, mock_which):
        """On macOS when which fails, tries Homebrew paths."""
        mock_sys.platform = "darwin"
        assert _az_command() == ["/opt/homebrew/bin/az"]


# ---------------------------------------------------------------------------
# get_arm_token
# ---------------------------------------------------------------------------
class TestGetArmToken:
    """Tests for get_arm_token()."""

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_success(self, mock_run, _mock_cmd):
        """Successful az CLI invocation returns the accessToken."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"accessToken": "tok123"}),
            returncode=0,
        )
        assert get_arm_token() == "tok123"

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="az", timeout=30))
    def test_timeout(self, mock_run, _mock_cmd):
        """TimeoutExpired is translated to RuntimeError."""
        with pytest.raises(RuntimeError, match="timed out"):
            get_arm_token()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run", side_effect=FileNotFoundError)
    def test_not_found(self, mock_run, _mock_cmd):
        """FileNotFoundError is translated to RuntimeError about installing az."""
        with pytest.raises(RuntimeError, match="not found"):
            get_arm_token()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_not_logged_in(self, mock_run, _mock_cmd):
        """CalledProcessError with 'az login' in stderr raises appropriate error."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "az", stderr="Please run 'az login' to setup account."
        )
        with pytest.raises(RuntimeError, match="Not logged in"):
            get_arm_token()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_refresh_token_expired(self, mock_run, _mock_cmd):
        """Expired refresh token error is detected."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "az", stderr="AADSTS700082: The refresh token has expired."
        )
        with pytest.raises(RuntimeError, match="expired"):
            get_arm_token()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_dns_error(self, mock_run, _mock_cmd):
        """Name resolution failure maps to clean error."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "az", stderr="Name resolution failed: getaddrinfo ENOTFOUND"
        )
        with pytest.raises(RuntimeError, match="DNS resolution failed"):
            get_arm_token()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_ssl_error(self, mock_run, _mock_cmd):
        """SSL certificate errors map to clean error."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "az", stderr="SSL: CERTIFICATE_VERIFY_FAILED"
        )
        with pytest.raises(RuntimeError, match="SSL"):
            get_arm_token()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_connection_refused(self, mock_run, _mock_cmd):
        """Connection refused maps to clean error."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "az", stderr="Connection refused by server"
        )
        with pytest.raises(RuntimeError, match="Connection failed"):
            get_arm_token()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_json_parse_error(self, mock_run, _mock_cmd):
        """Invalid JSON output raises RuntimeError."""
        mock_run.return_value = MagicMock(stdout="not json", returncode=0)
        with pytest.raises(RuntimeError, match="parse"):
            get_arm_token()


# ---------------------------------------------------------------------------
# get_user_identity
# ---------------------------------------------------------------------------
class TestGetUserIdentity:
    """Tests for get_user_identity()."""

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_success(self, mock_run, _mock_cmd):
        """Returns user name on success."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"user": {"name": "alice@example.com"}}),
            returncode=0,
        )
        assert get_user_identity() == "alice@example.com"

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run", side_effect=Exception("fail"))
    def test_failure_returns_none(self, mock_run, _mock_cmd):
        """Returns None on any exception."""
        assert get_user_identity() is None


# ---------------------------------------------------------------------------
# check_az_login
# ---------------------------------------------------------------------------
class TestCheckAzLogin:
    """Tests for check_az_login()."""

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_logged_in(self, mock_run, _mock_cmd):
        """Successful account show returns (True, message with user)."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "user": {"name": "alice@example.com"},
                "tenantId": "12345678-1234-1234-1234-123456789012",
            }),
        )
        ok, msg = check_az_login()
        assert ok is True
        assert "alice@example.com" in msg

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_not_logged_in(self, mock_run, _mock_cmd):
        """Non-zero return with generic stderr returns (False, login message)."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="Some error",
        )
        ok, msg = check_az_login()
        assert ok is False
        assert "not logged in" in msg.lower()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="az", timeout=30))
    def test_timeout(self, mock_run, _mock_cmd):
        """Timeout returns (False, timeout message)."""
        ok, msg = check_az_login()
        assert ok is False
        assert "timed out" in msg.lower()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run", side_effect=FileNotFoundError)
    def test_not_found(self, mock_run, _mock_cmd):
        """Missing az CLI returns (False, install message)."""
        ok, msg = check_az_login()
        assert ok is False
        assert "not found" in msg.lower()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_expired_session(self, mock_run, _mock_cmd):
        """Expired refresh token is detected in stderr."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="AADSTS700082: The refresh token has expired.",
        )
        ok, msg = check_az_login()
        assert ok is False
        assert "expired" in msg.lower()

    @patch("shared_auth.token._az_command", return_value=["az"])
    @patch("shared_auth.token.subprocess.run")
    def test_network_error(self, mock_run, _mock_cmd):
        """DNS / network errors are detected."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="Name resolution failed",
        )
        ok, msg = check_az_login()
        assert ok is False
        assert "dns" in msg.lower() or "network" in msg.lower()
