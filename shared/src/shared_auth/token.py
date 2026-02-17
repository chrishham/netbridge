"""
ARM Token acquisition using Azure CLI credentials.

Uses the user's existing `az login` session - no app registration needed.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import time
from typing import Optional


# Azure Resource Manager endpoint - any az login user can get tokens for this
ARM_RESOURCE = "https://management.azure.com"

# Timeout for az CLI commands (seconds)
AZ_CLI_TIMEOUT = 30

# Minimum token validity required (seconds) - refresh if less than this remaining
MIN_TOKEN_VALIDITY = 300  # 5 minutes


def _az_command() -> list[str]:
    """Return the base command list for invoking the Azure CLI.

    On Windows, ``az`` is typically installed as ``az.cmd`` which requires
    ``shell=True`` when passed as a bare string.  Instead, we resolve the
    full path via ``shutil.which`` so we can call it directly without a
    shell, avoiding command-injection risks (CWE-78).

    On macOS, when running as a launchd service (e.g. ``brew services``),
    the PATH is minimal and won't include Homebrew's bin directory, so we
    also check common Homebrew install locations as a fallback.
    """
    if sys.platform == "win32":
        candidates = ("az.cmd", "az")
    else:
        candidates = ("az",)

    for name in candidates:
        path = shutil.which(name)
        if path:
            return [path]

    # Fallback: check common Homebrew locations on macOS
    if sys.platform == "darwin":
        for candidate in ("/opt/homebrew/bin/az", "/usr/local/bin/az"):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return [candidate]

    return ["az"]


def decode_jwt_payload(token: str) -> dict:
    """
    Decode the payload of a JWT token without verification.

    Args:
        token: The JWT token string.

    Returns:
        The decoded payload as a dictionary.

    Raises:
        ValueError: If the token format is invalid.
    """
    try:
        # JWT format: header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        # Decode payload (add padding if needed)
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except Exception as e:
        raise ValueError(f"Failed to decode JWT: {e}")


def check_token_expiration(token: str, min_validity_seconds: int = MIN_TOKEN_VALIDITY) -> tuple[bool, str]:
    """
    Check if a token is expired or about to expire.

    Args:
        token: The JWT token string.
        min_validity_seconds: Minimum remaining validity required (default 5 minutes).

    Returns:
        Tuple of (is_valid, message).
    """
    try:
        payload = decode_jwt_payload(token)
        exp = payload.get("exp")
        if not exp:
            return False, "Token has no expiration claim"

        now = time.time()
        remaining = exp - now

        if remaining <= 0:
            expired_ago = int(-remaining)
            if expired_ago < 60:
                return False, f"Token expired {expired_ago} seconds ago"
            elif expired_ago < 3600:
                return False, f"Token expired {expired_ago // 60} minutes ago"
            else:
                return False, f"Token expired {expired_ago // 3600} hours ago"

        if remaining < min_validity_seconds:
            return False, f"Token expires in {int(remaining)} seconds (minimum {min_validity_seconds}s required)"

        return True, f"Token valid for {int(remaining // 60)} more minutes"
    except ValueError as e:
        return False, str(e)


def get_token_remaining_seconds(token: str) -> Optional[float]:
    """
    Get the remaining validity of a token in seconds.

    Args:
        token: The JWT token string.

    Returns:
        Remaining seconds until expiration, or None if token is invalid.
    """
    try:
        payload = decode_jwt_payload(token)
        exp = payload.get("exp")
        if not exp:
            return None
        return exp - time.time()
    except ValueError:
        return None


def get_arm_token() -> str:
    """
    Get an ARM access token using Azure CLI credentials.

    Requires the user to have run `az login` beforehand.

    Returns:
        The access token string.

    Raises:
        RuntimeError: If az cli is not installed or user not logged in.
    """
    try:
        result = subprocess.run(
            _az_command() + ["account", "get-access-token", "--resource", ARM_RESOURCE],
            capture_output=True,
            text=True,
            check=True,
            timeout=AZ_CLI_TIMEOUT,
        )
        data = json.loads(result.stdout)
        return data["accessToken"]

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Azure CLI timed out after {AZ_CLI_TIMEOUT}s. "
            "The az command may be stuck. Try running 'az account show' manually."
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Azure CLI (az) not found. Install it from: "
            "https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        )
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else ""
        stderr_lower = stderr.lower()
        if "az login" in stderr_lower or "not logged in" in stderr_lower:
            # Include first line of actual error for debugging
            first_line = stderr.split('\n')[0] if stderr else ""
            if first_line and len(first_line) < 150:
                raise RuntimeError(
                    f"Not logged in to Azure CLI. Run 'az login' first. ({first_line})"
                )
            raise RuntimeError(
                "Not logged in to Azure CLI. Run 'az login' first."
            )
        if "refresh token" in stderr_lower or "expired" in stderr_lower:
            raise RuntimeError(
                "Azure login session expired. Run 'az login' to re-authenticate."
            )
        if "interactive" in stderr_lower:
            raise RuntimeError(
                "Azure CLI requires interactive login. Run 'az login' in a terminal."
            )
        # Network/DNS errors - provide clean message instead of huge traceback
        if "name resolution" in stderr_lower or "getaddrinfo" in stderr_lower:
            raise RuntimeError(
                "DNS resolution failed. Check your network connection."
            )
        if "connection" in stderr_lower and ("refused" in stderr_lower or "reset" in stderr_lower):
            raise RuntimeError(
                "Connection failed. Check your network/firewall."
            )
        if "timeout" in stderr_lower or "timed out" in stderr_lower:
            raise RuntimeError(
                "Connection timed out. Network may be slow or unreachable."
            )
        if "ssl" in stderr_lower or "certificate" in stderr_lower:
            raise RuntimeError(
                "SSL/TLS error. Check proxy settings or network security."
            )
        if "max retries" in stderr_lower:
            raise RuntimeError(
                "Network error (max retries exceeded). Check your connection."
            )
        # For other errors, extract just the first meaningful line
        first_line = stderr.split('\n')[0] if stderr else "Unknown error"
        if len(first_line) > 200:
            first_line = first_line[:200] + "..."
        raise RuntimeError(f"Failed to get access token: {first_line}")
    except (json.JSONDecodeError, KeyError) as e:
        raise RuntimeError(f"Failed to parse az cli output: {e}")


def get_user_identity() -> Optional[str]:
    """
    Get the current user's identity (email/UPN) from Azure CLI.

    Returns:
        User principal name (email) or None if not available.
    """
    try:
        result = subprocess.run(
            _az_command() + ["account", "show"],
            capture_output=True,
            text=True,
            check=True,
            timeout=AZ_CLI_TIMEOUT,
        )
        data = json.loads(result.stdout)
        user = data.get("user", {})
        return user.get("name")
    except Exception:
        return None


def check_az_login() -> tuple[bool, str]:
    """
    Check if user is logged in to Azure CLI.

    Returns:
        Tuple of (is_logged_in, message)
    """
    try:
        result = subprocess.run(
            _az_command() + ["account", "show"],
            capture_output=True,
            text=True,
            timeout=AZ_CLI_TIMEOUT,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            user = data.get("user", {}).get("name", "unknown")
            tenant = data.get("tenantId", "unknown")[:8]
            return True, f"Logged in as {user} (tenant: {tenant}...)"
        else:
            stderr = result.stderr.strip() if result.stderr else ""
            stderr_lower = stderr.lower()
            if "refresh token" in stderr_lower or "expired" in stderr_lower:
                return False, "Azure login session expired. Run 'az login' to re-authenticate."
            # Network/DNS errors
            if "name resolution" in stderr_lower or "getaddrinfo" in stderr_lower:
                return False, "DNS resolution failed. Check your network connection."
            if "max retries" in stderr_lower or "connection" in stderr_lower:
                return False, "Network error. Check your connection."
            return False, "Not logged in. Run 'az login' first."
    except subprocess.TimeoutExpired:
        return False, f"Azure CLI timed out after {AZ_CLI_TIMEOUT}s. Try running 'az account show' manually."
    except FileNotFoundError:
        return False, "Azure CLI not found. Install from https://aka.ms/installazurecli"
    except Exception as e:
        return False, f"Error checking login status: {e}"
