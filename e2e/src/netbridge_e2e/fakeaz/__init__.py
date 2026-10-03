"""Fake Azure CLI put first on PATH for the binaries under test.

The agent and proxy run their real auth path: `az account show`, then
`az account get-access-token` via a subprocess, then a local check of the
token's `exp` claim. This fake answers both.

When the auth stub env vars (NETBRIDGE_E2E_SIGNING_KEY, NETBRIDGE_E2E_KID,
NETBRIDGE_E2E_TENANT) are set, the fake az mints RS256-signed tokens
compatible with Azure AD token structure. Otherwise, it returns unsigned
tokens for backward compatibility.
"""
import base64
import json
import os
import time
from collections.abc import Mapping
from pathlib import Path

FAKE_AZ_DIR = Path(__file__).resolve().parent / "bin"
ENV_PYTHON = "NETBRIDGE_E2E_PYTHON"
ENV_LOG = "NETBRIDGE_E2E_AZ_LOG"


def env_with_fake_az(
    base: Mapping[str, str],
    python: str,
    log: Path,
    auth_env: dict | None = None
) -> dict[str, str]:
    """Copy of `base` with the fake az first on PATH.

    Args:
        base: Base environment to extend
        python: Python interpreter path for the fake az wrapper
        log: Path to log az commands
        auth_env: Optional auth stub environment (e.g., from AuthStub.env())

    On Windows, preserves SystemRoot, ComSpec, and PATHEXT from the base env.
    """
    env = dict(base)
    env["PATH"] = os.pathsep.join(p for p in (str(FAKE_AZ_DIR), base.get("PATH", "")) if p)
    env[ENV_PYTHON] = python
    env[ENV_LOG] = str(log)
    if auth_env:
        env.update(auth_env)
    return env


def token_seconds_left(token: str) -> float:
    """Seconds until the (unverified) JWT's exp claim."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["exp"] - time.time()
