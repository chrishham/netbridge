"""Fake Azure CLI put first on PATH for the binaries under test.

The relay runs with --no-auth and ignores the bearer token, but the agent
and proxy still run their real auth path: `az account show`, then
`az account get-access-token` via a subprocess, then a local check of the
token's `exp` claim. This fake answers both.
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


def env_with_fake_az(base: Mapping[str, str], python: str, log: Path) -> dict[str, str]:
    """Copy of `base` with the fake az first on PATH."""
    env = dict(base)
    env["PATH"] = os.pathsep.join(p for p in (str(FAKE_AZ_DIR), base.get("PATH", "")) if p)
    env[ENV_PYTHON] = python
    env[ENV_LOG] = str(log)
    return env


def token_seconds_left(token: str) -> float:
    """Seconds until the (unverified) JWT's exp claim."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["exp"] - time.time()
