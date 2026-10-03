import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from shared_auth.token import check_token_expiration

from netbridge_e2e import fakeaz, jwtmint
from netbridge_e2e.authstub import AuthStub

AZ_NAME = "az.cmd" if sys.platform == "win32" else "az"


def run_az(env, *args):
    az = shutil.which(AZ_NAME, path=env["PATH"])
    return subprocess.run([az, *args], env=env, capture_output=True, text=True, timeout=30)


def test_fake_az_shadows_a_real_az_on_path(tmp_path):
    real = tmp_path / "real-bin"
    real.mkdir()
    (real / AZ_NAME).write_text("echo real")
    (real / AZ_NAME).chmod(0o755)
    env = fakeaz.env_with_fake_az({**os.environ, "PATH": str(real)}, sys.executable, tmp_path / "calls.log")
    resolved = Path(shutil.which(AZ_NAME, path=env["PATH"])).resolve()
    assert resolved.parent == fakeaz.FAKE_AZ_DIR


def test_account_show_returns_a_user(tmp_path):
    env = fakeaz.env_with_fake_az({**os.environ, "PATH": ""}, sys.executable, tmp_path / "calls.log")
    out = run_az(env, "account", "show")
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout)
    assert data["user"]["name"]
    assert data["tenantId"]


def test_token_is_accepted_by_the_real_expiry_check(tmp_path):
    env = fakeaz.env_with_fake_az({**os.environ, "PATH": ""}, sys.executable, tmp_path / "calls.log")
    out = run_az(env, "account", "get-access-token", "--resource", "https://management.azure.com/")
    assert out.returncode == 0, out.stderr
    token = json.loads(out.stdout)["accessToken"]
    ok, message = check_token_expiration(token)
    assert ok, message
    assert fakeaz.token_seconds_left(token) > 3000


def test_calls_are_logged_and_unknown_commands_fail(tmp_path):
    log = tmp_path / "calls.log"
    env = fakeaz.env_with_fake_az({**os.environ, "PATH": ""}, sys.executable, log)
    run_az(env, "account", "show")
    bad = run_az(env, "login")
    assert bad.returncode == 2
    assert log.read_text().splitlines() == ["account show", "login"]


def test_signed_tokens_when_auth_env_provided(tmp_path):
    """Test that fake az mints signed tokens when auth stub env vars are set."""
    stub = AuthStub(tmp_path)
    stub.start()
    try:
        # Use auth_env parameter to merge stub env
        env = fakeaz.env_with_fake_az(
            {**os.environ, "PATH": ""},
            sys.executable,
            tmp_path / "calls.log",
            auth_env=stub.env()
        )

        # Get access token
        out = run_az(env, "account", "get-access-token", "--resource", "https://management.azure.com/")
        assert out.returncode == 0, out.stderr
        token = json.loads(out.stdout)["accessToken"]

        # Decode and verify token structure
        parts = token.split(".")
        assert len(parts) == 3, "Token should have 3 parts (header.payload.signature)"

        # Decode header
        header_json = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
        header = json.loads(header_json)
        assert header["alg"] == "RS256"
        assert header["typ"] == "JWT"
        assert header["kid"] == stub.kid

        # Decode payload
        payload_json = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        payload = json.loads(payload_json)
        assert payload["tid"] == stub.tenant
        assert payload["iss"] == f"https://login.microsoftonline.com/{stub.tenant}/v2.0"
        assert payload["aud"] == "https://management.azure.com"
        assert payload["upn"] == "e2e@netbridge.test"  # default UPN

        # Verify signature with stub's public key
        public_key = stub._key.public_key()
        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))

        # This should not raise an exception
        public_key.verify(signature, signing_input, padding.PKCS1v15(), SHA256())

        # Verify account show uses the stub tenant
        show_out = run_az(env, "account", "show")
        assert show_out.returncode == 0, show_out.stderr
        account = json.loads(show_out.stdout)
        assert account["tenantId"] == stub.tenant
        assert account["user"]["name"] == "e2e@netbridge.test"

    finally:
        stub.close()


def test_signed_tokens_with_custom_upn(tmp_path):
    """Test that fake az uses NETBRIDGE_E2E_UPN when provided."""
    stub = AuthStub(tmp_path)
    stub.start()
    try:
        custom_upn = "custom@example.com"
        auth_env = {**stub.env(), "NETBRIDGE_E2E_UPN": custom_upn}
        env = fakeaz.env_with_fake_az(
            {**os.environ, "PATH": ""},
            sys.executable,
            tmp_path / "calls.log",
            auth_env=auth_env
        )

        out = run_az(env, "account", "get-access-token", "--resource", "https://management.azure.com/")
        assert out.returncode == 0, out.stderr
        token = json.loads(out.stdout)["accessToken"]

        # Decode payload
        parts = token.split(".")
        payload_json = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        payload = json.loads(payload_json)
        assert payload["upn"] == custom_upn

        # Verify account show also uses custom UPN
        show_out = run_az(env, "account", "show")
        account = json.loads(show_out.stdout)
        assert account["user"]["name"] == custom_upn

    finally:
        stub.close()


def test_unsigned_tokens_without_auth_env(tmp_path):
    """Test backward compatibility: unsigned tokens when auth env vars are not set."""
    env = fakeaz.env_with_fake_az({**os.environ, "PATH": ""}, sys.executable, tmp_path / "calls.log")

    out = run_az(env, "account", "get-access-token", "--resource", "https://management.azure.com/")
    assert out.returncode == 0, out.stderr
    token = json.loads(out.stdout)["accessToken"]

    # Decode header - should be unsigned (alg: none)
    parts = token.split(".")
    header_json = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
    header = json.loads(header_json)
    assert header["alg"] == "none", "Should still use unsigned tokens when auth env not set"

    # Still accepted by expiry check
    ok, message = check_token_expiration(token)
    assert ok, message
