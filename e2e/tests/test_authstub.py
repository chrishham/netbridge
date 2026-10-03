"""Tests for AuthStub and jwtmint."""
import base64
import json
import os
import tempfile
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest
from shared_auth import validate

from netbridge_e2e import jwtmint
from netbridge_e2e.authstub import AuthStub
from netbridge_e2e.stack import TEST_TENANT


def test_jwtmint_constants():
    """jwtmint defines the correct issuer and audience."""
    assert jwtmint.ISSUER_V2 == f"https://login.microsoftonline.com/{{tid}}/v2.0"
    assert jwtmint.AUDIENCE == "https://management.azure.com"


def test_mint_basic_structure():
    """mint produces three base64url segments with documented header/claims."""
    # Generate a test key
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    token = jwtmint.mint(key, "test-kid", TEST_TENANT)

    # Should have three segments
    parts = token.split(".")
    assert len(parts) == 3

    # Decode header (first segment)
    header_data = parts[0]
    # Add padding if needed
    padding = 4 - len(header_data) % 4
    if padding != 4:
        header_data += "=" * padding
    header = json.loads(base64.urlsafe_b64decode(header_data))

    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"
    assert header["kid"] == "test-kid"

    # Decode payload (second segment)
    payload_data = parts[1]
    padding = 4 - len(payload_data) % 4
    if padding != 4:
        payload_data += "=" * padding
    payload = json.loads(base64.urlsafe_b64decode(payload_data))

    assert payload["tid"] == TEST_TENANT
    assert payload["iss"] == f"https://login.microsoftonline.com/{TEST_TENANT}/v2.0"
    assert payload["aud"] == "https://management.azure.com"
    assert payload["upn"] == "e2e@netbridge.test"
    assert "iat" in payload
    assert "nbf" in payload
    assert "exp" in payload

    # exp should be iat + lifetime (default 3600)
    assert payload["exp"] == payload["iat"] + 3600


def test_mint_overrides_replace():
    """Claim overrides replace defaults."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    token = jwtmint.mint(
        key, "test-kid", TEST_TENANT,
        upn="custom@example.com",
        lifetime=7200,
        custom_claim="custom_value"
    )

    parts = token.split(".")
    payload_data = parts[1]
    padding = 4 - len(payload_data) % 4
    if padding != 4:
        payload_data += "=" * padding
    payload = json.loads(base64.urlsafe_b64decode(payload_data))

    assert payload["upn"] == "custom@example.com"
    assert payload["exp"] == payload["iat"] + 7200
    assert payload["custom_claim"] == "custom_value"


def test_mint_none_removes_claim():
    """None value removes a claim."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    token = jwtmint.mint(key, "test-kid", TEST_TENANT, upn=None)

    parts = token.split(".")
    payload_data = parts[1]
    padding = 4 - len(payload_data) % 4
    if padding != 4:
        payload_data += "=" * padding
    payload = json.loads(base64.urlsafe_b64decode(payload_data))

    assert "upn" not in payload


def test_mint_header_override_removes_kid():
    """header={"kid": None} drops kid from header."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    token = jwtmint.mint(key, "test-kid", TEST_TENANT, header={"kid": None})

    parts = token.split(".")
    header_data = parts[0]
    padding = 4 - len(header_data) % 4
    if padding != 4:
        header_data += "=" * padding
    header = json.loads(base64.urlsafe_b64decode(header_data))

    assert "kid" not in header
    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"


def test_authstub_jwks_endpoint():
    """AuthStub.start() serves GET <jwks_url> with JWKS JSON and counts requests."""
    with tempfile.TemporaryDirectory() as work_dir:
        work = Path(work_dir)
        stub = AuthStub(work, TEST_TENANT)

        try:
            stub.start()

            # Verify properties
            assert stub.tenant == TEST_TENANT
            assert stub.kid is not None
            assert stub.jwks_url.startswith("http://127.0.0.1:")
            assert f"/{TEST_TENANT}/discovery/v2.0/keys" in stub.jwks_url

            # Fetch JWKS
            initial_requests = stub.requests()
            response = urllib.request.urlopen(stub.jwks_url)
            assert response.status == 200

            jwks = json.loads(response.read())
            assert "keys" in jwks
            assert len(jwks["keys"]) == 1

            key = jwks["keys"][0]
            assert key["kty"] == "RSA"
            assert key["kid"] == stub.kid
            assert key["use"] == "sig"
            assert key["alg"] == "RS256"
            assert "n" in key
            assert "e" in key

            # Request was counted
            assert stub.requests() == initial_requests + 1

        finally:
            stub.close()


def test_authstub_other_paths_404():
    """Any other path returns 404 and is not counted."""
    with tempfile.TemporaryDirectory() as work_dir:
        work = Path(work_dir)
        stub = AuthStub(work, TEST_TENANT)

        try:
            stub.start()

            initial_requests = stub.requests()

            # Extract base URL
            base_url = stub.jwks_url.rsplit("/", 3)[0]

            # Try various wrong paths
            try:
                urllib.request.urlopen(f"{base_url}/wrong/path")
                assert False, "Should have raised HTTPError"
            except urllib.error.HTTPError as e:
                assert e.code == 404

            try:
                urllib.request.urlopen(f"{base_url}/")
                assert False, "Should have raised HTTPError"
            except urllib.error.HTTPError as e:
                assert e.code == 404

            # Requests not counted
            assert stub.requests() == initial_requests

        finally:
            stub.close()


def test_authstub_key_security():
    """key_path has mode 0600 on POSIX, is not under work, and is gone after close()."""
    with tempfile.TemporaryDirectory() as work_dir:
        work = Path(work_dir)
        stub = AuthStub(work, TEST_TENANT)

        try:
            stub.start()

            # Key path exists
            assert stub.key_path.exists()

            # Not under work directory
            assert not stub.key_path.is_relative_to(work)

            # Mode 0600 on POSIX
            if os.name == "posix":
                stat = stub.key_path.stat()
                mode = stat.st_mode & 0o777
                assert mode == 0o600, f"Expected mode 0600, got {oct(mode)}"

            key_path = stub.key_path

        finally:
            stub.close()

        # Key removed after close
        assert not key_path.exists()


@pytest.mark.asyncio
async def test_authstub_end_to_end_validation():
    """End-to-end: stub tokens verify with shared_auth.validate."""
    with tempfile.TemporaryDirectory() as work_dir:
        work = Path(work_dir)
        stub = AuthStub(work, TEST_TENANT)

        try:
            stub.start()

            # Fetch JWKS from stub
            response = urllib.request.urlopen(stub.jwks_url)
            jwks = json.loads(response.read())

            # Patch _get_jwks to return the stub's JWKS
            with patch.object(validate, "_get_jwks", return_value=jwks):
                # Set allowed tenant
                old_tenants = os.environ.get("NETBRIDGE_ALLOWED_TENANTS")
                os.environ["NETBRIDGE_ALLOWED_TENANTS"] = stub.tenant

                # Reset tenant cache
                validate._allowed_tenants_cache = None

                try:
                    # Valid token should validate and return upn
                    token = stub.mint()
                    user = await validate.validate_arm_token(token)
                    assert user == "e2e@netbridge.test"

                finally:
                    # Restore environment
                    if old_tenants is None:
                        os.environ.pop("NETBRIDGE_ALLOWED_TENANTS", None)
                    else:
                        os.environ["NETBRIDGE_ALLOWED_TENANTS"] = old_tenants
                    validate._allowed_tenants_cache = None

        finally:
            stub.close()


@pytest.mark.asyncio
async def test_authstub_foreign_mint_rejected():
    """foreign_mint() raises TokenValidationError with signature verification failure."""
    with tempfile.TemporaryDirectory() as work_dir:
        work = Path(work_dir)
        stub = AuthStub(work, TEST_TENANT)

        try:
            stub.start()

            # Fetch JWKS from stub
            response = urllib.request.urlopen(stub.jwks_url)
            jwks = json.loads(response.read())

            # Patch _get_jwks to return the stub's JWKS
            with patch.object(validate, "_get_jwks", return_value=jwks):
                # Set allowed tenant
                old_tenants = os.environ.get("NETBRIDGE_ALLOWED_TENANTS")
                os.environ["NETBRIDGE_ALLOWED_TENANTS"] = stub.tenant

                # Reset tenant cache
                validate._allowed_tenants_cache = None

                try:
                    # Foreign token should fail signature verification
                    foreign_token = stub.foreign_mint()

                    with pytest.raises(validate.TokenValidationError) as exc_info:
                        await validate.validate_arm_token(foreign_token)

                    assert "Signature verification failed" in str(exc_info.value)

                finally:
                    # Restore environment
                    if old_tenants is None:
                        os.environ.pop("NETBRIDGE_ALLOWED_TENANTS", None)
                    else:
                        os.environ["NETBRIDGE_ALLOWED_TENANTS"] = old_tenants
                    validate._allowed_tenants_cache = None

        finally:
            stub.close()


def test_authstub_env():
    """AuthStub.env() returns the expected environment dict."""
    with tempfile.TemporaryDirectory() as work_dir:
        work = Path(work_dir)
        stub = AuthStub(work, TEST_TENANT)

        try:
            stub.start()

            env = stub.env()

            assert env["NETBRIDGE_E2E_SIGNING_KEY"] == str(stub.key_path)
            assert env["NETBRIDGE_E2E_KID"] == stub.kid
            assert env["NETBRIDGE_E2E_TENANT"] == stub.tenant

        finally:
            stub.close()
