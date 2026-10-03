"""Real signature validation tests for shared_auth.validate.

Tests RSA signature verification, key rotation, and allowlists.
"""

import base64
import hashlib
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from shared_auth.validate import (
    ARM_AUDIENCE,
    TokenValidationError,
    validate_arm_token,
)

VALID_TENANT = "11111111-1111-1111-1111-111111111111"


def _generate_rsa_keypair():
    """Generate an RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def _key_to_jwk(public_key, kid: str) -> dict:
    """Convert an RSA public key to JWK format."""
    numbers = public_key.public_numbers()

    def int_to_b64(n: int) -> str:
        # Convert int to bytes (big-endian)
        byte_length = (n.bit_length() + 7) // 8
        n_bytes = n.to_bytes(byte_length, byteorder='big')
        # Base64url encode without padding
        return base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('ascii')

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_b64(numbers.n),
        "e": int_to_b64(numbers.e),
    }


def _sign_jwt(private_key, header: dict, payload: dict) -> str:
    """Sign a JWT with an RSA private key."""
    def b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())

    message = f"{header_b64}.{payload_b64}".encode('utf-8')

    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    signature_b64 = b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _make_valid_claims(
    tenant: str = VALID_TENANT,
    upn: str = "user@example.com",
    oid: str | None = None,
    groups: list[str] | None = None,
    **overrides,
) -> dict:
    """Build a valid claims dict."""
    claims = {
        "tid": tenant,
        "iss": f"https://login.microsoftonline.com/{tenant}/v2.0",
        "aud": ARM_AUDIENCE,
        "exp": int(time.time()) + 3600,
        "upn": upn,
    }
    if oid:
        claims["oid"] = oid
    if groups:
        claims["groups"] = groups
    claims.update(overrides)
    return claims


@pytest.fixture
def reset_caches(monkeypatch):
    """Reset all module-level caches before each test."""
    import shared_auth.validate as mod
    monkeypatch.setattr(mod, "_allowed_tenants_cache", None)
    monkeypatch.setattr(mod, "_allowed_users_cache", None)
    monkeypatch.setattr(mod, "_allowed_groups_cache", None)
    monkeypatch.setattr(mod, "_jwks_cache", {})
    monkeypatch.setenv("NETBRIDGE_ALLOWED_TENANTS", VALID_TENANT)


@pytest.mark.asyncio
async def test_valid_rs256_signature(reset_caches):
    """Valid RS256 signature should extract user identity."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "test-key-1"
    jwk = _key_to_jwk(public_key, kid)

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = _make_valid_claims(upn="alice@example.com")
    token = _sign_jwt(private_key, header, claims)

    # Mock _get_jwks to return our test JWKS
    jwks = {"keys": [jwk]}
    with patch("shared_auth.validate._get_jwks", return_value=jwks):
        user = await validate_arm_token(token)

    assert user == "alice@example.com"


@pytest.mark.asyncio
async def test_bad_signature_rejected(reset_caches):
    """Token with tampered signature should be rejected."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "test-key-1"
    jwk = _key_to_jwk(public_key, kid)

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = _make_valid_claims()
    token = _sign_jwt(private_key, header, claims)

    # Tamper with the signature
    parts = token.split('.')
    parts[2] = "tampered_signature"
    bad_token = '.'.join(parts)

    jwks = {"keys": [jwk]}
    with patch("shared_auth.validate._get_jwks", return_value=jwks):
        with pytest.raises(TokenValidationError, match="Signature verification failed"):
            await validate_arm_token(bad_token)


@pytest.mark.asyncio
async def test_unknown_kid_refetches_once(reset_caches):
    """Unknown kid should trigger exactly one cache refresh."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "new-key"
    jwk = _key_to_jwk(public_key, kid)

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = _make_valid_claims()
    token = _sign_jwt(private_key, header, claims)

    fetch_count = [0]

    async def fake_get_jwks(tenant_id):
        fetch_count[0] += 1
        if fetch_count[0] == 1:
            # First fetch: return empty keys (simulate cache miss)
            return {"keys": []}
        else:
            # Second fetch: return the key
            return {"keys": [jwk]}

    with patch("shared_auth.validate._get_jwks", side_effect=fake_get_jwks):
        user = await validate_arm_token(token)

    assert user == "user@example.com"
    assert fetch_count[0] == 2  # Exactly one refetch


@pytest.mark.asyncio
async def test_unknown_kid_still_not_found_after_refetch(reset_caches):
    """Unknown kid that's still missing after refetch should raise."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "unknown-key"

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = _make_valid_claims()
    token = _sign_jwt(private_key, header, claims)

    # Always return empty keys
    with patch("shared_auth.validate._get_jwks", return_value={"keys": []}):
        with pytest.raises(TokenValidationError, match="Signing key not found"):
            await validate_arm_token(token)


@pytest.mark.asyncio
async def test_key_rotation_via_real_get_jwks(reset_caches):
    """Key rotation: new kid triggers fetch, old kid rejected."""
    # Generate two key pairs
    private_a, public_a = _generate_rsa_keypair()
    private_b, public_b = _generate_rsa_keypair()

    kid_a, kid_b = "key-a", "key-b"
    jwk_a = _key_to_jwk(public_a, kid_a)
    jwk_b = _key_to_jwk(public_b, kid_b)

    # HTTP server state
    current_jwks = {"keys": [jwk_a]}
    requests = []

    class JWKSHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(current_jwks).encode())

        def log_message(self, format, *args):
            pass  # Suppress server logs

    # Start loopback HTTP server
    server = ThreadingHTTPServer(('127.0.0.1', 0), JWKSHandler)
    port = server.server_address[1]
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Patch only _get_jwks_url to point to our local server
        url = f"http://127.0.0.1:{port}/keys"

        # Token signed with key A
        header_a = {"alg": "RS256", "typ": "JWT", "kid": kid_a}
        claims_a = _make_valid_claims(upn="user-a@example.com")
        token_a = _sign_jwt(private_a, header_a, claims_a)

        with patch("shared_auth.validate._get_jwks_url", return_value=url):
            # First token: should fetch JWKS once
            user_a = await validate_arm_token(token_a)
            assert user_a == "user-a@example.com"
            assert len(requests) == 1

            # Switch server to key B
            current_jwks = {"keys": [jwk_b]}

            # Token signed with key B
            header_b = {"alg": "RS256", "typ": "JWT", "kid": kid_b}
            claims_b = _make_valid_claims(upn="user-b@example.com")
            token_b = _sign_jwt(private_b, header_b, claims_b)

            # Second token: kid not in cache, should fetch again
            user_b = await validate_arm_token(token_b)
            assert user_b == "user-b@example.com"
            assert len(requests) == 2  # Initial fetch + refetch on unknown kid

            # Token A should now fail (key no longer served)
            with pytest.raises(TokenValidationError, match="Signing key not found"):
                await validate_arm_token(token_a)
            assert len(requests) == 3  # one refetch for the unknown kid, then give up

    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.asyncio
async def test_key_with_wrong_alg_rejected(reset_caches):
    """Key with alg != RS256 should be rejected."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "test-key-1"
    jwk = _key_to_jwk(public_key, kid)
    jwk["alg"] = "HS256"  # Wrong algorithm

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = _make_valid_claims()
    token = _sign_jwt(private_key, header, claims)

    jwks = {"keys": [jwk]}
    with patch("shared_auth.validate._get_jwks", return_value=jwks):
        with pytest.raises(TokenValidationError, match="Unsupported algorithm"):
            await validate_arm_token(token)


@pytest.mark.asyncio
async def test_missing_identity_rejected(reset_caches):
    """Token without user identity fields should be rejected."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "test-key-1"
    jwk = _key_to_jwk(public_key, kid)

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    # Claims without upn, unique_name, preferred_username, or email
    claims = _make_valid_claims()
    del claims["upn"]
    token = _sign_jwt(private_key, header, claims)

    jwks = {"keys": [jwk]}
    with patch("shared_auth.validate._get_jwks", return_value=jwks):
        with pytest.raises(TokenValidationError, match="No user identity"):
            await validate_arm_token(token)


@pytest.mark.asyncio
async def test_allowed_users_by_upn(reset_caches, monkeypatch):
    """NETBRIDGE_ALLOWED_USERS with UPN should allow/deny."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "test-key-1"
    jwk = _key_to_jwk(public_key, kid)

    monkeypatch.setenv("NETBRIDGE_ALLOWED_USERS", "alice@example.com,bob@example.com")

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}

    # Alice should be allowed
    claims_alice = _make_valid_claims(upn="alice@example.com")
    token_alice = _sign_jwt(private_key, header, claims_alice)

    jwks = {"keys": [jwk]}
    with patch("shared_auth.validate._get_jwks", return_value=jwks):
        user = await validate_arm_token(token_alice)
        assert user == "alice@example.com"

    # Charlie should be denied
    claims_charlie = _make_valid_claims(upn="charlie@example.com")
    token_charlie = _sign_jwt(private_key, header, claims_charlie)

    # Reset cache after setting env var
    import shared_auth.validate as mod
    monkeypatch.setattr(mod, "_jwks_cache", {})

    with patch("shared_auth.validate._get_jwks", return_value=jwks):
        with pytest.raises(TokenValidationError, match="not in the allowed users list"):
            await validate_arm_token(token_charlie)


@pytest.mark.asyncio
async def test_allowed_users_by_oid(reset_caches, monkeypatch):
    """NETBRIDGE_ALLOWED_USERS with OID should allow/deny."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "test-key-1"
    jwk = _key_to_jwk(public_key, kid)

    allowed_oid = "oid-123"
    monkeypatch.setenv("NETBRIDGE_ALLOWED_USERS", allowed_oid)

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = _make_valid_claims(upn="user@example.com", oid=allowed_oid)
    token = _sign_jwt(private_key, header, claims)

    jwks = {"keys": [jwk]}
    with patch("shared_auth.validate._get_jwks", return_value=jwks):
        user = await validate_arm_token(token)
        assert user == "user@example.com"

        other = _sign_jwt(private_key, header, _make_valid_claims(upn="user@example.com", oid="oid-999"))
        with pytest.raises(TokenValidationError, match="not in the allowed users list"):
            await validate_arm_token(other)


@pytest.mark.asyncio
async def test_allowed_groups_allow(reset_caches, monkeypatch):
    """NETBRIDGE_ALLOWED_GROUPS should allow matching group."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "test-key-1"
    jwk = _key_to_jwk(public_key, kid)

    group_a = "group-aaa"
    group_b = "group-bbb"
    monkeypatch.setenv("NETBRIDGE_ALLOWED_GROUPS", f"{group_a},{group_b}")

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = _make_valid_claims(upn="user@example.com", groups=[group_a, "other-group"])
    token = _sign_jwt(private_key, header, claims)

    jwks = {"keys": [jwk]}
    with patch("shared_auth.validate._get_jwks", return_value=jwks):
        user = await validate_arm_token(token)
        assert user == "user@example.com"


@pytest.mark.asyncio
async def test_allowed_groups_deny(reset_caches, monkeypatch):
    """NETBRIDGE_ALLOWED_GROUPS should deny when no matching group."""
    private_key, public_key = _generate_rsa_keypair()
    kid = "test-key-1"
    jwk = _key_to_jwk(public_key, kid)

    monkeypatch.setenv("NETBRIDGE_ALLOWED_GROUPS", "group-aaa,group-bbb")

    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = _make_valid_claims(upn="user@example.com", groups=["other-group"])
    token = _sign_jwt(private_key, header, claims)

    # Reset cache
    import shared_auth.validate as mod
    monkeypatch.setattr(mod, "_jwks_cache", {})

    jwks = {"keys": [jwk]}
    with patch("shared_auth.validate._get_jwks", return_value=jwks):
        with pytest.raises(TokenValidationError, match="not a member of any allowed group"):
            await validate_arm_token(token)
