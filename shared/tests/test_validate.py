"""
Tests for shared_auth.validate module.
"""

import base64
import json
import re
import time
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from shared_auth.validate import (
    ARM_AUDIENCE,
    TokenValidationError,
    _decode_jwt_unverified,
    _get_jwks_url,
    _get_valid_issuers,
    get_allowed_tenant_ids,
    validate_arm_token,
)

# --- Helpers ---

VALID_TENANT = "11111111-1111-1111-1111-111111111111"


def _b64_encode(obj: dict) -> str:
    """Base64url-encode a dict as JSON (no padding)."""
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict, sig: str = "fakesig") -> str:
    """Create a fake JWT string from header, payload, and signature."""
    return f"{_b64_encode(header)}.{_b64_encode(payload)}.{sig}"


def _make_valid_claims(
    tenant: str = VALID_TENANT,
    exp_offset: int = 3600,
    **overrides,
) -> dict:
    """Build a valid claims dict that passes all pre-signature checks."""
    claims = {
        "tid": tenant,
        "iss": f"https://sts.windows.net/{tenant}/",
        "aud": ARM_AUDIENCE,
        "exp": int(time.time()) + exp_offset,
        "upn": "user@example.com",
    }
    claims.update(overrides)
    return claims


# --- _decode_jwt_unverified ---


class TestDecodeJwtUnverified:
    def test_valid_jwt(self):
        header = {"alg": "RS256", "kid": "test-key-id"}
        payload = {"sub": "user123", "aud": "api://test"}
        token = _make_jwt(header, payload)

        decoded_header, decoded_payload = _decode_jwt_unverified(token)

        assert decoded_header == header
        assert decoded_payload == payload

    def test_no_dots(self):
        with pytest.raises(TokenValidationError, match="Invalid JWT format"):
            _decode_jwt_unverified("notajwt")

    def test_two_parts(self):
        with pytest.raises(TokenValidationError, match="Invalid JWT format"):
            _decode_jwt_unverified("part1.part2")

    def test_four_parts(self):
        with pytest.raises(TokenValidationError, match="Invalid JWT format"):
            _decode_jwt_unverified("a.b.c.d")


# --- ALLOWED_TENANT_IDS ---


class TestAllowedTenantIds:
    def test_non_empty(self):
        assert len(get_allowed_tenant_ids()) > 0

    def test_valid_uuid_format(self):
        uuid_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        for tid in get_allowed_tenant_ids():
            assert uuid_re.match(tid), f"{tid} is not a valid UUID"


# --- _get_jwks_url ---


class TestGetJwksUrl:
    def test_correct_format(self):
        tid = "test-tenant-id"
        url = _get_jwks_url(tid)
        assert url == f"https://login.microsoftonline.com/{tid}/discovery/v2.0/keys"


# --- _get_valid_issuers ---


class TestGetValidIssuers:
    def test_returns_two_issuers(self):
        tid = "test-tenant-id"
        issuers = _get_valid_issuers(tid)
        assert len(issuers) == 2

    def test_v1_and_v2_urls(self):
        tid = "test-tenant-id"
        v1, v2 = _get_valid_issuers(tid)
        assert v1 == f"https://sts.windows.net/{tid}/"
        assert v2 == f"https://login.microsoftonline.com/{tid}/v2.0"


# --- validate_arm_token ---


class TestValidateArmToken:
    @pytest.mark.asyncio
    async def test_invalid_jwt_too_few_parts(self):
        with pytest.raises(TokenValidationError, match="Invalid JWT format"):
            await validate_arm_token("only-two.parts")

    @pytest.mark.asyncio
    async def test_invalid_jwt_bad_base64(self):
        with pytest.raises(TokenValidationError, match="Token validation failed"):
            await validate_arm_token("not.a.valid-base64-jwt")

    @pytest.mark.asyncio
    async def test_wrong_tenant(self):
        header = {"alg": "RS256", "kid": "k1"}
        claims = _make_valid_claims(tenant="00000000-0000-0000-0000-000000000000")
        token = _make_jwt(header, claims)

        with pytest.raises(TokenValidationError, match="Invalid tenant"):
            await validate_arm_token(token)

    @pytest.mark.asyncio
    async def test_wrong_issuer(self):
        header = {"alg": "RS256", "kid": "k1"}
        claims = _make_valid_claims(iss="https://evil.example.com/")
        token = _make_jwt(header, claims)

        with pytest.raises(TokenValidationError, match="Invalid issuer"):
            await validate_arm_token(token)

    @pytest.mark.asyncio
    async def test_wrong_audience(self):
        header = {"alg": "RS256", "kid": "k1"}
        claims = _make_valid_claims(aud="https://wrong.audience.com")
        token = _make_jwt(header, claims)

        with pytest.raises(TokenValidationError, match="Invalid audience"):
            await validate_arm_token(token)

    @pytest.mark.asyncio
    async def test_expired_token(self):
        header = {"alg": "RS256", "kid": "k1"}
        claims = _make_valid_claims(exp_offset=-3600)  # expired 1 hour ago
        token = _make_jwt(header, claims)

        with pytest.raises(TokenValidationError, match="Token expired"):
            await validate_arm_token(token)

    @pytest.mark.asyncio
    async def test_nbf_not_yet_valid(self):
        """Token with nbf 5 minutes in the future should be rejected."""
        header = {"alg": "RS256", "kid": "k1"}
        claims = _make_valid_claims(nbf=int(time.time()) + 300)
        token = _make_jwt(header, claims)

        with pytest.raises(TokenValidationError, match="Token not yet valid"):
            await validate_arm_token(token)

    @pytest.mark.asyncio
    async def test_nbf_within_skew(self):
        """Token with nbf 30s in the future should pass (within 60s skew)."""
        header = {"alg": "RS256", "kid": "k1"}
        # nbf 30s in the future is within the 60s clock skew allowance
        claims = _make_valid_claims(nbf=int(time.time()) + 30)
        token = _make_jwt(header, claims)

        # Should NOT raise on nbf — it will proceed past nbf check and
        # fail later at JWKS fetch (which means nbf check passed)
        with pytest.raises(TokenValidationError, match="Token validation failed"):
            await validate_arm_token(token)

    @pytest.mark.asyncio
    async def test_iat_too_old(self, monkeypatch):
        """Token with iat 2 hours ago should be rejected when max age is 1 hour."""
        monkeypatch.setenv("NETBRIDGE_MAX_TOKEN_AGE_HOURS", "1")
        header = {"alg": "RS256", "kid": "k1"}
        claims = _make_valid_claims(iat=int(time.time()) - 7200)  # 2 hours ago
        token = _make_jwt(header, claims)

        with pytest.raises(TokenValidationError, match="Token too old"):
            await validate_arm_token(token)

    @pytest.mark.asyncio
    async def test_iat_not_checked_by_default(self, monkeypatch):
        """Token with old iat should pass when NETBRIDGE_MAX_TOKEN_AGE_HOURS is unset."""
        monkeypatch.delenv("NETBRIDGE_MAX_TOKEN_AGE_HOURS", raising=False)
        header = {"alg": "RS256", "kid": "k1"}
        claims = _make_valid_claims(iat=int(time.time()) - 172800)  # 48 hours ago
        token = _make_jwt(header, claims)

        # Should NOT raise on iat — it will proceed past iat check and
        # fail later at JWKS fetch (which means iat check passed)
        with pytest.raises(TokenValidationError, match="Token validation failed"):
            await validate_arm_token(token)
