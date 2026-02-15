"""
ARM Token validation for relay server.

Validates JWT tokens issued by Azure AD without requiring an app registration.
"""

import os
import time
from typing import Optional
import httpx


class TokenValidationError(Exception):
    """Raised when token validation fails."""
    pass


_allowed_tenants_cache: set[str] | None = None
_allowed_users_cache: set[str] | None = None
_allowed_groups_cache: set[str] | None = None


def _load_comma_set(env_var: str) -> set[str] | None:
    """Load a comma-separated set from an environment variable.

    Returns None if the variable is unset or empty (meaning "allow all").
    """
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return None
    values = {v.strip().lower() for v in raw.split(",") if v.strip()}
    return values or None


def _load_allowed_tenants() -> set[str]:
    """Load allowed tenant IDs from NETBRIDGE_ALLOWED_TENANTS env var.

    Results are cached after the first call.
    """
    global _allowed_tenants_cache
    if _allowed_tenants_cache is not None:
        return _allowed_tenants_cache

    raw = os.environ.get("NETBRIDGE_ALLOWED_TENANTS", "").strip()
    if not raw:
        raise RuntimeError(
            "NETBRIDGE_ALLOWED_TENANTS environment variable is not set or empty"
        )
    tenants = {t.strip() for t in raw.split(",") if t.strip()}
    if not tenants:
        raise RuntimeError(
            "NETBRIDGE_ALLOWED_TENANTS contains no valid entries"
        )
    _allowed_tenants_cache = tenants
    return tenants


def get_allowed_tenant_ids() -> set[str]:
    """Return the set of allowed tenant IDs (lazy-loaded)."""
    return _load_allowed_tenants()


def _get_allowed_users() -> set[str] | None:
    """Return the set of allowed UPNs/OIDs (lazy-loaded).

    Returns None if NETBRIDGE_ALLOWED_USERS is unset (allow all).
    """
    global _allowed_users_cache
    if _allowed_users_cache is None:
        _allowed_users_cache = _load_comma_set("NETBRIDGE_ALLOWED_USERS")
    return _allowed_users_cache


def _get_allowed_groups() -> set[str] | None:
    """Return the set of allowed group OIDs (lazy-loaded).

    Returns None if NETBRIDGE_ALLOWED_GROUPS is unset (allow all).
    """
    global _allowed_groups_cache
    if _allowed_groups_cache is None:
        _allowed_groups_cache = _load_comma_set("NETBRIDGE_ALLOWED_GROUPS")
    return _allowed_groups_cache


def _get_jwks_url(tenant_id: str) -> str:
    """Get JWKS URL for a specific tenant."""
    return f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"


def _get_valid_issuers(tenant_id: str) -> tuple[str, str]:
    """Get valid issuer URLs for a specific tenant (v1 and v2 endpoints)."""
    return (
        f"https://sts.windows.net/{tenant_id}/",
        f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    )

# ARM resource identifier (audience check)
ARM_AUDIENCE = "https://management.azure.com"

# Cache for JWKS (public keys) - keyed by tenant ID
_jwks_cache: dict[str, tuple[float, dict]] = {}
JWKS_CACHE_TTL = 3600  # 1 hour


async def _get_jwks(tenant_id: str) -> dict:
    """Fetch and cache Microsoft's public keys for a tenant."""
    global _jwks_cache

    now = time.time()
    cached = _jwks_cache.get(tenant_id)
    if cached and (now - cached[0]) < JWKS_CACHE_TTL:
        return cached[1]

    async with httpx.AsyncClient(timeout=10.0) as client:
        url = _get_jwks_url(tenant_id)
        try:
            resp = await client.get(url)
        except httpx.TransportError:
            # Single retry on transient failure (connection error, timeout)
            resp = await client.get(url)
        resp.raise_for_status()
        jwks = resp.json()
        _jwks_cache[tenant_id] = (now, jwks)
        return jwks


def _decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    """
    Decode JWT without verification (to get header and claims).

    This is used to extract the key ID (kid) from the header
    before we verify the signature.
    """
    import base64
    import json

    parts = token.split(".")
    if len(parts) != 3:
        raise TokenValidationError("Invalid JWT format")

    def decode_part(part: str) -> dict:
        # Add padding if needed
        padding = 4 - len(part) % 4
        if padding != 4:
            part += "=" * padding
        # URL-safe base64 decode
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)

    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    return header, payload


async def validate_arm_token(token: str) -> str:
    """
    Validate an ARM JWT token and extract user identity.

    Args:
        token: The JWT access token from Azure CLI.

    Returns:
        User principal name (email) from the token.

    Raises:
        TokenValidationError: If validation fails.
    """
    try:
        # Decode without verification first (to check claims)
        header, claims = _decode_jwt_unverified(token)

        # Check tenant ID is in the token
        tid = claims.get("tid", "")
        if tid not in get_allowed_tenant_ids():
            raise TokenValidationError(f"Invalid tenant: {tid}")

        # Check issuer (accept both v1 and v2 tokens for the tenant)
        issuer = claims.get("iss", "")
        valid_issuers = _get_valid_issuers(tid)
        if issuer not in valid_issuers:
            raise TokenValidationError(f"Invalid issuer: {issuer}")

        # Check audience (ARM resource)
        aud = claims.get("aud", "")
        if aud != ARM_AUDIENCE:
            raise TokenValidationError(f"Invalid audience: {aud}")

        # Check expiration
        exp = claims.get("exp", 0)
        if time.time() > exp:
            raise TokenValidationError("Token expired")

        # Check not-before (if present) with 60s clock skew allowance
        nbf = claims.get("nbf")
        if nbf is not None and time.time() < nbf - 60:
            raise TokenValidationError("Token not yet valid")

        # Check issued-at age (opt-in via NETBRIDGE_MAX_TOKEN_AGE_HOURS)
        max_age_hours = os.environ.get("NETBRIDGE_MAX_TOKEN_AGE_HOURS", "0")
        try:
            max_age_hours = float(max_age_hours)
        except (ValueError, TypeError):
            max_age_hours = 0
        if max_age_hours > 0:
            iat = claims.get("iat")
            if iat is not None:
                token_age_hours = (time.time() - iat) / 3600
                if token_age_hours > max_age_hours:
                    raise TokenValidationError("Token too old")

        # Get JWKS for signature verification
        jwks = await _get_jwks(tid)

        # Find the signing key
        kid = header.get("kid")
        if not kid:
            raise TokenValidationError("No key ID in token header")

        signing_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                signing_key = key
                break

        if not signing_key:
            # Key not found - might need to refresh cache
            global _jwks_cache
            _jwks_cache.pop(tid, None)  # Invalidate cache for this tenant
            jwks = await _get_jwks(tid)
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    signing_key = key
                    break

        if not signing_key:
            raise TokenValidationError(f"Signing key not found: {kid}")

        # Verify signature using cryptography library
        await _verify_signature(token, signing_key)

        # Extract user identity
        # ARM tokens use 'upn' or 'unique_name' for user identity
        user = (
            claims.get("upn")
            or claims.get("unique_name")
            or claims.get("preferred_username")
            or claims.get("email")
        )

        if not user:
            raise TokenValidationError("No user identity in token")

        # Check user allowlist (if configured)
        allowed_users = _get_allowed_users()
        if allowed_users:
            user_lower = user.lower()
            oid = claims.get("oid", "").lower()
            if user_lower not in allowed_users and oid not in allowed_users:
                raise TokenValidationError(
                    f"User {user} is not in the allowed users list"
                )

        # Check group allowlist (if configured)
        allowed_groups = _get_allowed_groups()
        if allowed_groups:
            token_groups = {
                g.lower() for g in claims.get("groups", [])
                if isinstance(g, str)
            }
            if not token_groups & allowed_groups:
                raise TokenValidationError(
                    f"User {user} is not a member of any allowed group"
                )

        return user

    except TokenValidationError:
        raise
    except Exception as e:
        raise TokenValidationError(f"Token validation failed: {e}")


async def _verify_signature(token: str, jwk: dict) -> None:
    """
    Verify JWT signature using the provided JWK.

    Uses the cryptography library for RSA signature verification.
    """
    import base64
    import hashlib
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    parts = token.split(".")
    if len(parts) != 3:
        raise TokenValidationError("Invalid JWT format")

    # The message that was signed (header.payload)
    message = f"{parts[0]}.{parts[1]}".encode("utf-8")

    # Decode the signature
    sig_b64 = parts[2]
    # Add padding if needed
    padding_needed = 4 - len(sig_b64) % 4
    if padding_needed != 4:
        sig_b64 += "=" * padding_needed
    signature = base64.urlsafe_b64decode(sig_b64)

    # Get algorithm
    alg = jwk.get("alg", "RS256")
    if alg != "RS256":
        raise TokenValidationError(f"Unsupported algorithm: {alg}")

    # Build RSA public key from JWK
    def b64_to_int(b64: str) -> int:
        # Add padding if needed
        pad = 4 - len(b64) % 4
        if pad != 4:
            b64 += "=" * pad
        decoded = base64.urlsafe_b64decode(b64)
        return int.from_bytes(decoded, byteorder="big")

    n = b64_to_int(jwk["n"])  # modulus
    e = b64_to_int(jwk["e"])  # exponent

    public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())

    # Verify signature
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception as e:
        raise TokenValidationError(f"Signature verification failed: {e}")
