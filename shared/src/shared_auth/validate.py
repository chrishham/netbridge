"""
ARM Token validation for relay server.

Validates JWT tokens issued by Azure AD without requiring an app registration.
"""

import asyncio
import base64
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

# Cache for JWKS (public keys) - keyed by tenant ID: (monotonic fetch time, jwks); a wall-clock step must not age or refresh it
_jwks_cache: dict[str, tuple[float, dict]] = {}
JWKS_CACHE_TTL = 3600  # 1 hour

# Fetches toward Microsoft are bounded however many requests arrive: one fetch
# in flight per tenant, no refetch for a while after a failure, and an unknown
# kid forces a refresh at most once per cooldown.
JWKS_FETCH_BACKOFF = 10  # seconds
JWKS_FORCED_REFRESH_COOLDOWN = 60  # seconds
# During a Microsoft outage expired keys keep being served, but not forever:
# a key Microsoft revoked must stop working within a day.
JWKS_MAX_STALE = 86400  # seconds
_jwks_locks: dict[str, asyncio.Lock] = {}
_jwks_failed_at: dict[str, float] = {}
_jwks_forced_refresh: dict[str, float] = {}
_jwks_refreshes: dict[str, asyncio.Task] = {}  # at most one background refresh per tenant


async def _fetch_jwks(tenant_id: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        url = _get_jwks_url(tenant_id)
        try:
            resp = await client.get(url)
        except httpx.TransportError:
            # Single retry on transient failure (connection error, timeout)
            resp = await client.get(url)
        resp.raise_for_status()
        jwks = resp.json()
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise ValueError("Malformed JWKS response")  # a fetch failure: must not replace working keys
    # Keep only entries validation can use; a response with none of them is a failure too
    keys = [k for k in jwks["keys"] if _usable_jwk(k)]
    if not keys:
        raise ValueError("JWKS response has no usable keys")
    return {**jwks, "keys": keys}


def _usable_jwk(jwk) -> bool:
    """Whether _verify_signature could build a key from this entry."""
    if not isinstance(jwk, dict) or not isinstance(jwk.get("kid"), str) or not jwk["kid"]:
        return False  # validate_arm_token rejects tokens without a kid, so such a key is unselectable
    try:
        _jwk_public_key(jwk)
    except Exception:
        return False
    return True


async def _get_jwks(tenant_id: str, force: bool = False) -> dict:
    """Microsoft's public keys for a tenant: cached, single-flight, backed off after failures.

    force=True bypasses the TTL (unknown kid) and only replaces the cache on success.
    """
    cached = _jwks_cache.get(tenant_id)
    if not force and cached is not None:
        age = time.monotonic() - cached[0]
        if age < JWKS_CACHE_TTL:
            return cached[1]  # fast path: a fetch in flight must not stall validations served from cache
        if age < JWKS_MAX_STALE:
            # Expired but usable: refresh in the background so no validation waits on Microsoft
            failed_at = _jwks_failed_at.get(tenant_id)
            backing_off = failed_at is not None and time.monotonic() - failed_at < JWKS_FETCH_BACKOFF
            if tenant_id not in _jwks_refreshes and not backing_off:
                task = asyncio.create_task(_refresh_jwks_quietly(tenant_id))
                _jwks_refreshes[tenant_id] = task
                task.add_done_callback(lambda _t: _jwks_refreshes.pop(tenant_id, None))
            return cached[1]
    return await _refresh_jwks(tenant_id, force)


async def _refresh_jwks_quietly(tenant_id: str) -> None:
    try:
        await _refresh_jwks(tenant_id)
    except Exception:
        pass  # recorded in _jwks_failed_at; callers keep the cached keys


async def _refresh_jwks(tenant_id: str, force: bool = False) -> dict:
    lock = _jwks_locks.setdefault(tenant_id, asyncio.Lock())
    async with lock:
        cached = _jwks_cache.get(tenant_id)
        fresh = cached is not None and (time.monotonic() - cached[0]) < JWKS_CACHE_TTL
        if fresh and not force:
            return cached[1]
        usable = cached is not None and (time.monotonic() - cached[0]) < JWKS_MAX_STALE
        failed_at = _jwks_failed_at.get(tenant_id)
        if failed_at is not None and time.monotonic() - failed_at < JWKS_FETCH_BACKOFF:
            if usable:
                return cached[1]
            raise TokenValidationError("Signing keys unavailable")
        try:
            jwks = await _fetch_jwks(tenant_id)
        except Exception as e:
            _jwks_failed_at[tenant_id] = time.monotonic()
            if usable:
                return cached[1]  # keep serving the previous keys
            raise TokenValidationError("Signing keys unavailable") from e
        _jwks_failed_at.pop(tenant_id, None)
        _jwks_cache[tenant_id] = (time.monotonic(), jwks)
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

        kid = header.get("kid")
        if not kid:
            raise TokenValidationError("No key ID in token header")

        # Get JWKS for signature verification
        jwks = await _get_jwks(tid)

        # Find the signing key
        signing_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                signing_key = key
                break

        if not signing_key:
            # Maybe a key rollover: force a refresh, at most once per tenant per cooldown
            now = time.monotonic()
            last = _jwks_forced_refresh.get(tid)
            failed_at = _jwks_failed_at.get(tid)
            in_backoff = failed_at is not None and now - failed_at < JWKS_FETCH_BACKOFF
            # inside the failure backoff a refresh would fetch nothing: keep the cooldown unspent
            if not in_backoff and (last is None or now - last >= JWKS_FORCED_REFRESH_COOLDOWN):
                _jwks_forced_refresh[tid] = now  # before the await: concurrent requests skip
                jwks = await _get_jwks(tid, force=True)
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


def _jwk_public_key(jwk: dict):
    """The RSA public key for a JWK; raises TokenValidationError or ValueError if unusable."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    alg = jwk.get("alg", "RS256")
    if alg != "RS256":
        raise TokenValidationError(f"Unsupported algorithm: {alg}")

    def b64_to_int(b64: str) -> int:
        pad = 4 - len(b64) % 4
        if pad != 4:
            b64 += "=" * pad
        return int.from_bytes(base64.urlsafe_b64decode(b64), byteorder="big")

    n = b64_to_int(jwk["n"])  # modulus
    e = b64_to_int(jwk["e"])  # exponent
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


async def _verify_signature(token: str, jwk: dict) -> None:
    """
    Verify JWT signature using the provided JWK.

    Uses the cryptography library for RSA signature verification.
    """
    import hashlib
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

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

    public_key = _jwk_public_key(jwk)

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
