"""JWT minting for e2e tests.

Creates RS256-signed JWT tokens compatible with Azure AD token structure.
"""
import base64
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


ISSUER_V2 = "https://login.microsoftonline.com/{tid}/v2.0"
AUDIENCE = "https://management.azure.com"


def load_key(path: Path):
    """Load a private RSA key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def mint(
    key,
    kid: str,
    tenant: str,
    *,
    upn: str = "e2e@netbridge.test",
    lifetime: int = 3600,
    header: dict | None = None,
    **claims
) -> str:
    """Mint a JWT token signed with the given key.

    Args:
        key: RSA private key (from cryptography)
        kid: Key ID to include in JWT header
        tenant: Azure tenant ID
        upn: User principal name (email)
        lifetime: Token lifetime in seconds
        header: Optional header overrides/extensions
        **claims: Additional claims (overrides replace defaults, None removes)

    Returns:
        JWT token string
    """
    now = int(time.time())

    # Build header
    jwt_header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
    }

    # Apply header overrides
    if header:
        for key_name, value in header.items():
            if value is None:
                jwt_header.pop(key_name, None)
            else:
                jwt_header[key_name] = value

    # Build payload with defaults
    payload = {
        "tid": tenant,
        "iss": ISSUER_V2.format(tid=tenant),
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
    }

    # Add upn if not being explicitly removed or overridden
    if "upn" not in claims:
        if upn is not None:
            payload["upn"] = upn
    elif claims["upn"] is not None:
        payload["upn"] = claims["upn"]

    # Apply other claim overrides
    for claim_name, value in claims.items():
        if claim_name == "upn":
            # Already handled above
            continue
        if value is None:
            payload.pop(claim_name, None)
        else:
            payload[claim_name] = value

    # Encode header and payload
    def b64url_encode(data: dict) -> str:
        """Encode dict as base64url without padding."""
        json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(json_bytes).rstrip(b"=").decode("ascii")

    header_b64 = b64url_encode(jwt_header)
    payload_b64 = b64url_encode(payload)

    # Sign
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

    return f"{header_b64}.{payload_b64}.{signature_b64}"
