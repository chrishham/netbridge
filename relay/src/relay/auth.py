"""
ARM Token validation for relay server.

Delegates to shared_auth for token validation.
"""

from typing import Optional

from shared_auth import validate_arm_token, TokenValidationError

__all__ = ["validate_token", "extract_bearer_token", "TokenValidationError"]


async def validate_token(token: str) -> str:
    """
    Validate an ARM JWT token and extract user identity.

    Args:
        token: The JWT access token from Azure CLI.

    Returns:
        User principal name (email) from the token.

    Raises:
        TokenValidationError: If validation fails.
    """
    return await validate_arm_token(token)


def extract_bearer_token(auth_header: str) -> Optional[str]:
    """Extract token from Authorization header."""
    if not auth_header:
        return None
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header[7:].strip()
