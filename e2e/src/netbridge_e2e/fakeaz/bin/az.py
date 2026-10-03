"""Fake `az` for the E2E gate (see netbridge_e2e.fakeaz)."""
import base64
import json
import os
import sys
import time

# Default account (used when auth env vars are not set)
DEFAULT_ACCOUNT = {
    "name": "netbridge-e2e",
    "tenantId": "00000000-0000-0000-0000-0000000000e2",
    "user": {"name": "e2e@netbridge.test", "type": "user"},
}

DEFAULT_UPN = "e2e@netbridge.test"


def _get_account() -> dict:
    """Get account info based on environment variables."""
    tenant = os.environ.get("NETBRIDGE_E2E_TENANT")
    upn = os.environ.get("NETBRIDGE_E2E_UPN", DEFAULT_UPN)

    if tenant:
        return {
            "name": "netbridge-e2e",
            "tenantId": tenant,
            "user": {"name": upn, "type": "user"},
        }
    return DEFAULT_ACCOUNT


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def make_token(lifetime: int = 3600) -> str:
    """Make a token - signed if auth env vars are set, unsigned otherwise."""
    signing_key_path = os.environ.get("NETBRIDGE_E2E_SIGNING_KEY")

    if signing_key_path:
        # Mint a signed token using the e2e key
        from netbridge_e2e.jwtmint import load_key, mint
        from pathlib import Path

        key = load_key(Path(signing_key_path))
        kid = os.environ["NETBRIDGE_E2E_KID"]
        tenant = os.environ["NETBRIDGE_E2E_TENANT"]
        upn = os.environ.get("NETBRIDGE_E2E_UPN", DEFAULT_UPN)

        return mint(key, kid, tenant, upn=upn, lifetime=lifetime)

    # Fall back to unsigned token for backward compatibility
    account = _get_account()
    now = int(time.time())
    claims = {
        "exp": now + lifetime,
        "iat": now,
        "upn": account["user"]["name"],
        "tid": account["tenantId"]
    }
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}.e2e"


def main(argv: list[str]) -> int:
    log = os.environ.get("NETBRIDGE_E2E_AZ_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write(" ".join(argv) + "\n")
    if argv[:2] == ["account", "show"]:
        print(json.dumps(_get_account()))
        return 0
    if argv[:2] == ["account", "get-access-token"]:
        print(json.dumps({"accessToken": make_token(), "tokenType": "Bearer"}))
        return 0
    print(f"fake az: unsupported command: {' '.join(argv)}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
